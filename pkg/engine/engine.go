package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SiriusScan/ping++/pkg/artifact"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/metrics"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

// Matcher turns observations into fused claims.
type Matcher interface {
	Match([]model.ObservationRecord) []model.Claim
}

// Engine orchestrates staged scan execution via the planner and registry.
type Engine struct {
	registry       *Registry
	profile        Profile
	planner        *Planner
	limiter        *RateLimiter
	networkLimiter *transport.Limiter
	scheduler      *Scheduler
	fingerprints   Matcher
	artifacts      artifact.Store
	metrics        *metrics.Counters
	mu             sync.Mutex
}

// Options configures an Engine.
type Options struct {
	Profile       ProfileName
	SkipDiscovery bool
	// SkipICMP removes ICMP discovery only. TCP discovery still runs.
	SkipICMP bool
	// DisableICMP is the scan.Config name for SkipICMP (Runner V2 contract).
	DisableICMP bool
	// ProbeTypes filters discovery/enumeration/protocol collectors when set
	// (icmp, tcp, udp, ssh, http, smb, ...). Empty means the full Engine set.
	ProbeTypes []string
	TCPPorts   []uint16
	UDPPorts   []uint16
	// OverrideTCPPorts applies TCPPorts even when the slice is empty (disable TCP enum).
	OverrideTCPPorts bool
	// OverrideUDPPorts applies UDPPorts even when the slice is empty (disable UDP enum).
	OverrideUDPPorts bool
	RatePerSecond    int
	ProbeTimeout     time.Duration
	HTTPTimeout      time.Duration
	// MaxConcurrentPerHost overrides profile per-host collector concurrency when > 0.
	MaxConcurrentPerHost int
	MaxProbesPerHost     int
	Registry             *Registry
	// MaxNetworkOps overrides the profile network-operation budget when > 0.
	MaxNetworkOps int
	// Fingerprints overrides the built-in fingerprint engine when set.
	Fingerprints Matcher
	// FingerprintDir loads extra YAML packs after built-ins.
	FingerprintDir string
	// FingerprintDirs loads additional extra YAML pack directories after FingerprintDir.
	FingerprintDirs []string
	// Artifacts overrides the in-memory artifact store when set.
	Artifacts artifact.Store
	// Metrics overrides runtime counters when set.
	Metrics *metrics.Counters
	// NetworkLimiter is the run-wide network-op limiter (C7). Nil means unlimited.
	NetworkLimiter *transport.Limiter
	// UnmatchedBannerFile, when set, appends unmatched banners as JSONL.
	UnmatchedBannerFile string
}

// PrepareProfile applies Options onto a named Profile. scan.Config compiles
// into Options, then this function is the single bind path for port tri-state.
func PrepareProfile(opts Options) Profile {
	profile := applyEngineOptions(ProfileFor(opts.Profile), opts)
	if opts.OverrideTCPPorts {
		profile.TCPPorts = append([]uint16(nil), opts.TCPPorts...)
	} else if len(opts.TCPPorts) > 0 {
		profile.TCPPorts = append([]uint16(nil), opts.TCPPorts...)
	}
	if opts.OverrideUDPPorts {
		profile.UDPPorts = append([]uint16(nil), opts.UDPPorts...)
	} else if len(opts.UDPPorts) > 0 {
		profile.UDPPorts = append([]uint16(nil), opts.UDPPorts...)
	}
	if opts.RatePerSecond > 0 {
		profile.Budget.RatePerSecond = opts.RatePerSecond
	}
	if opts.MaxNetworkOps > 0 {
		profile.Budget.MaxNetworkOps = opts.MaxNetworkOps
	}
	if opts.ProbeTimeout > 0 {
		profile.Budget.ProbeTimeout = opts.ProbeTimeout
	}
	if opts.HTTPTimeout > 0 {
		profile.Budget.HTTPTimeout = opts.HTTPTimeout
	}
	if opts.MaxConcurrentPerHost > 0 {
		profile.Budget.MaxConcurrentPerHost = opts.MaxConcurrentPerHost
	}
	if opts.MaxProbesPerHost > 0 {
		profile.Budget.MaxProbesPerHost = opts.MaxProbesPerHost
	}
	return profile
}

// NewEngine builds an engine with the given options and registry.
func NewEngine(opts Options) (*Engine, error) {
	if opts.Registry == nil {
		return nil, fmt.Errorf("registry required")
	}
	profile := PrepareProfile(opts)
	store := opts.Artifacts
	if store == nil {
		store = artifact.NewMemoryStore(profile.Budget.MaxArtifactBytes)
	}
	fp := opts.Fingerprints
	if fp == nil {
		eng := fingerprint.NewEngine()
		eng.SetArtifactStore(store)
		if err := eng.LoadBuiltinPacks(); err != nil {
			return nil, fmt.Errorf("load builtin fingerprints: %w", err)
		}
		dirs := opts.FingerprintDirs
		if opts.FingerprintDir != "" {
			dirs = append([]string{opts.FingerprintDir}, dirs...)
		}
		for _, dir := range dirs {
			if err := eng.LoadDir(dir); err != nil {
				return nil, fmt.Errorf("fingerprint dir %s: %w", dir, err)
			}
		}
		fp = eng
	}
	counters := opts.Metrics
	if counters == nil {
		counters = &metrics.Counters{}
	}
	if opts.UnmatchedBannerFile != "" {
		sink, err := metrics.OpenBannerSink(opts.UnmatchedBannerFile)
		if err != nil {
			return nil, fmt.Errorf("unmatched banner file: %w", err)
		}
		counters.AttachBannerSink(sink)
	}
	return &Engine{
		registry:       opts.Registry,
		profile:        profile,
		planner:        NewPlanner(opts.Registry, profile),
		limiter:        NewRateLimiter(profile.Budget.RatePerSecond),
		networkLimiter: opts.NetworkLimiter,
		scheduler:      NewScheduler(profile.Budget.RatePerSecond, profile.Budget.MaxConcurrentPerHost),
		fingerprints:   fp,
		artifacts:      store,
		metrics:        counters,
	}, nil
}

// Close releases Engine-owned resources (unmatched-banner sink).
func (e *Engine) Close() error {
	if e == nil || e.metrics == nil {
		return nil
	}
	return e.metrics.Close()
}

func applyEngineOptions(profile Profile, opts Options) Profile {
	if opts.SkipDiscovery {
		profile.SkipDiscovery = true
	}
	if opts.SkipICMP || opts.DisableICMP {
		profile.DiscoveryCollectors = filterCollectorIDs(profile.DiscoveryCollectors, "discovery.icmp")
	}
	if len(opts.ProbeTypes) == 0 {
		return profile
	}
	has := map[string]bool{}
	for _, t := range opts.ProbeTypes {
		has[strings.ToLower(strings.TrimSpace(t))] = true
	}
	var allow []string
	var disc []string
	if has["icmp"] && !opts.SkipICMP && !opts.DisableICMP && !opts.SkipDiscovery {
		disc = append(disc, "discovery.icmp")
		allow = append(allow, "discovery.icmp")
	}
	if has["tcp"] {
		if !opts.SkipDiscovery {
			disc = append(disc, "discovery.tcp")
			allow = append(allow, "discovery.tcp")
		}
		allow = append(allow, "enumerate.tcp")
	}
	if has["udp"] {
		allow = append(allow, "enumerate.udp")
	}
	protoCollectors := map[string][]string{
		"ssh":  {"collect.ssh", "collect.banner"},
		"http": {"collect.http", "collect.tls", "collect.http.enrich", "collect.banner"},
		"smb":  {"collect.smb", "collect.banner"},
		"ftp":  {"collect.ftp", "collect.banner"},
		"smtp": {"collect.smtp", "collect.tls", "collect.banner"},
		"imap": {"collect.imap", "collect.tls", "collect.banner"},
		"pop3": {"collect.pop3", "collect.tls", "collect.banner"},
		"tls":  {"collect.tls"},
	}
	for kind, ids := range protoCollectors {
		if !has[kind] {
			continue
		}
		allow = append(allow, ids...)
	}
	profile.DiscoveryCollectors = uniqueIDs(disc)
	var coll []string
	for _, id := range allow {
		if strings.HasPrefix(id, "enumerate.") {
			coll = append(coll, id)
		}
	}
	profile.CollectCollectors = uniqueIDs(coll)
	profile.AllowCollectors = uniqueIDs(allow)
	return profile
}

func filterCollectorIDs(ids []string, drop string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != drop {
			out = append(out, id)
		}
	}
	return out
}

// ScanResult is the output of scanning one target.
type ScanResult struct {
	Asset *model.Asset
	State *ScanState
}

// ScanTarget resolves a target string and runs the staged pipeline for every A/AAAA.
func (e *Engine) ScanTarget(ctx context.Context, raw string) (*ScanResult, error) {
	target, err := ResolveTarget(ctx, raw)
	if err != nil {
		return nil, err
	}
	return e.ScanResolved(ctx, target)
}

// ScanResolved scans every address on target, keeping Hostname for SNI/Host.
// Discovery and enumeration run across all addresses before adaptive work so
// a shared target budget cannot starve later A/AAAA records.
func (e *Engine) ScanResolved(ctx context.Context, target model.Target) (*ScanResult, error) {
	addrs := uniqueOrderedAddresses(target.Addresses)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for %q", target.Input)
	}
	logicalID := "asset:" + target.Input
	if len(addrs) == 1 {
		return e.scanAddress(ctx, target, addrs[0], nil)
	}

	type addrWork struct {
		target model.Target
		asset  *model.Asset
	}
	works := make([]addrWork, 0, len(addrs))
	for _, addr := range addrs {
		one := target
		one.Addresses = []model.Address{addr}
		asset := model.NewAssetFromIP(addr.IP)
		if target.Hostname != "" {
			asset.Hostnames = []string{target.Hostname}
		}
		works = append(works, addrWork{target: one, asset: asset})
	}

	shared := e.newScanState(logicalID)
	merged := &model.Asset{ID: logicalID}
	if target.Hostname != "" {
		merged.Hostnames = []string{target.Hostname}
	}

	for i := range works {
		if err := e.runTasks(ctx, e.planner.PlanDiscovery(works[i].asset, &works[i].target, shared), works[i].asset, &works[i].target, shared); err != nil {
			return nil, err
		}
	}
	for i := range works {
		if err := e.runTasks(ctx, e.planner.PlanEnumeration(works[i].asset, &works[i].target, shared), works[i].asset, &works[i].target, shared); err != nil {
			return nil, err
		}
	}

	const maxPasses = 32
	for pass := 0; pass < maxPasses; pass++ {
		if !e.budgetRemaining(shared) {
			break
		}
		progress := false
		for i := range works {
			if !e.budgetRemaining(shared) {
				break
			}
			tasks := e.planner.Next(works[i].asset, shared)
			if len(tasks) == 0 {
				continue
			}
			progress = true
			if err := e.runTasks(ctx, tasks, works[i].asset, &works[i].target, shared); err != nil {
				return nil, err
			}
			e.applyFingerprints(works[i].asset)
		}
		if !progress {
			break
		}
	}

	for i := range works {
		e.applyFingerprints(works[i].asset)
		e.markEndpointExecution(ctx, works[i].asset, shared)
		mergeAsset(merged, works[i].asset)
	}
	e.applyFingerprints(merged)
	e.recordScanMetrics(merged, shared)
	e.mu.Lock()
	e.syncMeterLocked(shared)
	e.mu.Unlock()
	shared.AssetID = logicalID
	return &ScanResult{Asset: merged, State: shared}, nil
}

func (e *Engine) newScanState(assetID string) *ScanState {
	return &ScanState{
		AssetID:      assetID,
		Reachability: model.Reachability{State: model.ReachabilityUnknown},
		Budget:       e.profile.Budget,
		Completed:    make(map[string]bool),
		Matched:      make(map[string]map[string]bool),
		RuledOut:     make(map[string]map[string]bool),
		Requests:     make(map[string]int),
		Meter: &transport.Meter{
			MaxNetworkOps: e.profile.Budget.MaxNetworkOps,
			MaxBytes:      e.profile.Budget.MaxBytesPerHost,
		},
	}
}

func (e *Engine) scanAddress(ctx context.Context, target model.Target, addr model.Address, shared *ScanState) (*ScanResult, error) {
	asset := model.NewAssetFromIP(addr.IP)
	if target.Hostname != "" {
		asset.Hostnames = []string{target.Hostname}
	}
	state := shared
	if state == nil {
		state = e.newScanState(asset.ID)
	}

	if err := e.runTasks(ctx, e.planner.PlanDiscovery(asset, &target, state), asset, &target, state); err != nil {
		return nil, err
	}
	if err := e.runTasks(ctx, e.planner.PlanEnumeration(asset, &target, state), asset, &target, state); err != nil {
		return nil, err
	}

	const maxPasses = 32
	for pass := 0; pass < maxPasses; pass++ {
		if !e.budgetRemaining(state) {
			break
		}
		tasks := e.planner.Next(asset, state)
		if len(tasks) == 0 {
			break
		}
		if err := e.runTasks(ctx, tasks, asset, &target, state); err != nil {
			return nil, err
		}
		e.applyFingerprints(asset)
	}

	e.applyFingerprints(asset)
	e.markEndpointExecution(ctx, asset, state)
	if shared == nil {
		e.recordScanMetrics(asset, state)
		e.mu.Lock()
		e.syncMeterLocked(state)
		e.mu.Unlock()
	}
	return &ScanResult{Asset: asset, State: state}, nil
}

func setEndpointExecution(ep *model.Endpoint, exec model.EndpointExecution) {
	if ep == nil || exec == "" {
		return
	}
	switch ep.Execution {
	case model.ExecutionAttempted, model.ExecutionTimedOut:
		if exec == model.ExecutionTimedOut {
			ep.Execution = exec
		}
		return
	default:
		ep.Execution = exec
	}
}

func (e *Engine) markEndpointExecution(ctx context.Context, asset *model.Asset, state *ScanState) {
	if asset == nil {
		return
	}
	budgetLeft := e.budgetRemaining(state)
	for i := range asset.Endpoints {
		ep := &asset.Endpoints[i]
		if ep.Execution != "" {
			continue
		}
		classified := state != nil && state.HasCollectorForEndpoint(ep.Key())
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			ep.Execution = model.ExecutionTimedOut
		case ctx.Err() != nil:
			ep.Execution = model.ExecutionNotAttemptedCancelled
		case classified, ep.State == model.EndpointOpen, ep.State == model.EndpointClosed, ep.State == model.EndpointFiltered:
			ep.Execution = model.ExecutionAttempted
		case !budgetLeft && classifiableEndpoint(ep):
			ep.Execution = model.ExecutionNotAttemptedBudget
		default:
			ep.Execution = model.ExecutionAttempted
		}
	}
}

func mergeAsset(dst, src *model.Asset) {
	if dst == nil || src == nil {
		return
	}
	for _, a := range src.Addresses {
		found := false
		for _, e := range dst.Addresses {
			if e.IP == a.IP {
				found = true
				break
			}
		}
		if !found {
			dst.Addresses = append(dst.Addresses, a)
		}
	}
	for _, h := range src.Hostnames {
		dup := false
		for _, e := range dst.Hostnames {
			if e == h {
				dup = true
				break
			}
		}
		if !dup {
			dst.Hostnames = append(dst.Hostnames, h)
		}
	}
	for _, ep := range src.Endpoints {
		dst.AddEndpoint(ep)
	}
	for _, o := range src.Observations {
		dst.AddObservation(o)
	}
	for _, c := range src.Claims {
		if c.Kind == model.ClaimProtocol {
			dst.AddClaim(c)
		}
	}
}

func mergeScanState(dst, src *ScanState) {
	if dst == nil || src == nil || dst == src {
		return
	}
	dst.Budget.ProbesUsed += src.Budget.ProbesUsed
	if src.Reachability.State == model.ReachabilityConfirmed {
		dst.Reachability.State = model.ReachabilityConfirmed
	} else if dst.Reachability.State == model.ReachabilityUnknown {
		dst.Reachability.State = src.Reachability.State
	}
	for _, r := range src.Reachability.Reasons {
		dst.Reachability.Reasons = appendUniqueReason(dst.Reachability.Reasons, r)
	}
	if dst.Completed == nil {
		dst.Completed = map[string]bool{}
	}
	for k, v := range src.Completed {
		dst.Completed[k] = v
	}
	dst.Matched = mergeNestedBool(dst.Matched, src.Matched)
	dst.RuledOut = mergeNestedBool(dst.RuledOut, src.RuledOut)
	if dst.Requests == nil {
		dst.Requests = map[string]int{}
	}
	for k, v := range src.Requests {
		dst.Requests[k] += v
	}
}

func mergeNestedBool(dst, src map[string]map[string]bool) map[string]map[string]bool {
	if dst == nil {
		dst = map[string]map[string]bool{}
	}
	for k, inner := range src {
		if dst[k] == nil {
			dst[k] = map[string]bool{}
		}
		for p, v := range inner {
			dst[k][p] = v
		}
	}
	return dst
}

func (e *Engine) runTasks(ctx context.Context, tasks []Task, asset *model.Asset, target *model.Target, state *ScanState) error {
	if len(tasks) == 0 {
		return nil
	}
	for i := range tasks {
		if tasks[i].Target == nil {
			tasks[i].Target = target
		}
	}
	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].Priority > tasks[j].Priority
	})
	return e.scheduler.RunAll(ctx, tasks, func(ctx context.Context, task Task) error {
		if !e.budgetRemaining(state) {
			setEndpointExecution(task.Endpoint, model.ExecutionNotAttemptedBudget)
			return nil
		}
		err := e.runTask(ctx, task, asset, state)
		if err != nil && ctx.Err() != nil {
			return err
		}
		return nil
	})
}

func (e *Engine) budgetRemaining(state *ScanState) bool {
	if state == nil {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.syncMeterLocked(state)
	return state.Budget.Remaining()
}

func (e *Engine) syncMeterLocked(state *ScanState) {
	if state == nil || state.Meter == nil {
		return
	}
	ops, conns, read, sent := state.Meter.Snapshot()
	state.Budget.NetworkOps = ops
	state.Budget.Connections = conns
	state.Budget.BytesUsed = read + sent
}

func (e *Engine) runTask(ctx context.Context, task Task, asset *model.Asset, state *ScanState) error {
	cfg := Config{
		Timeout:     e.profile.Budget.ProbeTimeout,
		Ports:       e.profile.TCPPorts,
		UDPPorts:    e.profile.UDPPorts,
		Concurrency: e.profile.Budget.MaxConcurrentPerHost,
		Extra:       task.Extra,
	}
	if task.Stage == StageDiscovery {
		cfg.Ports = append([]uint16(nil), QuickPorts...)
	}
	c, err := e.registry.Create(task.CollectorID, cfg)
	if err != nil {
		return err
	}
	in := CollectorInput{
		Asset:     asset,
		Endpoint:  task.Endpoint,
		Target:    task.Target,
		State:     state,
		Timeout:   cfg.Timeout,
		Extra:     task.Extra,
		Artifacts: e.artifacts,
	}
	if task.CollectorID == "collect.http" || task.CollectorID == "collect.http.enrich" {
		if e.profile.Budget.HTTPTimeout > 0 {
			in.Timeout = e.profile.Budget.HTTPTimeout
		}
	}
	if state != nil && state.Meter != nil {
		ctx = transport.WithMeter(ctx, state.Meter)
	}
	if e.networkLimiter != nil {
		ctx = transport.WithLimiter(ctx, e.networkLimiter)
	}

	e.mu.Lock()
	e.syncMeterLocked(state)
	if !state.Budget.Remaining() {
		e.mu.Unlock()
		setEndpointExecution(task.Endpoint, model.ExecutionNotAttemptedBudget)
		return nil
	}
	state.Budget.ConsumeProbe()
	e.mu.Unlock()

	result, err := executeCollector(ctx, c, in)

	e.mu.Lock()
	defer e.mu.Unlock()
	if state.Meter != nil {
		e.syncMeterLocked(state)
	} else if result.NetworkOps > 0 || result.BytesRead > 0 {
		state.Budget.ConsumeNetwork(result.NetworkOps, result.BytesRead)
	}
	if task.Endpoint != nil {
		state.NoteEndpointRequest(task.Endpoint.Key())
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded) || result.Outcome == OutcomeTimeout:
			setEndpointExecution(task.Endpoint, model.ExecutionTimedOut)
		case errors.Is(ctx.Err(), context.Canceled):
			setEndpointExecution(task.Endpoint, model.ExecutionNotAttemptedCancelled)
		default:
			setEndpointExecution(task.Endpoint, model.ExecutionAttempted)
		}
	}
	key := hostCollectorKey(task.CollectorID, task.Target)
	if task.Endpoint != nil {
		key = task.CollectorID + ":" + task.Endpoint.Key()
	}
	state.MarkComplete(key)
	if err != nil && result.Outcome == "" {
		result.Outcome = outcomeFromError(err)
	}
	if e.metrics != nil {
		e.metrics.RecordCollector(string(result.Outcome))
	}

	if err != nil {
		if ctx.Err() != nil {
			return err
		}
	}
	applyCollectorOutcome(state, task, result)
	e.applyProtocolClaim(asset, task, result)
	for _, o := range result.Observations {
		if o.AssetID == "" {
			o.AssetID = asset.ID
		}
		asset.AddObservation(o)
		applyObservationToAsset(asset, state, o, result.Outcome)
	}
	return nil
}

func executeCollector(ctx context.Context, c Collector, in CollectorInput) (result CollectorResult, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			result = CollectorResult{Outcome: OutcomeInternalError, Observations: result.Observations}
			err = nil
		}
	}()
	if rc, ok := c.(ResultCollector); ok {
		return rc.RunResult(ctx, in)
	}
	obs, runErr := c.Run(ctx, in)
	out := CollectorResult{Observations: obs}
	if runErr != nil {
		out.Outcome = outcomeFromError(runErr)
		return out, runErr
	}
	return out, nil
}

func applyCollectorOutcome(state *ScanState, task Task, result CollectorResult) {
	if state == nil || task.Endpoint == nil {
		return
	}
	proto := resultProtocol(task, result)
	switch result.Outcome {
	case OutcomeSuccess:
		state.NoteProtocol(task.Endpoint.Key(), proto, true)
	case OutcomeNoMatch:
		state.NoteProtocol(task.Endpoint.Key(), proto, false)
	}
}

func resultProtocol(task Task, result CollectorResult) string {
	if result.Protocol != "" {
		return result.Protocol
	}
	return collectorProtocol(task.CollectorID)
}

func (e *Engine) applyProtocolClaim(asset *model.Asset, task Task, result CollectorResult) {
	if asset == nil || task.Endpoint == nil || result.Outcome != OutcomeSuccess {
		return
	}
	proto := resultProtocol(task, result)
	if proto == "" || proto == "banner" || proto == "tcp" || proto == "udp" || proto == "endpoint" {
		return
	}
	var evidence []string
	for _, o := range result.Observations {
		if o.ID != "" {
			evidence = append(evidence, o.ID)
		}
	}
	asset.AddClaim(model.Claim{
		ID:               fmt.Sprintf("protocol:%s:%s", proto, task.Endpoint.Key()),
		Kind:             model.ClaimProtocol,
		Product:          proto,
		Value:            proto,
		Subject:          task.Endpoint.Key(),
		Score:            90,
		Confidence:       model.ConfidenceStrong,
		EvidenceIDs:      evidence,
		CorrelationGroup: "protocol:" + task.Endpoint.Key(),
	})
	if e != nil && e.metrics != nil {
		e.metrics.RecordProtocolMatch()
	}
}

func OutcomeFromError(err error) ProbeOutcome {
	return outcomeFromError(err)
}

func outcomeFromError(err error) ProbeOutcome {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return OutcomeTimeout
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return OutcomeTimeout
	case strings.Contains(msg, "refused"):
		return OutcomeRefused
	case strings.Contains(msg, "filtered") || strings.Contains(msg, "no route") || strings.Contains(msg, "unreachable"):
		return OutcomeFiltered
	default:
		return OutcomeInternalError
	}
}

func (e *Engine) applyFingerprints(asset *model.Asset) {
	if e == nil || e.fingerprints == nil || asset == nil {
		return
	}
	kept := asset.Claims[:0]
	for _, c := range asset.Claims {
		if c.Kind == model.ClaimProtocol {
			kept = append(kept, c)
		}
	}
	asset.Claims = kept
	for _, c := range e.fingerprints.Match(asset.Observations) {
		asset.AddClaim(c)
	}
}

func (e *Engine) recordScanMetrics(asset *model.Asset, state *ScanState) {
	if e == nil || e.metrics == nil || asset == nil {
		return
	}
	for _, ep := range asset.Endpoints {
		if ep.State == model.EndpointUnknown || ep.State == model.EndpointFiltered {
			e.metrics.RecordUnknownEndpoint()
		}
	}
	if state != nil && state.Meter != nil {
		_, _, read, sent := state.Meter.Snapshot()
		e.metrics.RecordBytes(read + sent)
	}
	seenConflict := map[string]bool{}
	for _, c := range asset.Claims {
		if c.Kind != model.ClaimProtocol {
			e.metrics.RecordClaimTier(string(c.Confidence))
		}
		if len(c.ContradictionIDs) > 0 && !seenConflict[c.ID] {
			seenConflict[c.ID] = true
			e.metrics.RecordConflict()
		}
	}
	e.recordUnmatchedBanners(asset)
}

func (e *Engine) recordUnmatchedBanners(asset *model.Asset) {
	used := map[string]bool{}
	for _, c := range asset.Claims {
		if c.Kind == model.ClaimProduct || c.Kind == model.ClaimApplication || c.Kind == model.ClaimDevice {
			for _, id := range c.EvidenceIDs {
				used[id] = true
			}
		}
	}
	for _, o := range asset.Observations {
		if used[o.ID] {
			continue
		}
		switch o.ObservationType {
		case model.ObservationSSH:
			var p model.SSHObservation
			_ = o.DecodePayload(&p)
			if p.Banner != "" {
				e.metrics.RecordUnmatchedBanner(p.Banner)
			}
		case model.ObservationBanner:
			var p model.BannerObservation
			_ = o.DecodePayload(&p)
			if p.Text != "" {
				e.metrics.RecordUnmatchedBanner(p.Text)
			}
		case "smtp", "imap", "pop3", "ftp", "telnet":
			var p struct {
				Banner string `json:"banner"`
			}
			_ = o.DecodePayload(&p)
			if p.Banner != "" {
				e.metrics.RecordUnmatchedBanner(p.Banner)
			}
		}
	}
}

func applyObservationToAsset(asset *model.Asset, state *ScanState, o model.ObservationRecord, outcome ProbeOutcome) {
	switch o.ObservationType {
	case model.ObservationICMPEcho:
		if o.Error == "" {
			state.Reachability.State = model.ReachabilityConfirmed
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, "icmp.echo")
		}
	case model.ObservationTCPEndpoint:
		var payload model.TCPEndpointObservation
		_ = o.DecodePayload(&payload)
		if o.Endpoint != nil {
			asset.AddEndpoint(model.NewEndpoint(o.Endpoint.Address, o.Endpoint.Port, o.Endpoint.Transport, payload.State))
		}
		switch payload.State {
		case model.EndpointOpen, model.EndpointResponsive:
			state.Reachability.State = model.ReachabilityConfirmed
			reason := "tcp.connect"
			if payload.State == model.EndpointOpen {
				reason = "tcp.open"
			}
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, reason)
		case model.EndpointClosed:
			if state.Reachability.State == model.ReachabilityUnknown {
				state.Reachability.State = model.ReachabilityProbable
			}
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, "tcp.rst")
		}
	case model.ObservationUDPEndpoint:
		var payload model.UDPEndpointObservation
		_ = o.DecodePayload(&payload)
		if o.Endpoint != nil {
			asset.AddEndpoint(model.NewEndpoint(o.Endpoint.Address, o.Endpoint.Port, o.Endpoint.Transport, payload.State))
		}
		if payload.State == model.EndpointOpen || payload.State == model.EndpointResponsive {
			state.Reachability.State = model.ReachabilityConfirmed
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, "udp.response")
		}
	default:
		// Endpoint Open requires an explicit protocol match, not Completeness.
		if outcome == OutcomeSuccess && o.Endpoint != nil {
			asset.AddEndpoint(model.NewEndpoint(o.Endpoint.Address, o.Endpoint.Port, o.Endpoint.Transport, model.EndpointOpen))
			state.Reachability.State = model.ReachabilityConfirmed
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, "tcp.service")
		}
	}
}

func appendUniqueReason(slice []string, v string) []string {
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}

// lookupIPAddr is the hostname resolver used by ResolveTarget. Tests swap it
// to inject A/AAAA answers without touching the system resolver.
var lookupIPAddr = defaultLookupIPAddr

func defaultLookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// ResolveTarget expands a single IP or hostname into a Target.
// CIDR expansion is handled by callers for now. Hostname answers are
// de-duplicated (including IPv4-mapped forms) and ordered IPv4 then IPv6,
// then by address bytes, so later pipeline stages are not resolver-order
// dependent.
func ResolveTarget(ctx context.Context, raw string) (model.Target, error) {
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(raw); ip != nil {
		canon := uniqueOrderedAddresses([]model.Address{model.NewAddress(ip.String())})
		if len(canon) == 1 {
			return model.NewTargetIP(canon[0].IP), nil
		}
		return model.NewTargetIP(raw), nil
	}
	// Hostname — retain for SNI/Host
	addrs, err := lookupIPAddr(ctx, raw)
	if err != nil {
		return model.Target{}, err
	}
	converted := make([]model.Address, 0, len(addrs))
	for _, a := range addrs {
		if a.IP == nil {
			continue
		}
		converted = append(converted, model.NewAddress(a.IP.String()))
	}
	ordered := uniqueOrderedAddresses(converted)
	if len(ordered) == 0 {
		return model.Target{}, fmt.Errorf("no A/AAAA records for %s", raw)
	}
	ips := make([]string, len(ordered))
	for i, a := range ordered {
		ips[i] = a.IP
	}
	return model.NewTargetHostname(raw, ips...), nil
}

func uniqueOrderedAddresses(in []model.Address) []model.Address {
	type item struct {
		ip   net.IP
		orig model.Address
	}
	seen := make(map[string]struct{}, len(in))
	items := make([]item, 0, len(in))
	for _, a := range in {
		ip := net.ParseIP(strings.TrimSpace(a.IP))
		if ip == nil {
			key := "raw:" + a.IP
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			items = append(items, item{orig: a})
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		orig := a
		orig.IP = ip.String()
		if ip.To4() != nil {
			orig.Version = 4
		} else {
			orig.Version = 6
		}
		items = append(items, item{ip: append(net.IP(nil), ip...), orig: orig})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i].ip, items[j].ip
		if a == nil && b == nil {
			return items[i].orig.IP < items[j].orig.IP
		}
		if a == nil {
			return false
		}
		if b == nil {
			return true
		}
		a4, b4 := a.To4() != nil, b.To4() != nil
		if a4 != b4 {
			return a4
		}
		aa, bb := a.To16(), b.To16()
		if aa == nil || bb == nil {
			return a.String() < b.String()
		}
		return bytes.Compare(aa, bb) < 0
	})
	out := make([]model.Address, len(items))
	for i, it := range items {
		out[i] = it.orig
	}
	return out
}

// Scheduler runs tasks with per-host concurrency limits.
type Scheduler struct {
	limiter *RateLimiter
	workers int
}

// NewScheduler creates a scheduler.
func NewScheduler(ratePerSecond, perHostWorkers int) *Scheduler {
	if perHostWorkers <= 0 {
		perHostWorkers = 4
	}
	return &Scheduler{
		limiter: NewRateLimiter(ratePerSecond),
		workers: perHostWorkers,
	}
}

// RunAll executes tasks with bounded concurrency.
func (s *Scheduler) RunAll(ctx context.Context, tasks []Task, fn func(context.Context, Task) error) error {
	if len(tasks) == 0 {
		return nil
	}
	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for _, task := range tasks {
		task := task
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if !s.limiter.Wait(ctx.Done()) {
				return
			}
			if err := fn(ctx, task); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return firstErr
}
