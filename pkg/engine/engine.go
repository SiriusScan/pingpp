package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

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
	registry     *Registry
	profile      Profile
	planner      *Planner
	limiter      *RateLimiter
	scheduler    *Scheduler
	fingerprints Matcher
	artifacts    artifact.Store
	metrics      *metrics.Counters
	mu           sync.Mutex
}

// Options configures an Engine.
type Options struct {
	Profile       ProfileName
	SkipDiscovery bool
	TCPPorts      []uint16
	UDPPorts      []uint16
	RatePerSecond int
	Registry      *Registry
	// MaxNetworkOps overrides the profile network-operation budget when > 0.
	MaxNetworkOps int
	// Fingerprints overrides the built-in fingerprint engine when set.
	Fingerprints Matcher
	// FingerprintDir loads extra YAML packs after built-ins.
	FingerprintDir string
	// Artifacts overrides the in-memory artifact store when set.
	Artifacts artifact.Store
	// Metrics overrides runtime counters when set.
	Metrics *metrics.Counters
}

// NewEngine builds an engine with the given options and registry.
func NewEngine(opts Options) (*Engine, error) {
	if opts.Registry == nil {
		return nil, fmt.Errorf("registry required")
	}
	profile := ProfileFor(opts.Profile)
	if opts.SkipDiscovery {
		profile.SkipDiscovery = true
	}
	if len(opts.TCPPorts) > 0 {
		profile.TCPPorts = append([]uint16(nil), opts.TCPPorts...)
	}
	if len(opts.UDPPorts) > 0 {
		profile.UDPPorts = append([]uint16(nil), opts.UDPPorts...)
	}
	if opts.RatePerSecond > 0 {
		profile.Budget.RatePerSecond = opts.RatePerSecond
	}
	if opts.MaxNetworkOps > 0 {
		profile.Budget.MaxNetworkOps = opts.MaxNetworkOps
	}
	store := opts.Artifacts
	if store == nil {
		store = artifact.NewMemoryStore(profile.Budget.MaxArtifactBytes)
	}
	fp := opts.Fingerprints
	if fp == nil {
		eng := fingerprint.NewEngine()
		eng.SetArtifactStore(store)
		if err := eng.LoadBuiltinPacks(fingerprint.RepoFingerprintsRoot()); err != nil {
			return nil, fmt.Errorf("load builtin fingerprints: %w", err)
		}
		if opts.FingerprintDir != "" {
			if err := eng.LoadDir(opts.FingerprintDir); err != nil {
				return nil, fmt.Errorf("fingerprint dir %s: %w", opts.FingerprintDir, err)
			}
		}
		fp = eng
	}
	counters := opts.Metrics
	if counters == nil {
		counters = &metrics.Counters{}
	}
	return &Engine{
		registry:     opts.Registry,
		profile:      profile,
		planner:      NewPlanner(opts.Registry, profile),
		limiter:      NewRateLimiter(profile.Budget.RatePerSecond),
		scheduler:    NewScheduler(profile.Budget.RatePerSecond, profile.Budget.MaxConcurrentPerHost),
		fingerprints: fp,
		artifacts:    store,
		metrics:      counters,
	}, nil
}

// ScanResult is the output of scanning one target.
type ScanResult struct {
	Asset *model.Asset
	State *ScanState
}

// ScanTarget resolves a target string and runs the staged pipeline.
func (e *Engine) ScanTarget(ctx context.Context, raw string) (*ScanResult, error) {
	target, err := ResolveTarget(ctx, raw)
	if err != nil {
		return nil, err
	}
	if len(target.Addresses) == 0 {
		return nil, fmt.Errorf("no addresses for %q", raw)
	}

	ip := target.Addresses[0].IP
	asset := model.NewAssetFromIP(ip)
	if target.Hostname != "" {
		asset.Hostnames = []string{target.Hostname}
	}
	state := &ScanState{
		AssetID:      asset.ID,
		Reachability: model.Reachability{State: model.ReachabilityUnknown},
		Budget:       e.profile.Budget,
		Completed:    make(map[string]bool),
		Meter: &transport.Meter{
			MaxNetworkOps: e.profile.Budget.MaxNetworkOps,
		},
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
	e.mu.Lock()
	e.syncMeterLocked(state)
	e.mu.Unlock()
	return &ScanResult{Asset: asset, State: state}, nil
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
	ops, conns, read, _ := state.Meter.Snapshot()
	state.Budget.NetworkOps = ops
	state.Budget.Connections = conns
	state.Budget.BytesUsed = read
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
	if state != nil && state.Meter != nil {
		ctx = transport.WithMeter(ctx, state.Meter)
	}
	result, err := executeCollector(ctx, c, in)

	e.mu.Lock()
	defer e.mu.Unlock()
	state.Budget.ConsumeProbe()
	if state.Meter != nil {
		e.syncMeterLocked(state)
	} else if result.NetworkOps > 0 || result.BytesRead > 0 {
		state.Budget.ConsumeNetwork(result.NetworkOps, result.BytesRead)
	}
	key := task.CollectorID
	if task.Endpoint != nil {
		key = task.CollectorID + ":" + task.Endpoint.Key()
	}
	state.MarkComplete(key)

	if err != nil {
		if result.Outcome == "" {
			result.Outcome = outcomeFromError(err)
		}
		if ctx.Err() != nil {
			return err
		}
	}
	applyCollectorOutcome(state, task, result)
	applyProtocolClaim(asset, task, result)
	for _, o := range result.Observations {
		if o.AssetID == "" {
			o.AssetID = asset.ID
		}
		asset.AddObservation(o)
		applyObservationToAsset(asset, state, o, result.Outcome)
	}
	return nil
}

func executeCollector(ctx context.Context, c Collector, in CollectorInput) (CollectorResult, error) {
	if rc, ok := c.(ResultCollector); ok {
		return rc.RunResult(ctx, in)
	}
	obs, err := c.Run(ctx, in)
	// Legacy collectors: record observations, but do not treat Completeness
	// as a protocol match. Planning identity comes only from ProbeOutcome.
	out := CollectorResult{Observations: obs}
	if err != nil {
		out.Outcome = outcomeFromError(err)
		return out, err
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

func applyProtocolClaim(asset *model.Asset, task Task, result CollectorResult) {
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
	if e.metrics != nil {
		for _, c := range asset.Claims {
			if len(c.ContradictionIDs) > 0 {
				e.metrics.RecordConflict()
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

// ResolveTarget expands a single IP or hostname into a Target.
// CIDR expansion is handled by callers for now.
func ResolveTarget(ctx context.Context, raw string) (model.Target, error) {
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(raw); ip != nil {
		return model.NewTargetIP(raw), nil
	}
	// Hostname — retain for SNI/Host
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, raw)
	if err != nil {
		return model.Target{}, err
	}
	var ips []string
	for _, a := range addrs {
		ips = append(ips, a.IP.String())
	}
	if len(ips) == 0 {
		return model.Target{}, fmt.Errorf("no A/AAAA records for %s", raw)
	}
	return model.NewTargetHostname(raw, ips...), nil
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
