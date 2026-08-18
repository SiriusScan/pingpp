package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/SiriusScan/ping++/pkg/artifact"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/metrics"
	"github.com/SiriusScan/ping++/pkg/model"
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
}

// Options configures an Engine.
type Options struct {
	Profile       ProfileName
	SkipDiscovery bool
	TCPPorts      []uint16
	RatePerSecond int
	Registry      *Registry
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
	if opts.RatePerSecond > 0 {
		profile.Budget.RatePerSecond = opts.RatePerSecond
	}
	fp := opts.Fingerprints
	if fp == nil {
		eng := fingerprint.NewEngine()
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
	store := opts.Artifacts
	if store == nil {
		store = artifact.NewMemoryStore(profile.Budget.MaxArtifactBytes)
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
	}

	// Stage 2: discovery
	for _, task := range e.planner.PlanDiscovery(asset, &target, state) {
		if !state.Budget.RemainingProbes() {
			break
		}
		if err := e.runTask(ctx, task, asset, state); err != nil && ctx.Err() != nil {
			return nil, err
		}
	}

	// Stage 3: enumeration
	for _, task := range e.planner.PlanEnumeration(asset, &target, state) {
		if !state.Budget.RemainingProbes() {
			break
		}
		if err := e.runTask(ctx, task, asset, state); err != nil && ctx.Err() != nil {
			return nil, err
		}
	}

	// Stage 4+: adaptive classify → fingerprint → replan.
	const maxPasses = 8
	for pass := 0; pass < maxPasses; pass++ {
		if !state.Budget.RemainingProbes() {
			break
		}
		tasks := e.planner.Next(asset, state)
		if len(tasks) == 0 {
			break
		}
		for i := range tasks {
			tasks[i].Target = &target
		}
		sort.Slice(tasks, func(i, j int) bool {
			return tasks[i].Priority > tasks[j].Priority
		})
		progress := false
		for _, task := range tasks {
			if !state.Budget.RemainingProbes() {
				break
			}
			before := len(asset.Observations)
			if err := e.runTask(ctx, task, asset, state); err != nil && ctx.Err() != nil {
				return nil, err
			}
			if len(asset.Observations) > before {
				progress = true
			}
		}
		e.applyFingerprints(asset)
		if !progress {
			break
		}
	}

	e.applyFingerprints(asset)
	return &ScanResult{Asset: asset, State: state}, nil
}

func (e *Engine) runTask(ctx context.Context, task Task, asset *model.Asset, state *ScanState) error {
	if !e.limiter.Wait(ctx.Done()) {
		return ctx.Err()
	}
	cfg := Config{
		Timeout: e.profile.Budget.ProbeTimeout,
		Ports:   e.profile.TCPPorts,
		Extra:   task.Extra,
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
		Artifacts: e.artifacts,
	}
	obs, err := c.Run(ctx, in)
	state.Budget.ConsumeProbe()
	key := task.CollectorID
	if task.Endpoint != nil {
		key = task.CollectorID + ":" + task.Endpoint.Key()
	}
	state.MarkComplete(key)

	if err != nil {
		return err
	}
	for _, o := range obs {
		if o.AssetID == "" {
			o.AssetID = asset.ID
		}
		asset.AddObservation(o)
		applyObservationToAsset(asset, state, o)
		noteObservationProtocol(state, o)
	}
	return nil
}

func noteObservationProtocol(state *ScanState, o model.ObservationRecord) {
	if state == nil || o.Endpoint == nil {
		return
	}
	proto := protocolFromObservation(o)
	if proto == "" {
		return
	}
	key := model.EndpointKey(o.Endpoint.Address, o.Endpoint.Port, o.Endpoint.Transport)
	match := protocolObservationConfirmed(o)
	state.NoteProtocol(key, proto, match)
}

func protocolFromObservation(o model.ObservationRecord) string {
	switch o.ObservationType {
	case model.ObservationTCPEndpoint, model.ObservationICMPEcho, model.ObservationBanner, "tcp.stack":
		return ""
	default:
		return o.ObservationType
	}
}

func (e *Engine) applyFingerprints(asset *model.Asset) {
	if e == nil || e.fingerprints == nil || asset == nil {
		return
	}
	asset.Claims = asset.Claims[:0]
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

func applyObservationToAsset(asset *model.Asset, state *ScanState, o model.ObservationRecord) {
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
	default:
		if protocolObservationConfirmed(o) {
			asset.AddEndpoint(model.NewEndpoint(o.Endpoint.Address, o.Endpoint.Port, o.Endpoint.Transport, model.EndpointOpen))
			state.Reachability.State = model.ReachabilityConfirmed
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, "tcp.service")
		}
	}
}

// protocolObservationConfirmed reports whether a collector proved a service
// spoke — not merely that TCP connect succeeded.
func protocolObservationConfirmed(o model.ObservationRecord) bool {
	if o.Error != "" || o.Endpoint == nil {
		return false
	}
	switch o.ObservationType {
	case model.ObservationTCPEndpoint, model.ObservationICMPEcho, "tcp.stack":
		return false
	}
	return o.Completeness == "full" || o.Completeness == "partial"
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
