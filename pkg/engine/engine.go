package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/SiriusScan/ping++/pkg/model"
)

// Engine orchestrates staged scan execution via the planner and registry.
type Engine struct {
	registry *Registry
	profile  Profile
	planner  *Planner
	limiter  *RateLimiter
}

// Options configures an Engine.
type Options struct {
	Profile       ProfileName
	SkipDiscovery bool
	TCPPorts      []uint16
	RatePerSecond int
	Registry      *Registry
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
	return &Engine{
		registry: opts.Registry,
		profile:  profile,
		planner:  NewPlanner(opts.Registry, profile),
		limiter:  NewRateLimiter(profile.Budget.RatePerSecond),
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

	// Stage 4+: classification / collect for registered protocol collectors only.
	// Attach the resolved Target so collectors can use hostname for SNI / Host.
	classTasks := e.planner.PlanClassification(asset, state)
	for i := range classTasks {
		classTasks[i].Target = &target
	}
	sort.Slice(classTasks, func(i, j int) bool {
		return classTasks[i].Priority > classTasks[j].Priority
	})
	for _, task := range classTasks {
		if !state.Budget.RemainingProbes() {
			break
		}
		if err := e.runTask(ctx, task, asset, state); err != nil && ctx.Err() != nil {
			return nil, err
		}
	}

	return &ScanResult{Asset: asset, State: state}, nil
}

func (e *Engine) runTask(ctx context.Context, task Task, asset *model.Asset, state *ScanState) error {
	if !e.limiter.Wait(ctx.Done()) {
		return ctx.Err()
	}
	cfg := Config{
		Timeout: e.profile.Budget.ProbeTimeout,
		Ports:   e.profile.TCPPorts,
	}
	c, err := e.registry.Create(task.CollectorID, cfg)
	if err != nil {
		return err
	}
	in := CollectorInput{
		Asset:    asset,
		Endpoint: task.Endpoint,
		Target:   task.Target,
		State:    state,
		Timeout:  cfg.Timeout,
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
	}
	return nil
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
		case model.EndpointOpen:
			state.Reachability.State = model.ReachabilityConfirmed
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, "tcp.open")
		case model.EndpointClosed:
			if state.Reachability.State == model.ReachabilityUnknown {
				state.Reachability.State = model.ReachabilityProbable
			}
			state.Reachability.Reasons = appendUniqueReason(state.Reachability.Reasons, "tcp.rst")
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
