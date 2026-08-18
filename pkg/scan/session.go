package scan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/SiriusScan/ping++/pkg/artifact"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/metrics"
	"github.com/SiriusScan/ping++/pkg/transport"
)

// Session is a prepared scanning runtime. Registry, fingerprint corpus,
// artifact store, metrics, and the global network limiter load once.
// Each Scan call owns isolated Asset/ScanState/meter.
//
// Scan is serialized on this type until Runner host-concurrency (C9) fans
// out across sessions or a proven concurrent Engine split exists. The
// global limiter is still attached so C7 rate applies to every dial.
type Session struct {
	mu      sync.Mutex
	closed  bool
	eng     *engine.Engine
	timeout time.Duration
}

// NewSession validates cfg and loads shared resources once.
func NewSession(cfg Config) (*Session, error) {
	opts, err := cfg.Compile()
	if err != nil {
		return nil, err
	}
	if opts.Registry == nil {
		opts.Registry = NewRegistry()
	}

	store := opts.Artifacts
	if cfg.artifactStore != nil {
		store = cfg.artifactStore
	}
	if store == nil {
		if cfg.Artifacts.Dir != "" {
			fs, err := artifact.NewFileStore(cfg.Artifacts.Dir, artifact.FileStoreOptions{
				MaxSize: cfg.Artifacts.MaxSize,
			})
			if err != nil {
				return nil, err
			}
			store = fs
		} else {
			maxSize := cfg.Artifacts.MaxSize
			if maxSize <= 0 {
				maxSize = engine.PrepareProfile(opts).Budget.MaxArtifactBytes
			}
			store = artifact.NewMemoryStore(maxSize)
		}
	}

	fp := opts.Fingerprints
	if cfg.fingerprintMatcher != nil {
		fp = cfg.fingerprintMatcher
	}
	if fp == nil {
		eng := fingerprint.NewEngine()
		eng.SetArtifactStore(store)
		if err := eng.LoadBuiltinPacks(); err != nil {
			return nil, fmt.Errorf("load builtin fingerprints: %w", err)
		}
		for _, dir := range opts.FingerprintDirs {
			if err := eng.LoadDir(dir); err != nil {
				return nil, fmt.Errorf("fingerprint dir %s: %w", dir, err)
			}
		}
		fp = eng
	}

	counters := opts.Metrics
	if cfg.metrics != nil {
		counters = cfg.metrics
	}
	if counters == nil {
		counters = &metrics.Counters{}
	}

	profile := engine.PrepareProfile(opts)
	rate := profile.Budget.RatePerSecond
	if cfg.networkLimiter != nil {
		opts.NetworkLimiter = cfg.networkLimiter
	} else if opts.NetworkLimiter == nil {
		opts.NetworkLimiter = transport.NewLimiter(rate)
	}
	opts.Artifacts = store
	opts.Fingerprints = fp
	opts.Metrics = counters

	eng, err := engine.NewEngine(opts)
	if err != nil {
		return nil, err
	}
	return &Session{
		eng:     eng,
		timeout: cfg.Limits.TargetTimeout,
	}, nil
}

// Scan runs the engine pipeline for one target. It is not safe for concurrent
// callers of the same Session; Runner host-concurrency is a later stage.
func (s *Session) Scan(ctx context.Context, target string) (*engine.ScanResult, error) {
	if s == nil {
		return nil, fmt.Errorf("nil session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("session closed")
	}
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	return s.eng.ScanTarget(ctx, target)
}

// Close marks the session unusable. Artifact stores currently need no flush.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// ConfigFromScanOptions maps the compatibility ScanOptions wrapper onto Config.
func ConfigFromScanOptions(opts ScanOptions) Config {
	cfg := DefaultConfig()
	cfg.Profile.Name = opts.Profile
	cfg.Discovery.SkipDiscovery = opts.SkipDiscovery
	cfg.Discovery.DisableICMP = opts.DisableICMP || opts.SkipICMP
	if opts.OverrideTCPPorts || len(opts.TCPPorts) > 0 {
		cfg.Ports.TCP = PortSelection{Override: true, Ports: append([]uint16(nil), opts.TCPPorts...)}
	}
	if opts.OverrideUDPPorts || len(opts.UDPPorts) > 0 {
		cfg.Ports.UDP = PortSelection{Override: true, Ports: append([]uint16(nil), opts.UDPPorts...)}
	}
	cfg.Limits.RatePerSecond = opts.RatePerSecond
	cfg.Limits.ProbeTimeout = opts.ProbeTimeout
	cfg.Limits.HTTPTimeout = opts.HTTPTimeout
	cfg.Limits.PerHostConcurrency = opts.MaxConcurrentPerHost
	cfg.Limits.MaxProbesPerHost = opts.MaxProbesPerHost
	cfg.Limits.MaxNetworkOps = opts.MaxNetworkOps
	cfg.Limits.TargetTimeout = opts.Timeout
	if opts.FingerprintDir != "" {
		cfg.Fingerprints.ExtraDirs = append(cfg.Fingerprints.ExtraDirs, opts.FingerprintDir)
	}
	cfg.Fingerprints.ExtraDirs = append(cfg.Fingerprints.ExtraDirs, opts.FingerprintDirs...)
	cfg.Registry = opts.Registry
	cfg.fingerprintMatcher = opts.Fingerprints
	cfg.artifactStore = opts.Artifacts
	cfg.metrics = opts.Metrics
	cfg.networkLimiter = opts.NetworkLimiter
	return cfg
}
