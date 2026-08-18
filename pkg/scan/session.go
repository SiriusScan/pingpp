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
// Each Scan call builds a per-target Engine that shares those resources
// so Runner host-concurrency is real.
type Session struct {
	mu      sync.Mutex
	closed  bool
	opts    engine.Options
	metrics *metrics.Counters
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
	if opts.UnmatchedBannerFile != "" {
		sink, err := metrics.OpenBannerSink(opts.UnmatchedBannerFile)
		if err != nil {
			return nil, fmt.Errorf("unmatched banner file: %w", err)
		}
		counters.AttachBannerSink(sink)
		opts.UnmatchedBannerFile = ""
	}

	return &Session{
		opts:    opts,
		metrics: counters,
		timeout: cfg.Limits.TargetTimeout,
	}, nil
}

// Scan runs the engine pipeline for one target. Concurrent callers share
// fingerprints, artifacts, metrics, and the global limiter.
func (s *Session) Scan(ctx context.Context, target string) (*engine.ScanResult, error) {
	if s == nil {
		return nil, fmt.Errorf("nil session")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("session closed")
	}
	opts := s.opts
	timeout := s.timeout
	s.mu.Unlock()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	eng, err := engine.NewEngine(opts)
	if err != nil {
		return nil, err
	}
	return eng.ScanTarget(ctx, target)
}

// Close marks the session unusable and closes the unmatched-banner sink.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.metrics == nil {
		return nil
	}
	return s.metrics.Close()
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
	cfg.Unknowns.BannerFile = opts.UnmatchedBannerFile
	cfg.probeTypes = append([]string(nil), opts.ProbeTypes...)
	return cfg
}
