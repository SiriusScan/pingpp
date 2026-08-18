package scan

import (
	"errors"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/artifact"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/metrics"
	"github.com/SiriusScan/ping++/pkg/transport"
)

// ErrInvalidConfig marks user/config mistakes that the CLI must exit 2 for.
var ErrInvalidConfig = errors.New("invalid scan configuration")

func invalidConfig(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidConfig}, args...)...)
}

// Config is the canonical public scan configuration. Compile it to
// engine.Options + Profile; do not treat engine.Options as the CLI API.
type Config struct {
	Profile      ProfileConfig
	Discovery    DiscoveryConfig
	Ports        PortConfig
	Limits       LimitConfig
	Fingerprints FingerprintConfig
	Artifacts    ArtifactConfig
	Unknowns     UnknownsConfig
	// Registry overrides the default production registry. Tests and adapters
	// may set this; the CLI should leave it nil.
	Registry *engine.Registry

	fingerprintMatcher engine.Matcher
	artifactStore      artifact.Store
	metrics            *metrics.Counters
	networkLimiter     *transport.Limiter
	// probeTypes is a private Sirius/legacy compatibility filter. Profiles
	// are the supported selector; this field is not part of the public Config API.
	probeTypes []string
}

// ProfileConfig selects a named engine profile.
type ProfileConfig struct {
	Name engine.ProfileName
}

// DiscoveryConfig is independent ICMP disable vs skipping the discovery stage.
type DiscoveryConfig struct {
	SkipDiscovery bool
	DisableICMP   bool
}

// PortConfig holds tri-state TCP/UDP port selection.
type PortConfig struct {
	TCP PortSelection
	UDP PortSelection
}

// PortSelection is the public override signal. len(Ports) > 0 is not enough:
// Override + empty Ports disables that transport's enumeration.
type PortSelection struct {
	Override bool
	Ports    []uint16
}

// LimitConfig is timeouts, rate, and concurrency. HostConcurrency is owned
// by Runner (C9); Session stores it but does not fan out targets.
type LimitConfig struct {
	TargetTimeout      time.Duration
	ProbeTimeout       time.Duration
	HTTPTimeout        time.Duration
	RatePerSecond      int
	HostConcurrency    int
	PerHostConcurrency int
	MaxNetworkOps      int
	MaxProbesPerHost   int
}

// FingerprintConfig loads extra packs after the built-in corpus.
type FingerprintConfig struct {
	ExtraDirs []string
}

// ArtifactConfig selects memory vs FileStore persistence.
type ArtifactConfig struct {
	Dir     string
	MaxSize int64
}

// UnknownsConfig is durable export of unmatched banners for corpus work.
type UnknownsConfig struct {
	BannerFile string
}

// DefaultConfig returns production defaults (profile default, no port override).
func DefaultConfig() Config {
	return Config{
		Profile: ProfileConfig{Name: engine.ProfileDefault},
		Limits: LimitConfig{
			HostConcurrency: 50,
		},
	}
}

// Compile maps Config onto engine.Options. Session binds fingerprints,
// artifacts, and the global limiter after this step.
func (c Config) Compile() (engine.Options, error) {
	name := c.Profile.Name
	if name == "" {
		name = engine.ProfileDefault
	}
	if !engine.KnownProfile(name) {
		return engine.Options{}, invalidConfig("unknown profile %q", name)
	}
	if err := validatePortSelection("tcp", c.Ports.TCP); err != nil {
		return engine.Options{}, err
	}
	if err := validatePortSelection("udp", c.Ports.UDP); err != nil {
		return engine.Options{}, err
	}
	if c.Limits.TargetTimeout < 0 {
		return engine.Options{}, invalidConfig("invalid target timeout %s", c.Limits.TargetTimeout)
	}
	if c.Limits.ProbeTimeout < 0 {
		return engine.Options{}, invalidConfig("invalid probe timeout %s", c.Limits.ProbeTimeout)
	}
	if c.Limits.HTTPTimeout < 0 {
		return engine.Options{}, invalidConfig("invalid http timeout %s", c.Limits.HTTPTimeout)
	}
	if c.Limits.RatePerSecond < 0 {
		return engine.Options{}, invalidConfig("invalid rate %d", c.Limits.RatePerSecond)
	}
	if c.Limits.HostConcurrency < 0 {
		return engine.Options{}, invalidConfig("invalid host concurrency %d", c.Limits.HostConcurrency)
	}
	if c.Limits.PerHostConcurrency < 0 {
		return engine.Options{}, invalidConfig("invalid per-host concurrency %d", c.Limits.PerHostConcurrency)
	}

	opts := engine.Options{
		Profile:              name,
		SkipDiscovery:        c.Discovery.SkipDiscovery,
		SkipICMP:             c.Discovery.DisableICMP,
		DisableICMP:          c.Discovery.DisableICMP,
		OverrideTCPPorts:     c.Ports.TCP.Override,
		TCPPorts:             append([]uint16(nil), c.Ports.TCP.Ports...),
		OverrideUDPPorts:     c.Ports.UDP.Override,
		UDPPorts:             append([]uint16(nil), c.Ports.UDP.Ports...),
		RatePerSecond:        c.Limits.RatePerSecond,
		ProbeTimeout:         c.Limits.ProbeTimeout,
		HTTPTimeout:          c.Limits.HTTPTimeout,
		MaxConcurrentPerHost: c.Limits.PerHostConcurrency,
		MaxProbesPerHost:     c.Limits.MaxProbesPerHost,
		MaxNetworkOps:        c.Limits.MaxNetworkOps,
		FingerprintDirs:      append([]string(nil), c.Fingerprints.ExtraDirs...),
		Registry:             c.Registry,
		UnmatchedBannerFile:  c.Unknowns.BannerFile,
		ProbeTypes:           append([]string(nil), c.probeTypes...),
	}
	return opts, nil
}

func validatePortSelection(kind string, sel PortSelection) error {
	for _, p := range sel.Ports {
		if p == 0 {
			return invalidConfig("invalid %s port 0", kind)
		}
	}
	if !sel.Override && len(sel.Ports) > 0 {
		// Allowed: callers may pre-fill Ports without Override. Compile still
		// requires Override to disable (empty) a transport.
		return nil
	}
	return nil
}
