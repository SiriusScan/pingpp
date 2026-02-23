// Package runner provides the core execution engine for ping++.
// It manages probe execution, concurrency, and result aggregation.
package runner

import (
	"errors"
	"time"
)

// DefaultTimeout is the default probe timeout.
const DefaultTimeout = 3 * time.Second

// DefaultThreads is the default number of concurrent workers.
const DefaultThreads = 50

// DefaultRetries is the default number of probe retries.
const DefaultRetries = 2

// DefaultRate is the default probes per second rate limit.
const DefaultRate = 100

// DefaultTCPPorts are the default ports for TCP probing.
// Includes Windows ports for OS detection (135, 139, 445, 3389).
var DefaultTCPPorts = []int{22, 80, 443, 135, 139, 445, 3389, 548}

// DefaultProbeTypes are the default probe types to use.
// Includes SSH, HTTP, and SMB for enhanced OS fingerprinting.
var DefaultProbeTypes = []string{"icmp", "tcp", "ssh", "http", "smb"}

// OnResultCallback is the function signature for result callbacks.
// This is called for each host as results become available.
type OnResultCallback func(*Result)

// Options contains configuration for the ping++ runner.
// This follows the ProjectDiscovery pattern of using an Options struct
// that can be populated via CLI or programmatically.
type Options struct {
	// Targets is a list of targets to scan (IP, CIDR, or hostname)
	Targets []string

	// TargetFile is a file containing targets (one per line)
	TargetFile string

	// ProbeTypes specifies which probes to use (icmp, tcp, ssh, http, smb, arp)
	ProbeTypes []string

	// TCPPorts are the ports to use for TCP probing
	TCPPorts []int

	// Timeout is the per-probe timeout duration
	Timeout time.Duration

	// Retries is the number of times to retry failed probes
	Retries int

	// Rate is the maximum probes per second
	Rate int

	// Threads is the number of concurrent workers
	Threads int

	// OnResult is called for each completed host scan
	OnResult OnResultCallback

	// Silent suppresses all output except results
	Silent bool

	// Debug enables debug logging
	Debug bool

	// JSON enables JSON output format
	JSON bool

	// Output is the file to write results to
	Output string

	// ResolveHostname enables reverse DNS lookup
	ResolveHostname bool

	// DisableICMP disables ICMP probing (use when not running as root)
	DisableICMP bool

	// ShowAll shows all hosts including offline (default: only show alive hosts)
	ShowAll bool

	// Verbose enables verbose output with detection reasoning
	Verbose bool
}

// DefaultOptions returns Options with sensible defaults.
func DefaultOptions() *Options {
	return &Options{
		Targets:         []string{},
		ProbeTypes:      DefaultProbeTypes,
		TCPPorts:        DefaultTCPPorts,
		Timeout:         DefaultTimeout,
		Retries:         DefaultRetries,
		Rate:            DefaultRate,
		Threads:         DefaultThreads,
		Silent:          false,
		Debug:           false,
		JSON:            false,
		ResolveHostname: false,
		DisableICMP:     false,
		ShowAll:         false,
		Verbose:         false,
	}
}

// Validate checks that the options are valid and returns an error if not.
func (o *Options) Validate() error {
	if len(o.Targets) == 0 && o.TargetFile == "" {
		return errors.New("no targets specified: use -t or provide a target file")
	}

	if len(o.ProbeTypes) == 0 {
		return errors.New("no probe types specified")
	}

	if o.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	if o.Threads <= 0 {
		return errors.New("threads must be positive")
	}

	if o.Rate <= 0 {
		return errors.New("rate must be positive")
	}

	return nil
}

// HasProbeType checks if a specific probe type is enabled.
func (o *Options) HasProbeType(probeType string) bool {
	for _, pt := range o.ProbeTypes {
		if pt == probeType {
			return true
		}
	}
	return false
}

// Clone creates a deep copy of the options.
func (o *Options) Clone() *Options {
	clone := *o
	clone.Targets = make([]string, len(o.Targets))
	copy(clone.Targets, o.Targets)
	clone.ProbeTypes = make([]string, len(o.ProbeTypes))
	copy(clone.ProbeTypes, o.ProbeTypes)
	clone.TCPPorts = make([]int, len(o.TCPPorts))
	copy(clone.TCPPorts, o.TCPPorts)
	return &clone
}
