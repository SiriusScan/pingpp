// Package probes defines the interface and types for network probes.
// Each probe type (ICMP, TCP, ARP, SMB) implements the Probe interface
// to provide a modular, extensible fingerprinting system.
package probes

import (
	"context"
	"time"
)

// Probe defines the interface that all probe types must implement.
// This allows the runner to use different probe types interchangeably.
type Probe interface {
	// Name returns the probe type identifier (e.g., "icmp", "tcp", "arp", "smb")
	Name() string

	// Probe executes the probe against the target and returns results.
	// The context can be used for cancellation and timeouts.
	Probe(ctx context.Context, target string) (ProbeResult, error)
}

// ProbeResult contains the results from a single probe execution.
type ProbeResult struct {
	// Success indicates whether the probe received a response
	Success bool `json:"success"`

	// TTL is the Time-To-Live value from the response (used for OS detection)
	TTL int `json:"ttl,omitempty"`

	// Latency is the round-trip time for the probe
	Latency time.Duration `json:"latency,omitempty"`

	// Port is the port number if applicable (TCP probes)
	Port int `json:"port,omitempty"`

	// Protocol is the protocol used (tcp, udp, icmp)
	Protocol string `json:"protocol,omitempty"`

	// Details contains additional probe-specific information
	Details map[string]string `json:"details,omitempty"`

	// Error contains any error message if the probe failed
	Error string `json:"error,omitempty"`
}

// ProbeConfig contains common configuration for all probe types.
type ProbeConfig struct {
	// Timeout is the maximum time to wait for a response
	Timeout time.Duration

	// Retries is the number of times to retry on failure
	Retries int
}

// NewProbeResult creates a new ProbeResult with initialized Details map.
func NewProbeResult() ProbeResult {
	return ProbeResult{
		Details: make(map[string]string),
	}
}

// NewSuccessResult creates a successful probe result with TTL and latency.
func NewSuccessResult(ttl int, latency time.Duration) ProbeResult {
	return ProbeResult{
		Success: true,
		TTL:     ttl,
		Latency: latency,
		Details: make(map[string]string),
	}
}

// NewFailureResult creates a failed probe result with an error message.
func NewFailureResult(err string) ProbeResult {
	return ProbeResult{
		Success: false,
		Error:   err,
		Details: make(map[string]string),
	}
}
