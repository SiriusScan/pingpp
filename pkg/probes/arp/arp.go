// Package arp provides ARP-based probe functionality for Layer 2 enumeration.
// This probe only works on local network segments.
package arp

import (
	"context"
	"time"

	"github.com/SiriusScan/ping++/pkg/probes"
)

// Probe implements the probes.Probe interface using ARP requests.
type Probe struct {
	timeout time.Duration
}

// New creates a new ARP probe.
func New(timeout time.Duration) *Probe {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Probe{
		timeout: timeout,
	}
}

// Name returns the probe type identifier.
func (p *Probe) Name() string {
	return "arp"
}

// Probe executes an ARP request to the target.
// This is a placeholder implementation - full ARP scanning requires
// raw socket access and is platform-specific.
func (p *Probe) Probe(ctx context.Context, target string) (probes.ProbeResult, error) {
	result := probes.NewProbeResult()
	result.Protocol = "arp"

	// TODO: Implement ARP scanning
	// This requires:
	// 1. Determining if target is on local subnet
	// 2. Sending ARP request via raw socket
	// 3. Capturing ARP response with MAC address
	//
	// For now, return not supported
	result.Success = false
	result.Error = "ARP probe not yet implemented"
	result.Details["status"] = "not_implemented"

	return result, nil
}
