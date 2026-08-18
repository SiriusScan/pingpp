// Package icmp provides ICMP Echo (ping) probe functionality.
// It captures TTL values for OS fingerprinting.
package icmp

import (
	"context"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/SiriusScan/ping++/pkg/probes"
)

// Probe implements the probes.Probe interface using ICMP Echo.
type Probe struct {
	timeout time.Duration
	retries int
}

// New creates a new ICMP probe.
func New(timeout time.Duration, retries int) *Probe {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if retries <= 0 {
		retries = 1
	}
	return &Probe{
		timeout: timeout,
		retries: retries,
	}
}

// Name returns the probe type identifier.
func (p *Probe) Name() string {
	return "icmp"
}

// Probe executes an ICMP Echo request to the target.
func (p *Probe) Probe(ctx context.Context, target string) (probes.ProbeResult, error) {
	result := probes.NewProbeResult()
	result.Protocol = "icmp"

	// Create pinger
	pinger, err := probing.NewPinger(target)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	// Configure pinger
	pinger.Count = 1
	pinger.Timeout = p.timeout
	pinger.SetPrivileged(true) // Try privileged mode first

	// Track TTL from response
	var ttl int
	var latency time.Duration

	pinger.OnRecv = func(pkt *probing.Packet) {
		ttl = pkt.TTL
		latency = pkt.Rtt
	}

	// Try privileged mode, fall back to unprivileged if it fails
	err = pinger.Run()
	if err != nil {
		// Try unprivileged mode
		pinger.SetPrivileged(false)
		err = pinger.Run()
		if err != nil {
			// Final attempt with retries
			for i := 0; i < p.retries && err != nil; i++ {
				time.Sleep(100 * time.Millisecond)
				err = pinger.Run()
			}
		}
	}

	stats := pinger.Statistics()

	if stats.PacketsRecv > 0 {
		result.Success = true
		result.TTL = ttl
		result.Latency = latency
		if latency == 0 && stats.AvgRtt > 0 {
			result.Latency = stats.AvgRtt
		}
		result.Details["packets_sent"] = "1"
		result.Details["packets_recv"] = "1"
	} else {
		result.Success = false
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = "no response"
		}
	}

	return result, nil
}
