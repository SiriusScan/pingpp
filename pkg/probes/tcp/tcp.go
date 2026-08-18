// Package tcp provides TCP connection probe functionality.
// It attempts connections to configured ports to detect host liveliness
// and enumerate which endpoints accept connections.
package tcp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/probes"
)

// DefaultPorts are the standard ports for TCP probing.
var DefaultPorts = []int{22, 80, 443}

// Probe implements the probes.Probe interface using TCP connections.
type Probe struct {
	ports   []int
	timeout time.Duration
}

// New creates a new TCP probe.
func New(ports []int, timeout time.Duration) *Probe {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Probe{
		ports:   ports,
		timeout: timeout,
	}
}

// Name returns the probe type identifier.
func (p *Probe) Name() string {
	return "tcp"
}

// Probe executes TCP connection attempts to every configured port.
// It does not stop after the first successful connection; all ports are
// attempted so callers can enumerate open endpoints.
//
// Success is true when at least one port accepts a connection.
// Per-port outcomes are recorded in Details:
//   - open_ports: comma-separated ports that accepted connections
//   - closed_ports: comma-separated ports that returned connection refused (RST)
//   - filtered_ports: comma-separated ports that timed out or otherwise failed
//
// TTL is never set from the connected socket: IP_TTL via Getsockopt reflects
// local transmit configuration, not the remote host's observed TTL.
func (p *Probe) Probe(ctx context.Context, target string) (probes.ProbeResult, error) {
	result := probes.NewProbeResult()
	result.Protocol = "tcp"

	var openPorts, closedPorts, filteredPorts []int
	var firstOpenPort int
	var firstOpenLatency time.Duration

	for _, port := range p.ports {
		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			writePortDetails(&result, openPorts, closedPorts, filteredPorts)
			if len(openPorts) > 0 {
				result.Success = true
				result.Port = firstOpenPort
				result.Latency = firstOpenLatency
			}
			return result, nil
		default:
		}

		addr := net.JoinHostPort(target, strconv.Itoa(port))
		start := time.Now()

		conn, err := net.DialTimeout("tcp", addr, p.timeout)
		latency := time.Since(start)

		if err == nil {
			_ = conn.Close()
			openPorts = append(openPorts, port)
			if firstOpenPort == 0 {
				firstOpenPort = port
				firstOpenLatency = latency
			}
			continue
		}

		if isConnectionRefused(err) {
			closedPorts = append(closedPorts, port)
			continue
		}

		// Timeouts and other errors are treated as filtered/unknown.
		filteredPorts = append(filteredPorts, port)
	}

	writePortDetails(&result, openPorts, closedPorts, filteredPorts)

	if len(openPorts) > 0 {
		result.Success = true
		result.Port = firstOpenPort
		result.Latency = firstOpenLatency
		return result, nil
	}

	result.Success = false
	result.Error = "no ports responded"
	return result, nil
}

func writePortDetails(result *probes.ProbeResult, open, closed, filtered []int) {
	if len(open) > 0 {
		result.Details["open_ports"] = intsToCSV(open)
		result.Details["connected_port"] = strconv.Itoa(open[0])
	}
	if len(closed) > 0 {
		result.Details["closed_ports"] = intsToCSV(closed)
	}
	if len(filtered) > 0 {
		result.Details["filtered_ports"] = intsToCSV(filtered)
	}
}

func intsToCSV(ports []int) string {
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = strconv.Itoa(port)
	}
	return strings.Join(parts, ",")
}

// isConnectionRefused checks if the error is a connection refused error.
// This indicates the host responded with RST (port closed); it is useful
// endpoint state but is not treated as Success for this probe.
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "refused")
}

// Ports returns a copy of the configured port list.
func (p *Probe) Ports() []int {
	return append([]int(nil), p.ports...)
}
