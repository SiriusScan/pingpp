// Package tcp provides TCP connection probe functionality.
// It attempts connections to common ports to detect host liveliness.
package tcp

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
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

// Probe executes TCP connection attempts to the target.
func (p *Probe) Probe(ctx context.Context, target string) (probes.ProbeResult, error) {
	result := probes.NewProbeResult()
	result.Protocol = "tcp"

	startTime := time.Now()
	portsTimedOut := 0

	// Try each port until one succeeds
	for _, port := range p.ports {
		select {
		case <-ctx.Done():
			result.Error = "context cancelled"
			return result, nil
		default:
		}

		addr := fmt.Sprintf("%s:%d", target, port)
		start := time.Now()

		conn, err := net.DialTimeout("tcp", addr, p.timeout)
		latency := time.Since(start)

		if err == nil {
			// Connection successful - host is definitely alive
			result.Success = true
			result.Port = port
			result.Latency = latency

			// Try to get TTL from connection
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				if ttl := getTTLFromConn(tcpConn); ttl > 0 {
					result.TTL = ttl
				}
			}

			result.Details["connected_port"] = fmt.Sprintf("%d", port)
			conn.Close()
			// #region agent log
			log.Printf("[TCP DEBUG] %s:%d CONNECTED in %v (host ALIVE)", target, port, latency)
			// #endregion
			return result, nil
		}

		// Check if the error indicates the host is reachable but port is closed
		if isConnectionRefused(err) {
			// IMPORTANT: RST (connection refused) is NOT reliable for host detection.
			// Gateways/routers often respond with RST for non-existent hosts.
			//
			// We NO LONGER trust RST as proof of host being alive.
			// Only an actual TCP CONNECTED proves a host is alive.
			// RST is logged but ignored for liveness detection.
			totalElapsed := time.Since(startTime)

			// #region agent log
			log.Printf("[TCP DEBUG] %s:%d REFUSED in %v, total=%v, timeouts=%d (IGNORED - RST not reliable)",
				target, port, latency, totalElapsed, portsTimedOut)
			// #endregion
			// Continue to next port - RST doesn't prove host is alive
		}

		// Check if this was a timeout
		if isTimeout(err) {
			portsTimedOut++
			// #region agent log
			log.Printf("[TCP DEBUG] %s:%d TIMEOUT after %v (timeouts=%d)", target, port, latency, portsTimedOut)
			// #endregion
		} else {
			// #region agent log
			log.Printf("[TCP DEBUG] %s:%d FAILED in %v: %v", target, port, latency, err)
			// #endregion
		}
	}

	// No ports responded
	result.Success = false
	result.Error = "no ports responded"
	// #region agent log
	log.Printf("[TCP DEBUG] %s: ALL PORTS FAILED after %v - marking as DOWN", target, time.Since(startTime))
	// #endregion
	return result, nil
}

// isTimeout checks if the error is a timeout error.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	// Check for net.Error with Timeout() method
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "i/o timeout")
}

// getTTLFromConn attempts to get the TTL from a TCP connection.
// This is platform-specific and may not work on all systems.
func getTTLFromConn(conn *net.TCPConn) int {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0
	}

	var ttl int
	err = rawConn.Control(func(fd uintptr) {
		// Try to get TTL via socket option (Linux)
		val, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
		if err == nil {
			ttl = val
		}
	})

	if err != nil {
		return 0
	}

	return ttl
}

// isConnectionRefused checks if the error is a connection refused error.
// This indicates the host is up but the port is closed.
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "refused")
}
