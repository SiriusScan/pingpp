package runner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/SiriusScan/ping++/fingerprint"
	"github.com/SiriusScan/ping++/pkg/probes"
	"github.com/SiriusScan/ping++/pkg/probes/arp"
	"github.com/SiriusScan/ping++/pkg/probes/http"
	"github.com/SiriusScan/ping++/pkg/probes/icmp"
	"github.com/SiriusScan/ping++/pkg/probes/smb"
	"github.com/SiriusScan/ping++/pkg/probes/ssh"
	"github.com/SiriusScan/ping++/pkg/probes/tcp"
)

// Runner is the main execution engine for ping++.
// It manages probe execution, concurrency, and result aggregation.
type Runner struct {
	options *Options
	probes  []probes.Probe

	// Stats tracking
	totalHosts   int64
	scannedHosts int64
	aliveHosts   int64

	// Control
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// NewRunner creates a new Runner with the given options.
func NewRunner(options *Options) (*Runner, error) {
	if options == nil {
		options = DefaultOptions()
	}

	if err := options.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &Runner{
		options: options,
		probes:  make([]probes.Probe, 0),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Initialize enabled probes
	if err := r.initProbes(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize probes: %w", err)
	}

	return r, nil
}

// initProbes initializes the enabled probe types.
func (r *Runner) initProbes() error {
	for _, probeType := range r.options.ProbeTypes {
		switch strings.ToLower(probeType) {
		case "icmp":
			if !r.options.DisableICMP {
				r.probes = append(r.probes, icmp.New(r.options.Timeout, r.options.Retries))
			}
		case "tcp":
			r.probes = append(r.probes, tcp.New(r.options.TCPPorts, r.options.Timeout))
		case "ssh":
			r.probes = append(r.probes, ssh.New(r.options.Timeout))
		case "http":
			r.probes = append(r.probes, http.New(r.options.Timeout))
		case "arp":
			r.probes = append(r.probes, arp.New(r.options.Timeout))
		case "smb":
			r.probes = append(r.probes, smb.New(r.options.Timeout))
		default:
			return fmt.Errorf("unknown probe type: %s", probeType)
		}
	}

	if len(r.probes) == 0 {
		return fmt.Errorf("no probes enabled")
	}

	return nil
}

// RunEnumeration executes the scan against all targets.
// This is the main entry point, following the ProjectDiscovery pattern.
func (r *Runner) RunEnumeration(ctx context.Context) error {
	// Merge contexts
	if ctx != nil {
		r.ctx, r.cancel = context.WithCancel(ctx)
	}

	// Load targets
	targets, err := r.loadTargets()
	if err != nil {
		return fmt.Errorf("failed to load targets: %w", err)
	}

	r.totalHosts = int64(len(targets))

	if r.totalHosts == 0 {
		return fmt.Errorf("no targets to scan")
	}

	// Create work channel
	work := make(chan string, r.options.Threads)

	// Start workers
	for i := 0; i < r.options.Threads; i++ {
		r.wg.Add(1)
		go r.worker(work)
	}

	// Send targets to workers
	go func() {
	sendLoop:
		for _, target := range targets {
			select {
			case <-r.ctx.Done():
				break sendLoop
			case work <- target:
			}
		}
		close(work)
	}()

	// Wait for completion
	r.wg.Wait()

	return nil
}

// worker processes targets from the work channel.
func (r *Runner) worker(work <-chan string) {
	defer r.wg.Done()

	for target := range work {
		select {
		case <-r.ctx.Done():
			return
		default:
			result := r.scanHost(target)
			atomic.AddInt64(&r.scannedHosts, 1)

			if result.IsAlive {
				atomic.AddInt64(&r.aliveHosts, 1)
			}

			// Call the result callback if set
			if r.options.OnResult != nil {
				r.options.OnResult(result)
			}
		}
	}
}

// scanHost performs all enabled probes against a single host.
//
// Liveness is additive: any successful probe (including ICMP) marks the host
// alive. A lack of open TCP ports must never reverse that conclusion — a host
// can be alive with all scanned ports closed, filtered, or UDP-only.
func (r *Runner) scanHost(target string) *Result {
	result := NewResult(target)

	// Resolve hostname if enabled
	if r.options.ResolveHostname {
		if names, err := net.LookupAddr(target); err == nil && len(names) > 0 {
			result.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	// Run all enabled probes
	for _, probe := range r.probes {
		probeResult, err := probe.Probe(r.ctx, target)
		if err != nil {
			probeResult = probes.NewFailureResult(err.Error())
		}
		result.AddProbeResult(probeResult)
	}

	// Calculate original TTL for reference (from probes that observe real remote TTL)
	if result.TTL > 0 {
		result.OriginalTTL = fingerprint.CalculateOriginalTTL(result.TTL)
	}

	// Use the fingerprint aggregator for OS detection
	if result.IsAlive {
		fpResult := fingerprint.AggregateFromProbes(result.Probes, result.OpenPorts)

		result.OSFamily = fpResult.OSFamily
		result.OSVersion = fpResult.OSVersion
		result.OSConfidence = fpResult.Confidence
		result.OSReason = fpResult.Reasoning
		result.Evidence = fpResult.Evidence

		// Add conflict info if present
		if fpResult.ConflictInfo != "" {
			result.Details["os_conflict"] = fpResult.ConflictInfo
		}
	} else {
		result.OSFamily = "unknown"
		result.OSReason = "Host is not alive - no OS detection performed"
	}

	return result
}

// loadTargets loads all targets from options.
func (r *Runner) loadTargets() ([]string, error) {
	var targets []string

	// Add direct targets
	for _, t := range r.options.Targets {
		expanded, err := expandTarget(t)
		if err != nil {
			return nil, fmt.Errorf("invalid target %s: %w", t, err)
		}
		targets = append(targets, expanded...)
	}

	// Add targets from file
	if r.options.TargetFile != "" {
		fileTargets, err := loadTargetFile(r.options.TargetFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load target file: %w", err)
		}
		for _, t := range fileTargets {
			expanded, err := expandTarget(t)
			if err != nil {
				continue // Skip invalid targets in file
			}
			targets = append(targets, expanded...)
		}
	}

	return targets, nil
}

// expandTarget expands a target (IP, CIDR, or hostname) into individual IPs.
func expandTarget(target string) ([]string, error) {
	// Check if it's a CIDR
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}

	// Check if it's an IP
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}, nil
	}

	// Assume it's a hostname, resolve it
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			result = append(result, ipv4.String())
		}
	}

	return result, nil
}

// expandCIDR expands a CIDR notation into individual IPs.
func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /24 and larger
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// incrementIP increments an IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// loadTargetFile loads targets from a file (one per line).
func loadTargetFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

// Close cleans up runner resources.
func (r *Runner) Close() {
	r.cancel()
}

// Stats returns current scan statistics.
func (r *Runner) Stats() (total, scanned, alive int64) {
	return r.totalHosts, atomic.LoadInt64(&r.scannedHosts), atomic.LoadInt64(&r.aliveHosts)
}
