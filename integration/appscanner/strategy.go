// Package appscanner provides integration with the Sirius app-scanner.
// It implements the FingerprintStrategy interface to enable ping++ as
// the fingerprinting engine in the scan pipeline.
package appscanner

import (
	"context"
	"time"

	"github.com/SiriusScan/ping++/fingerprint"
	"github.com/SiriusScan/ping++/pkg/runner"
)

// FingerprintResult mirrors the app-scanner FingerprintResult type.
// This allows ping++ to be used without importing app-scanner directly.
type FingerprintResult struct {
	IsAlive  bool              `json:"is_alive"`
	OSFamily string            `json:"os_family"`
	TTL      int               `json:"ttl"`
	Details  map[string]string `json:"details"`
}

// PingPlusPlusStrategy implements the FingerprintStrategy interface
// from app-scanner using ping++ for actual fingerprinting.
type PingPlusPlusStrategy struct {
	// ProbeTypes specifies which probes to use
	ProbeTypes []string

	// Timeout is the per-probe timeout
	Timeout time.Duration

	// DisableICMP disables ICMP probing (for unprivileged mode)
	DisableICMP bool
}

// NewStrategy creates a new PingPlusPlusStrategy with default settings.
func NewStrategy() *PingPlusPlusStrategy {
	return &PingPlusPlusStrategy{
		ProbeTypes: []string{"icmp", "tcp"},
		Timeout:    3 * time.Second,
	}
}

// NewStrategyWithOptions creates a strategy with custom options.
func NewStrategyWithOptions(probeTypes []string, timeout time.Duration, disableICMP bool) *PingPlusPlusStrategy {
	return &PingPlusPlusStrategy{
		ProbeTypes:  probeTypes,
		Timeout:     timeout,
		DisableICMP: disableICMP,
	}
}

// Fingerprint performs host fingerprinting on the target.
// This method signature matches the app-scanner FingerprintStrategy interface.
func (p *PingPlusPlusStrategy) Fingerprint(target string) (FingerprintResult, error) {
	result := FingerprintResult{
		Details: make(map[string]string),
	}

	// Create runner options
	opts := runner.DefaultOptions()
	opts.Targets = []string{target}
	opts.ProbeTypes = p.ProbeTypes
	opts.Timeout = p.Timeout
	opts.DisableICMP = p.DisableICMP
	opts.Threads = 1 // Single target, single thread

	// Capture result via callback
	var scanResult *runner.Result
	opts.OnResult = func(r *runner.Result) {
		scanResult = r
	}

	// Create and run the runner
	r, err := runner.NewRunner(opts)
	if err != nil {
		return result, err
	}
	defer r.Close()

	// Execute the scan with longer timeout for concurrent scenarios
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout*5)
	defer cancel()

	if err := r.RunEnumeration(ctx); err != nil {
		return result, err
	}

	// Convert result
	if scanResult != nil {
		result.IsAlive = scanResult.IsAlive
		result.OSFamily = scanResult.OSFamily
		result.TTL = scanResult.TTL
		result.Details = scanResult.Details

		// Add fingerprint confidence
		osResult := fingerprint.AggregateOSFromProbes(scanResult.Probes)
		result.Details["confidence"] = confidenceToString(osResult.Confidence)
		result.Details["hops"] = string(rune('0' + osResult.Hops))
	}

	return result, nil
}

// confidenceToString converts confidence level to string.
func confidenceToString(c fingerprint.Confidence) string {
	switch c {
	case fingerprint.ConfidenceHigh:
		return "high"
	case fingerprint.ConfidenceMedium:
		return "medium"
	case fingerprint.ConfidenceLow:
		return "low"
	default:
		return "unknown"
	}
}
