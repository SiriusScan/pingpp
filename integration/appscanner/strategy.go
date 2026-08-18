// Package appscanner provides integration with the Sirius app-scanner.
// It implements the FingerprintStrategy interface to enable ping++ as
// the fingerprinting engine in the scan pipeline.
package appscanner

import (
	"context"
	"strconv"
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
//
// OS detection uses the runner's AggregateFromProbes path exclusively.
// Do not re-run the legacy TTL-only AggregateOSFromProbes here — that
// duplicated and could diverge from the primary aggregation result.
func (p *PingPlusPlusStrategy) Fingerprint(target string) (FingerprintResult, error) {
	result := FingerprintResult{
		Details: make(map[string]string),
	}

	opts := runner.DefaultOptions()
	opts.Targets = []string{target}
	opts.ProbeTypes = p.ProbeTypes
	opts.Timeout = p.Timeout
	opts.DisableICMP = p.DisableICMP
	opts.Threads = 1

	var scanResult *runner.Result
	opts.OnResult = func(r *runner.Result) {
		scanResult = r
	}

	r, err := runner.NewRunner(opts)
	if err != nil {
		return result, err
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout*5)
	defer cancel()

	if err := r.RunEnumeration(ctx); err != nil {
		return result, err
	}

	if scanResult != nil {
		result.IsAlive = scanResult.IsAlive
		result.OSFamily = scanResult.OSFamily
		result.TTL = scanResult.TTL
		result.Details = scanResult.Details
		if result.Details == nil {
			result.Details = make(map[string]string)
		}

		// Surface confidence and hop estimate from the runner's already-computed
		// aggregation rather than invoking a second OS aggregation path.
		result.Details["confidence"] = strconv.FormatFloat(scanResult.OSConfidence, 'f', 2, 64)
		if scanResult.TTL > 0 {
			result.Details["hops"] = strconv.Itoa(fingerprint.EstimateHops(scanResult.TTL))
		}
		if scanResult.OSVersion != "" {
			result.Details["os_version"] = scanResult.OSVersion
		}
		if scanResult.OSReason != "" {
			result.Details["os_reason"] = scanResult.OSReason
		}
	}

	return result, nil
}
