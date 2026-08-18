package appscanner

import (
	"context"
	"strconv"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/output"
	"github.com/SiriusScan/ping++/pkg/runner"
	"github.com/SiriusScan/ping++/pkg/scan"
)

// FingerprintResult mirrors the app-scanner FingerprintResult type.
type FingerprintResult struct {
	IsAlive  bool                   `json:"is_alive"`
	OSFamily string                 `json:"os_family"`
	TTL      int                    `json:"ttl"`
	Details  map[string]string      `json:"details"`
	Asset    map[string]interface{} `json:"asset,omitempty"`
}

// PingPlusPlusStrategy implements FingerprintStrategy using the new engine when possible.
type PingPlusPlusStrategy struct {
	ProbeTypes      []string
	Timeout         time.Duration
	DisableICMP     bool
	UseLegacyRunner bool
}

// NewStrategy creates a strategy with defaults.
func NewStrategy() *PingPlusPlusStrategy {
	return &PingPlusPlusStrategy{
		ProbeTypes: []string{"icmp", "tcp"},
		Timeout:    3 * time.Second,
	}
}

// NewStrategyWithOptions creates a strategy with custom options.
func NewStrategyWithOptions(probeTypes []string, timeout time.Duration, disableICMP bool) *PingPlusPlusStrategy {
	return &PingPlusPlusStrategy{ProbeTypes: probeTypes, Timeout: timeout, DisableICMP: disableICMP}
}

// Fingerprint performs host fingerprinting on the target.
func (p *PingPlusPlusStrategy) Fingerprint(target string) (FingerprintResult, error) {
	if p.UseLegacyRunner {
		return p.fingerprintLegacyRunner(target)
	}
	return p.fingerprintEngine(target)
}

func (p *PingPlusPlusStrategy) fingerprintEngine(target string) (FingerprintResult, error) {
	result := FingerprintResult{Details: map[string]string{}}
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout*5)
	defer cancel()
	res, err := scan.Scan(ctx, target, scan.ScanOptions{
		Options: engine.Options{
			Profile:       engine.ProfileQuick,
			SkipICMP:      p.DisableICMP,
			ProbeTypes:    p.ProbeTypes,
			RatePerSecond: 200,
		},
		Timeout: p.Timeout * 5,
	})
	if err != nil {
		return result, err
	}
	alive := res.State.Reachability.State == model.ReachabilityConfirmed ||
		res.State.Reachability.State == model.ReachabilityProbable
	sirius := output.ToSiriusHost(res.Asset, alive)
	result.IsAlive = alive
	if os, ok := sirius["os"].(string); ok {
		result.OSFamily = os
	}
	result.Asset = sirius
	if conf, ok := sirius["confidence"].(float64); ok {
		result.Details["confidence"] = strconv.FormatFloat(conf, 'f', 2, 64)
	}
	return result, nil
}

func (p *PingPlusPlusStrategy) fingerprintLegacyRunner(target string) (FingerprintResult, error) {
	result := FingerprintResult{Details: make(map[string]string)}
	opts := runner.DefaultOptions()
	opts.Targets = []string{target}
	opts.ProbeTypes = p.ProbeTypes
	opts.Timeout = p.Timeout
	opts.DisableICMP = p.DisableICMP
	opts.Threads = 1
	var scanResult *runner.Result
	opts.OnResult = func(r *runner.Result) { scanResult = r }
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
			result.Details = map[string]string{}
		}
		result.Details["confidence"] = strconv.FormatFloat(scanResult.OSConfidence, 'f', 2, 64)
	}
	return result, nil
}
