// Package metrics defines runtime scan instrumentation.
// Ground-truth precision (exact/strong correct) lives in pkg/metrics/eval,
// not on the scan path.
package metrics

import "sync"

// Counters tracks runtime scan activity. It must not require ground truth.
type Counters struct {
	mu sync.Mutex

	CollectorsExecuted int64
	ProtocolMatches    int64
	Timeouts           int64
	BytesTotal         int64
	UnknownEndpoints   int64
	ClaimExact         int64
	ClaimStrong        int64
	ClaimProbable      int64
	ClaimHint          int64
	ConflictCount      int64
	UnmatchedBanners   int64
	unmatched          []string
}

// RecordCollector records that a collector finished with the given outcome.
func (c *Counters) RecordCollector(outcome string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.CollectorsExecuted++
	switch outcome {
	case "timeout":
		c.Timeouts++
	}
}

// RecordProtocolMatch counts an endpoint-scoped protocol claim, not a generic collector success.
func (c *Counters) RecordProtocolMatch() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ProtocolMatches++
}

// RecordBytes adds payload bytes observed by the meter.
func (c *Counters) RecordBytes(n int64) {
	if c == nil || n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BytesTotal += n
}

// RecordUnknownEndpoint increments the unknown-endpoint counter.
func (c *Counters) RecordUnknownEndpoint() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UnknownEndpoints++
}

// RecordClaimTier counts fused claims by qualitative tier.
func (c *Counters) RecordClaimTier(tier string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch tier {
	case "exact":
		c.ClaimExact++
	case "strong":
		c.ClaimStrong++
	case "probable":
		c.ClaimProbable++
	case "hint":
		c.ClaimHint++
	}
}

// RecordUnmatchedBanner keeps a short dump of banners with no product claim.
func (c *Counters) RecordUnmatchedBanner(banner string) {
	if c == nil || banner == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UnmatchedBanners++
	if len(c.unmatched) < 64 {
		c.unmatched = append(c.unmatched, banner)
	}
}

// UnmatchedBannerDump returns recorded unmatched banners for corpus work.
func (c *Counters) UnmatchedBannerDump() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.unmatched))
	copy(out, c.unmatched)
	return out
}

// Snapshot returns a copy of counters for reporting.
func (c *Counters) Snapshot() map[string]float64 {
	if c == nil {
		return map[string]float64{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]float64{
		"collectors_executed": float64(c.CollectorsExecuted),
		"protocol_matches":    float64(c.ProtocolMatches),
		"timeouts":            float64(c.Timeouts),
		"bytes_total":         float64(c.BytesTotal),
		"unknown_endpoints":   float64(c.UnknownEndpoints),
		"claim_exact":         float64(c.ClaimExact),
		"claim_strong":        float64(c.ClaimStrong),
		"claim_probable":      float64(c.ClaimProbable),
		"claim_hint":          float64(c.ClaimHint),
		"conflict_count":      float64(c.ConflictCount),
		"unmatched_banners":   float64(c.UnmatchedBanners),
	}
}

// RecordConflict increments the runtime conflict counter.
func (c *Counters) RecordConflict() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ConflictCount++
}
