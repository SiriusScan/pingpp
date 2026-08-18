// Package metrics defines fingerprint quality instrumentation hooks.
package metrics

import "sync"

// Counters tracks precision-oriented fingerprint metrics.
type Counters struct {
	mu sync.Mutex

	ExactTotal, ExactCorrect       int64
	StrongTotal, StrongCorrect     int64
	ProbableTotal, ProbableCorrect int64
	UnknownRateSamples             int64
	UnknownCount                   int64
	ConflictCount                  int64
	ProbesTotal                    int64
	BytesTotal                     int64
	ResolvedEndpoints              int64
}

// RecordClaimOutcome records whether a claim at a tier was correct.
func (c *Counters) RecordClaimOutcome(tier string, correct bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch tier {
	case "exact":
		c.ExactTotal++
		if correct {
			c.ExactCorrect++
		}
	case "strong":
		c.StrongTotal++
		if correct {
			c.StrongCorrect++
		}
	case "probable":
		c.ProbableTotal++
		if correct {
			c.ProbableCorrect++
		}
	}
}

// RecordUnknown tracks unknown rate samples.
func (c *Counters) RecordUnknown(unknown bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UnknownRateSamples++
	if unknown {
		c.UnknownCount++
	}
}

// RecordEffort tracks probes/bytes per resolved endpoint.
func (c *Counters) RecordEffort(probes int, bytes int64, resolved bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ProbesTotal += int64(probes)
	c.BytesTotal += bytes
	if resolved {
		c.ResolvedEndpoints++
	}
}

// Snapshot returns a copy of counters for reporting.
func (c *Counters) Snapshot() map[string]float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]float64{}
	if c.ExactTotal > 0 {
		out["p_correct_exact"] = float64(c.ExactCorrect) / float64(c.ExactTotal)
	}
	if c.StrongTotal > 0 {
		out["p_correct_strong"] = float64(c.StrongCorrect) / float64(c.StrongTotal)
	}
	if c.ProbableTotal > 0 {
		out["p_correct_probable"] = float64(c.ProbableCorrect) / float64(c.ProbableTotal)
	}
	if c.UnknownRateSamples > 0 {
		out["unknown_rate"] = float64(c.UnknownCount) / float64(c.UnknownRateSamples)
	}
	if c.ResolvedEndpoints > 0 {
		out["mean_probes_per_resolved"] = float64(c.ProbesTotal) / float64(c.ResolvedEndpoints)
		out["mean_bytes_per_resolved"] = float64(c.BytesTotal) / float64(c.ResolvedEndpoints)
	}
	out["conflict_count"] = float64(c.ConflictCount)
	return out
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
