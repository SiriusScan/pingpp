// Package eval holds offline fingerprint-quality counters that require ground truth.
// The scan path must not update these.
package eval

import "sync"

// PrecisionCounters tracks whether claims at a tier were correct versus labels.
type PrecisionCounters struct {
	mu sync.Mutex

	ExactTotal, ExactCorrect       int64
	StrongTotal, StrongCorrect     int64
	ProbableTotal, ProbableCorrect int64
	UnknownRateSamples             int64
	UnknownCount                   int64
}

// RecordClaimOutcome records whether a labeled claim at a tier was correct.
func (c *PrecisionCounters) RecordClaimOutcome(tier string, correct bool) {
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
func (c *PrecisionCounters) RecordUnknown(unknown bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UnknownRateSamples++
	if unknown {
		c.UnknownCount++
	}
}

// Snapshot returns labeled precision ratios.
func (c *PrecisionCounters) Snapshot() map[string]float64 {
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
	return out
}
