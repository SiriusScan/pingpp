// Package fingerprint provides OS detection from network characteristics.
package fingerprint

import (
	"github.com/SiriusScan/ping++/pkg/probes"
)

// OSResult contains the aggregated OS detection result.
type OSResult struct {
	Family      string     `json:"family"`       // linux, windows, cisco, unknown
	Hint        string     `json:"hint"`         // More specific hint
	TTL         int        `json:"ttl"`          // Observed TTL
	OriginalTTL int        `json:"original_ttl"` // Calculated original TTL
	Hops        int        `json:"hops"`         // Estimated network hops
	Confidence  Confidence `json:"confidence"`   // Detection confidence
}

// AggregateOSFromProbes analyzes multiple probe results to determine OS.
func AggregateOSFromProbes(results []probes.ProbeResult) OSResult {
	osResult := OSResult{
		Family: "unknown",
	}

	if len(results) == 0 {
		return osResult
	}

	// Collect TTL values from successful probes
	var ttlValues []int
	var allDetails = make(map[string]string)

	for _, pr := range results {
		if pr.Success && pr.TTL > 0 {
			ttlValues = append(ttlValues, pr.TTL)
		}
		// Merge details
		for k, v := range pr.Details {
			allDetails[k] = v
		}
	}

	if len(ttlValues) == 0 {
		osResult.Confidence = ConfidenceUnknown
		return osResult
	}

	// Use the most common TTL (mode) or the first one
	ttl := mode(ttlValues)
	osResult.TTL = ttl
	osResult.OriginalTTL = CalculateOriginalTTL(ttl)
	osResult.Hops = EstimateHops(ttl)
	osResult.Family = DetectOSFromTTL(ttl)
	osResult.Hint = GetOSHint(ttl, allDetails)

	// Calculate confidence
	ttlConsistent := allSame(ttlValues)
	osResult.Confidence = GetConfidence(len(ttlValues), ttlConsistent)

	return osResult
}

// mode returns the most common value in a slice.
func mode(values []int) int {
	if len(values) == 0 {
		return 0
	}

	counts := make(map[int]int)
	for _, v := range values {
		counts[v]++
	}

	maxCount := 0
	modeValue := values[0]
	for v, c := range counts {
		if c > maxCount {
			maxCount = c
			modeValue = v
		}
	}

	return modeValue
}

// allSame returns true if all values in the slice are the same.
func allSame(values []int) bool {
	if len(values) <= 1 {
		return true
	}
	first := values[0]
	for _, v := range values[1:] {
		if v != first {
			return false
		}
	}
	return true
}
