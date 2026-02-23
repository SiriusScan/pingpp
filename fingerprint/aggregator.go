// Package fingerprint provides OS detection from network characteristics.
package fingerprint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SiriusScan/ping++/pkg/probes"
)

// Aggregator combines evidence from multiple sources to determine OS
type Aggregator struct {
	evidence []Evidence
}

// NewAggregator creates a new fingerprint aggregator
func NewAggregator() *Aggregator {
	return &Aggregator{
		evidence: make([]Evidence, 0),
	}
}

// AddEvidence adds a piece of evidence to the aggregator
func (a *Aggregator) AddEvidence(e Evidence) {
	if e.OSFamily != "" {
		a.evidence = append(a.evidence, e)
	}
}

// AddEvidenceFromProbe extracts evidence from a probe result
func (a *Aggregator) AddEvidenceFromProbe(pr probes.ProbeResult) {
	if !pr.Success {
		return
	}

	// Extract TTL evidence
	if pr.TTL > 0 {
		osFamily := DetectOSFromTTL(pr.TTL)
		if osFamily != "unknown" {
			originalTTL := CalculateOriginalTTL(pr.TTL)
			raw := fmt.Sprintf("TTL %d (original: %d)", pr.TTL, originalTTL)
			a.AddEvidence(NewEvidence(SourceTTL, osFamily, "", raw))
		}
	}

	// Extract SSH banner evidence
	if banner, ok := pr.Details["ssh_banner"]; ok && banner != "" {
		if family, ok := pr.Details["os_family"]; ok && family != "" {
			version := pr.Details["os_version"]
			a.AddEvidence(NewEvidence(SourceSSHBanner, family, version, banner))
		}
	}

	// Extract HTTP server evidence
	if server, ok := pr.Details["http_server"]; ok && server != "" {
		if family, ok := pr.Details["os_family"]; ok && family != "" {
			version := pr.Details["os_version"]
			a.AddEvidence(NewEvidence(SourceHTTPServer, family, version, server))
		}
	}

	// Extract SMB evidence
	if _, ok := pr.Details["smb_port_open"]; ok {
		if family, ok := pr.Details["os_family"]; ok && family != "" {
			version := pr.Details["os_version"]
			if version == "" {
				version = pr.Details["os_hint"]
			}

			// Build informative raw string with NTLMSSP details
			var rawParts []string
			if build := pr.Details["os_build"]; build != "" {
				rawParts = append(rawParts, "NTLMSSP Build "+build)
			} else {
				rawParts = append(rawParts, "SMB port 445")
			}
			if computerName := pr.Details["computer_name"]; computerName != "" {
				rawParts = append(rawParts, "Computer: "+computerName)
			}
			if domain := pr.Details["domain"]; domain != "" && domain != pr.Details["computer_name"] {
				rawParts = append(rawParts, "Domain: "+domain)
			}
			raw := strings.Join(rawParts, ", ")

			a.AddEvidence(NewEvidence(SourceSMB, family, version, raw))
		}
	}
}

// AddPortEvidence analyzes open ports and adds port-based evidence
func (a *Aggregator) AddPortEvidence(openPorts []int) {
	if len(openPorts) == 0 {
		return
	}

	analysis := AnalyzePorts(openPorts)

	// Add individual port indicators
	for _, indicator := range analysis.Indicators {
		raw := fmt.Sprintf("Port %d (%s)", indicator.Port, indicator.Service)
		a.AddEvidence(NewEvidenceWithWeight(SourcePorts, indicator.OSFamily, "", raw, indicator.Weight*0.5))
	}

	// Add combination evidence (stronger)
	for _, combo := range analysis.Combinations {
		portsStr := intsToString(combo.Ports)
		raw := fmt.Sprintf("Port combination: %s", portsStr)
		a.AddEvidence(NewEvidenceWithWeight(SourcePortCombo, combo.OSFamily, combo.Version, raw, combo.Weight))
	}
}

// Aggregate processes all evidence and produces a final result
func (a *Aggregator) Aggregate() *FingerprintResult {
	result := NewFingerprintResult()
	result.Evidence = a.evidence

	if len(a.evidence) == 0 {
		result.Reasoning = "No evidence collected"
		return result
	}

	// Score each OS family
	familyScores := make(map[string]float64)
	familyVersions := make(map[string]string)
	familyBestWeight := make(map[string]float64)

	for _, e := range a.evidence {
		familyScores[e.OSFamily] += e.Weight

		// Track the best version for each family (from highest weight evidence)
		if e.Weight > familyBestWeight[e.OSFamily] && e.OSVersion != "" {
			familyBestWeight[e.OSFamily] = e.Weight
			familyVersions[e.OSFamily] = e.OSVersion
		}
	}

	// Find the winning OS family
	var bestFamily string
	var bestScore float64
	for family, score := range familyScores {
		if score > bestScore {
			bestScore = score
			bestFamily = family
		}
	}

	result.OSFamily = bestFamily
	result.TotalWeight = bestScore

	// Set version from best evidence
	if version, ok := familyVersions[bestFamily]; ok {
		result.OSVersion = version
	}

	// Calculate confidence
	// Consider: total weight, number of sources, agreement between sources
	numSources := len(a.uniqueSources())
	maxPossibleWeight := float64(numSources) * 1.0 // Max weight per source is 1.0
	result.Confidence = minFloat(bestScore/maxPossibleWeight, 1.0)

	// Boost confidence if multiple sources agree
	if numSources >= 3 && a.allSourcesAgree(bestFamily) {
		result.Confidence = minFloat(result.Confidence*1.2, 1.0)
	}

	// Check for conflicts
	conflicts := a.findConflicts(bestFamily)
	if len(conflicts) > 0 {
		result.ConflictInfo = fmt.Sprintf("Conflicting evidence from: %s", strings.Join(conflicts, ", "))
		result.Confidence *= 0.8 // Reduce confidence on conflicts
	}

	// Build reasoning
	result.Reasoning = a.buildReasoning(bestFamily, bestScore, numSources)

	return result
}

// uniqueSources returns the unique evidence sources
func (a *Aggregator) uniqueSources() []EvidenceSource {
	seen := make(map[EvidenceSource]bool)
	var sources []EvidenceSource
	for _, e := range a.evidence {
		if !seen[e.Source] {
			seen[e.Source] = true
			sources = append(sources, e.Source)
		}
	}
	return sources
}

// allSourcesAgree checks if all evidence points to the same OS family
func (a *Aggregator) allSourcesAgree(family string) bool {
	for _, e := range a.evidence {
		if e.OSFamily != family {
			return false
		}
	}
	return true
}

// findConflicts returns sources that disagree with the winning family
func (a *Aggregator) findConflicts(winningFamily string) []string {
	var conflicts []string
	seen := make(map[string]bool)
	for _, e := range a.evidence {
		if e.OSFamily != winningFamily {
			key := fmt.Sprintf("%s (%s)", e.Source, e.OSFamily)
			if !seen[key] {
				seen[key] = true
				conflicts = append(conflicts, key)
			}
		}
	}
	return conflicts
}

// buildReasoning creates a human-readable explanation
func (a *Aggregator) buildReasoning(family string, score float64, numSources int) string {
	// Get strongest evidence for this family
	var strongestEvidence []Evidence
	for _, e := range a.evidence {
		if e.OSFamily == family {
			strongestEvidence = append(strongestEvidence, e)
		}
	}

	// Sort by weight descending
	sort.Slice(strongestEvidence, func(i, j int) bool {
		return strongestEvidence[i].Weight > strongestEvidence[j].Weight
	})

	var parts []string
	for i, e := range strongestEvidence {
		if i >= 3 { // Limit to top 3
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%.0f%%)", e.Source, e.Weight*100))
	}

	return fmt.Sprintf("Detected as %s based on %d sources: %s (total score: %.2f)",
		family, numSources, strings.Join(parts, ", "), score)
}

// AggregateFromProbes is a convenience function to aggregate multiple probe results
func AggregateFromProbes(probeResults []probes.ProbeResult, openPorts []int) *FingerprintResult {
	agg := NewAggregator()

	for _, pr := range probeResults {
		agg.AddEvidenceFromProbe(pr)
	}

	if len(openPorts) > 0 {
		agg.AddPortEvidence(openPorts)
	}

	return agg.Aggregate()
}

// intsToString converts a slice of ints to a comma-separated string
func intsToString(ints []int) string {
	strs := make([]string, len(ints))
	for i, v := range ints {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(strs, ", ")
}
