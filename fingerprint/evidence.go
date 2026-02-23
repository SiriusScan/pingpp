// Package fingerprint provides OS detection from network characteristics.
package fingerprint

import "fmt"

// EvidenceSource represents the source of OS fingerprint evidence
type EvidenceSource string

const (
	SourceSSHBanner  EvidenceSource = "ssh_banner"
	SourceHTTPServer EvidenceSource = "http_server"
	SourceSMB        EvidenceSource = "smb"
	SourceTTL        EvidenceSource = "ttl"
	SourcePorts      EvidenceSource = "ports"
	SourcePortCombo  EvidenceSource = "port_combination"
)

// Default weights for each evidence source
var DefaultWeights = map[EvidenceSource]float64{
	SourceSSHBanner:  0.95, // Highly reliable, often includes exact distro
	SourceSMB:        0.98, // Direct OS info from NTLMSSP - extremely accurate
	SourceHTTPServer: 0.80, // Common but sometimes spoofed
	SourcePortCombo:  0.75, // Strong correlation (scaled by number of ports)
	SourcePorts:      0.30, // Low indicator (single port alone is weak)
	SourceTTL:        0.20, // Very weak, fallback only
}

// Evidence represents a single piece of OS fingerprint evidence
type Evidence struct {
	Source    EvidenceSource `json:"source"`     // Where this evidence came from
	OSFamily  string         `json:"os_family"`  // linux, windows, macos, freebsd, cisco
	OSVersion string         `json:"os_version"` // Ubuntu 22.04, Windows 11, etc.
	Weight    float64        `json:"weight"`     // Confidence weight (0.0-1.0)
	Raw       string         `json:"raw"`        // Raw data that led to this conclusion
}

// NewEvidence creates a new Evidence with default weight for the source
func NewEvidence(source EvidenceSource, family, version, raw string) Evidence {
	weight := DefaultWeights[source]
	return Evidence{
		Source:    source,
		OSFamily:  family,
		OSVersion: version,
		Weight:    weight,
		Raw:       raw,
	}
}

// NewEvidenceWithWeight creates a new Evidence with custom weight
func NewEvidenceWithWeight(source EvidenceSource, family, version, raw string, weight float64) Evidence {
	return Evidence{
		Source:    source,
		OSFamily:  family,
		OSVersion: version,
		Weight:    weight,
		Raw:       raw,
	}
}

// String returns a human-readable representation of the evidence
func (e Evidence) String() string {
	if e.OSVersion != "" {
		return fmt.Sprintf("%s: %s (%s) [weight: %.2f]", e.Source, e.OSFamily, e.OSVersion, e.Weight)
	}
	return fmt.Sprintf("%s: %s [weight: %.2f]", e.Source, e.OSFamily, e.Weight)
}

// FingerprintResult contains the aggregated OS fingerprint result
type FingerprintResult struct {
	OSFamily     string     `json:"os_family"`     // Primary OS family
	OSVersion    string     `json:"os_version"`    // Most specific version detected
	Confidence   float64    `json:"confidence"`    // Overall confidence (0.0-1.0)
	Evidence     []Evidence `json:"evidence"`      // All evidence collected
	Reasoning    string     `json:"reasoning"`     // Human-readable explanation
	TotalWeight  float64    `json:"total_weight"`  // Sum of evidence weights
	ConflictInfo string     `json:"conflict_info"` // Info about conflicting evidence
}

// NewFingerprintResult creates an empty fingerprint result
func NewFingerprintResult() *FingerprintResult {
	return &FingerprintResult{
		OSFamily: "unknown",
		Evidence: make([]Evidence, 0),
	}
}

// HasEvidence returns true if there is any evidence
func (r *FingerprintResult) HasEvidence() bool {
	return len(r.Evidence) > 0
}

// GetEvidenceBySource returns all evidence from a specific source
func (r *FingerprintResult) GetEvidenceBySource(source EvidenceSource) []Evidence {
	var result []Evidence
	for _, e := range r.Evidence {
		if e.Source == source {
			result = append(result, e)
		}
	}
	return result
}

// GetStrongestEvidence returns the evidence with highest weight
func (r *FingerprintResult) GetStrongestEvidence() *Evidence {
	if len(r.Evidence) == 0 {
		return nil
	}

	var strongest *Evidence
	for i := range r.Evidence {
		if strongest == nil || r.Evidence[i].Weight > strongest.Weight {
			strongest = &r.Evidence[i]
		}
	}
	return strongest
}
