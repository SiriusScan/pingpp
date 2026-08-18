package model

// ClaimKind distinguishes what a claim asserts about an asset or endpoint.
type ClaimKind string

const (
	ClaimProtocol    ClaimKind = "protocol"
	ClaimService     ClaimKind = "service"
	ClaimProduct     ClaimKind = "product"
	ClaimApplication ClaimKind = "application"
	ClaimOS          ClaimKind = "os"
	ClaimDevice      ClaimKind = "device"
	ClaimHardware    ClaimKind = "hardware"
	ClaimIdentity    ClaimKind = "identity"
)

// Valid reports whether k is a known claim kind.
func (k ClaimKind) Valid() bool {
	switch k {
	case ClaimProtocol, ClaimService, ClaimProduct, ClaimApplication,
		ClaimOS, ClaimDevice, ClaimHardware, ClaimIdentity:
		return true
	default:
		return false
	}
}

// Claim is an inference produced by fingerprint rules from observations.
// Protocol, product, application, OS, and device claims remain separate.
type Claim struct {
	ID         string    `json:"id"`
	Kind       ClaimKind `json:"kind"`
	Vendor     string    `json:"vendor,omitempty"`
	Product    string    `json:"product,omitempty"`
	Version    string    `json:"version,omitempty"`
	Family     string    `json:"family,omitempty"`
	DeviceType string    `json:"device_type,omitempty"`
	CPE        string    `json:"cpe,omitempty"`

	// Subject identifies what the claim is about (asset ID or endpoint key).
	Subject string `json:"subject,omitempty"`
	// Attribute is an optional structured attribute name (e.g. device.vendor).
	Attribute string `json:"attribute,omitempty"`
	// Value is the primary asserted value when not covered by Product/Version.
	Value string `json:"value,omitempty"`

	Score      float64        `json:"score"`
	Confidence ConfidenceTier `json:"confidence"`

	EvidenceIDs      []string `json:"evidence_ids,omitempty"`
	ContradictionIDs []string `json:"contradiction_ids,omitempty"`
	RuleIDs          []string `json:"rule_ids,omitempty"`

	// CorrelationGroup groups evidence that must not independently inflate confidence.
	CorrelationGroup string `json:"correlation_group,omitempty"`
}

// NewClaim constructs a claim with confidence derived from score.
func NewClaim(kind ClaimKind, product string, score float64) Claim {
	return Claim{
		Kind:       kind,
		Product:    product,
		Value:      product,
		Score:      score,
		Confidence: TierFromScore(score),
	}
}
