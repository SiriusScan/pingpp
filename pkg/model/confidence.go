package model

// ConfidenceTier is a qualitative certainty class.
// Numeric scores are evidence scores, not calibrated probabilities.
type ConfidenceTier string

const (
	ConfidenceExact    ConfidenceTier = "exact"
	ConfidenceStrong   ConfidenceTier = "strong"
	ConfidenceProbable ConfidenceTier = "probable"
	ConfidenceHint     ConfidenceTier = "hint"
	ConfidenceUnknown  ConfidenceTier = "unknown"
)

// Valid reports whether t is a known confidence tier.
func (t ConfidenceTier) Valid() bool {
	switch t {
	case ConfidenceExact, ConfidenceStrong, ConfidenceProbable, ConfidenceHint, ConfidenceUnknown:
		return true
	default:
		return false
	}
}

// Score bands (0–100 evidence score):
//
//	exact      95–100
//	strong     85–94
//	probable   70–84
//	hint       40–69
//	unknown    below 40
//
// TierFromScore maps an evidence score onto a confidence tier.
// Scores may be provided on a 0–100 or 0–1 scale; values ≤1.0 are treated as fractions.
func TierFromScore(score float64) ConfidenceTier {
	s := score
	if s >= 0 && s <= 1.0 {
		s = s * 100
	}
	switch {
	case s >= 95:
		return ConfidenceExact
	case s >= 85:
		return ConfidenceStrong
	case s >= 70:
		return ConfidenceProbable
	case s >= 40:
		return ConfidenceHint
	default:
		return ConfidenceUnknown
	}
}

// MinScore returns the inclusive lower bound for a tier on the 0–100 scale.
func (t ConfidenceTier) MinScore() float64 {
	switch t {
	case ConfidenceExact:
		return 95
	case ConfidenceStrong:
		return 85
	case ConfidenceProbable:
		return 70
	case ConfidenceHint:
		return 40
	default:
		return 0
	}
}
