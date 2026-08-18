// Package adapters wraps third-party fingerprint databases behind ping++ interfaces.
// Third-party types must never leak into pkg/model.
package adapters

import (
	"github.com/SiriusScan/ping++/pkg/model"
)

// FingerprintAdapter converts observations into claims using an external corpus.
type FingerprintAdapter interface {
	Name() string
	Match(observations []model.ObservationRecord) ([]model.Claim, error)
}

// WebTechDetector is a Wappalyzer-compatible technology detection surface.
type WebTechDetector interface {
	Detect(httpObs model.HTTPObservation) ([]model.Claim, error)
}

// RecogMatcher is a Recog-compatible fingerprint matcher surface.
type RecogMatcher interface {
	MatchField(protocol, field, value string) ([]model.Claim, error)
}
