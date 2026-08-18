package model

import "time"

// Artifact is metadata for bounded raw evidence retained for replay and
// future fingerprint development. Content is addressed by SHA-256 where practical.
type Artifact struct {
	ID          string    `json:"id"`
	SHA256      string    `json:"sha256"`
	MediaType   string    `json:"media_type,omitempty"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	Description string    `json:"description,omitempty"`
	// MaxSize documents the size limit that was enforced when storing.
	MaxSize int64 `json:"max_size,omitempty"`
}

// DefaultArtifactMaxBytes is the default per-artifact size cap (256 KiB).
const DefaultArtifactMaxBytes int64 = 256 * 1024

// ReachabilityState describes host-level reachability with provenance.
// Introduced alongside the domain model so discovery can stop using a bare bool.
type ReachabilityState string

const (
	ReachabilityConfirmed    ReachabilityState = "confirmed"
	ReachabilityProbable     ReachabilityState = "probable"
	ReachabilityUnresponsive ReachabilityState = "unresponsive"
	ReachabilityUnknown      ReachabilityState = "unknown"
)

// Valid reports whether s is a known reachability state.
func (s ReachabilityState) Valid() bool {
	switch s {
	case ReachabilityConfirmed, ReachabilityProbable, ReachabilityUnresponsive, ReachabilityUnknown:
		return true
	default:
		return false
	}
}

// Reachability holds state plus reasons that established it.
type Reachability struct {
	State   ReachabilityState `json:"state"`
	Reasons []string          `json:"reasons,omitempty"`
}
