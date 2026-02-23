package probes

import (
	"testing"
	"time"
)

func TestNewProbeResult(t *testing.T) {
	result := NewProbeResult()

	if result.Details == nil {
		t.Error("NewProbeResult().Details should not be nil")
	}

	if result.Success {
		t.Error("NewProbeResult().Success should be false")
	}
}

func TestNewSuccessResult(t *testing.T) {
	ttl := 64
	latency := 10 * time.Millisecond

	result := NewSuccessResult(ttl, latency)

	if !result.Success {
		t.Error("NewSuccessResult().Success should be true")
	}

	if result.TTL != ttl {
		t.Errorf("TTL = %d, want %d", result.TTL, ttl)
	}

	if result.Latency != latency {
		t.Errorf("Latency = %v, want %v", result.Latency, latency)
	}

	if result.Details == nil {
		t.Error("Details should not be nil")
	}
}

func TestNewFailureResult(t *testing.T) {
	errMsg := "connection refused"

	result := NewFailureResult(errMsg)

	if result.Success {
		t.Error("NewFailureResult().Success should be false")
	}

	if result.Error != errMsg {
		t.Errorf("Error = %s, want %s", result.Error, errMsg)
	}

	if result.Details == nil {
		t.Error("Details should not be nil")
	}
}
