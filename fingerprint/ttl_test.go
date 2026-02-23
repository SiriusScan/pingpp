package fingerprint

import "testing"

func TestDetectOSFromTTL(t *testing.T) {
	tests := []struct {
		name        string
		observedTTL int
		expected    string
	}{
		{"Linux TTL 64", 64, "linux"},
		{"Linux TTL 63 (1 hop)", 63, "linux"},
		{"Linux TTL 56 (8 hops)", 56, "linux"},
		{"Windows TTL 128", 128, "windows"},
		{"Windows TTL 127 (1 hop)", 127, "windows"},
		{"Windows TTL 120 (8 hops)", 120, "windows"},
		{"Windows TTL 65", 65, "windows"},
		{"Cisco TTL 255", 255, "cisco"},
		{"Cisco TTL 250 (5 hops)", 250, "cisco"},
		{"Cisco TTL 129", 129, "cisco"},
		{"Zero TTL", 0, "unknown"},
		{"Negative TTL", -1, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectOSFromTTL(tt.observedTTL)
			if result != tt.expected {
				t.Errorf("DetectOSFromTTL(%d) = %s, want %s", tt.observedTTL, result, tt.expected)
			}
		})
	}
}

func TestCalculateOriginalTTL(t *testing.T) {
	tests := []struct {
		observedTTL int
		expected    int
	}{
		{64, 64},
		{63, 64},
		{56, 64},
		{1, 64},
		{128, 128},
		{127, 128},
		{65, 128},
		{255, 255},
		{129, 255},
		{0, 0},
		{-1, 0},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := CalculateOriginalTTL(tt.observedTTL)
			if result != tt.expected {
				t.Errorf("CalculateOriginalTTL(%d) = %d, want %d", tt.observedTTL, result, tt.expected)
			}
		})
	}
}

func TestEstimateHops(t *testing.T) {
	tests := []struct {
		observedTTL  int
		expectedHops int
	}{
		{64, 0},
		{63, 1},
		{56, 8},
		{128, 0},
		{127, 1},
		{120, 8},
		{255, 0},
		{250, 5},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := EstimateHops(tt.observedTTL)
			if result != tt.expectedHops {
				t.Errorf("EstimateHops(%d) = %d, want %d", tt.observedTTL, result, tt.expectedHops)
			}
		})
	}
}

func TestGetConfidence(t *testing.T) {
	tests := []struct {
		probeCount    int
		ttlConsistent bool
		expected      Confidence
	}{
		{0, true, ConfidenceUnknown},
		{1, true, ConfidenceLow},
		{2, true, ConfidenceMedium},
		{2, false, ConfidenceLow},
		{3, true, ConfidenceHigh},
		{3, false, ConfidenceLow},
		{5, true, ConfidenceHigh},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := GetConfidence(tt.probeCount, tt.ttlConsistent)
			if result != tt.expected {
				t.Errorf("GetConfidence(%d, %t) = %d, want %d", tt.probeCount, tt.ttlConsistent, result, tt.expected)
			}
		})
	}
}
