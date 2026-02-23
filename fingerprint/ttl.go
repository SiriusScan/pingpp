// Package fingerprint provides OS detection from network characteristics.
package fingerprint

// Common initial TTL values by operating system.
// When a packet traverses the network, each hop decrements the TTL by 1.
// By observing the received TTL and calculating the original, we can infer the OS.
var TTLDefaults = map[string]int{
	"linux":   64,  // Linux, Android, macOS, iOS, FreeBSD
	"windows": 128, // Windows (all versions)
	"cisco":   255, // Cisco IOS, Solaris, some network devices
}

// OSFamilyFromTTL maps original TTL values to OS families.
var OSFamilyFromTTL = map[int]string{
	64:  "linux",   // Also covers macOS, BSD, Android
	128: "windows", // Windows
	255: "cisco",   // Network devices, Solaris
}

// DetectOSFromTTL determines the OS family based on observed TTL.
// It calculates the likely original TTL and maps it to an OS family.
func DetectOSFromTTL(observedTTL int) string {
	if observedTTL <= 0 {
		return "unknown"
	}

	originalTTL := CalculateOriginalTTL(observedTTL)

	if osFamily, ok := OSFamilyFromTTL[originalTTL]; ok {
		return osFamily
	}

	return "unknown"
}

// CalculateOriginalTTL estimates the original TTL from observed TTL.
// It rounds up to the nearest common initial TTL value (64, 128, 255).
func CalculateOriginalTTL(observedTTL int) int {
	if observedTTL <= 0 {
		return 0
	}

	// Round up to nearest common initial TTL
	switch {
	case observedTTL <= 64:
		return 64
	case observedTTL <= 128:
		return 128
	case observedTTL <= 255:
		return 255
	default:
		return 255
	}
}

// EstimateHops calculates the number of network hops from TTL.
func EstimateHops(observedTTL int) int {
	originalTTL := CalculateOriginalTTL(observedTTL)
	return originalTTL - observedTTL
}

// GetOSHint returns a more detailed OS hint if available.
// This can be enhanced with additional fingerprinting data.
func GetOSHint(observedTTL int, details map[string]string) string {
	osFamily := DetectOSFromTTL(observedTTL)

	// Check for additional hints from probe details
	if details != nil {
		// SMB responses can provide Windows version info
		if smbVersion, ok := details["smb_version"]; ok {
			return "Windows " + smbVersion
		}

		// If we detect specific ports, we might refine the guess
		if port, ok := details["connected_port"]; ok {
			switch port {
			case "22":
				if osFamily == "linux" {
					return "Linux/Unix (SSH detected)"
				}
			case "3389":
				return "Windows (RDP detected)"
			case "445":
				return "Windows (SMB detected)"
			}
		}
	}

	return osFamily
}

// Confidence represents how confident we are in the OS detection.
type Confidence int

const (
	ConfidenceUnknown Confidence = iota
	ConfidenceLow
	ConfidenceMedium
	ConfidenceHigh
)

// GetConfidence returns the confidence level for an OS detection.
func GetConfidence(probeCount int, ttlConsistent bool) Confidence {
	if probeCount == 0 {
		return ConfidenceUnknown
	}

	if probeCount >= 3 && ttlConsistent {
		return ConfidenceHigh
	}

	if probeCount >= 2 && ttlConsistent {
		return ConfidenceMedium
	}

	return ConfidenceLow
}
