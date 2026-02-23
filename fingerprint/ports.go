// Package fingerprint provides OS detection from network characteristics.
package fingerprint

// PortIndicator represents an OS indicator from a specific port
type PortIndicator struct {
	Port     int
	Service  string
	OSFamily string
	Weight   float64
}

// OS-specific port indicators
var portIndicators = []PortIndicator{
	// Windows-specific ports
	{Port: 135, Service: "RPC Endpoint Mapper", OSFamily: "windows", Weight: 0.70},
	{Port: 139, Service: "NetBIOS Session", OSFamily: "windows", Weight: 0.50},
	{Port: 445, Service: "SMB", OSFamily: "windows", Weight: 0.75},
	{Port: 3389, Service: "RDP", OSFamily: "windows", Weight: 0.80},
	{Port: 5985, Service: "WinRM HTTP", OSFamily: "windows", Weight: 0.70},
	{Port: 5986, Service: "WinRM HTTPS", OSFamily: "windows", Weight: 0.70},

	// macOS-specific ports
	{Port: 548, Service: "AFP", OSFamily: "macos", Weight: 0.90},
	{Port: 5900, Service: "Screen Sharing", OSFamily: "macos", Weight: 0.40}, // VNC is cross-platform
	{Port: 3283, Service: "ARD", OSFamily: "macos", Weight: 0.85},
	{Port: 88, Service: "Kerberos", OSFamily: "macos", Weight: 0.30}, // Also Windows

	// Linux/Unix-specific ports
	{Port: 111, Service: "Portmapper/rpcbind", OSFamily: "linux", Weight: 0.60},
	{Port: 2049, Service: "NFS", OSFamily: "linux", Weight: 0.65},
	{Port: 631, Service: "CUPS", OSFamily: "linux", Weight: 0.50}, // Also macOS
	{Port: 6000, Service: "X11", OSFamily: "linux", Weight: 0.70},

	// Network device indicators
	{Port: 23, Service: "Telnet", OSFamily: "cisco", Weight: 0.20}, // Common on network devices
	{Port: 161, Service: "SNMP", OSFamily: "cisco", Weight: 0.15},  // Network devices
	{Port: 830, Service: "NETCONF", OSFamily: "cisco", Weight: 0.60},
}

// Port combinations that strongly indicate specific OS
type PortCombination struct {
	Ports    []int
	OSFamily string
	Version  string
	Weight   float64
}

var portCombinations = []PortCombination{
	// Windows combinations - stronger weights for more ports
	{
		Ports:    []int{135, 139, 445, 3389},
		OSFamily: "windows",
		Version:  "Windows (RPC+NetBIOS+SMB+RDP)",
		Weight:   0.98, // 4 ports = very high confidence
	},
	{
		Ports:    []int{135, 445, 3389},
		OSFamily: "windows",
		Version:  "Windows (RPC+SMB+RDP)",
		Weight:   0.95, // 3 ports = high confidence
	},
	{
		Ports:    []int{139, 445, 3389},
		OSFamily: "windows",
		Version:  "Windows (NetBIOS+SMB+RDP)",
		Weight:   0.95,
	},
	{
		Ports:    []int{135, 445},
		OSFamily: "windows",
		Version:  "Windows (RPC+SMB)",
		Weight:   0.88,
	},
	{
		Ports:    []int{139, 445},
		OSFamily: "windows",
		Version:  "Windows (NetBIOS+SMB)",
		Weight:   0.88,
	},
	{
		Ports:    []int{445, 3389},
		OSFamily: "windows",
		Version:  "Windows (SMB+RDP)",
		Weight:   0.88,
	},
	{
		Ports:    []int{5985, 5986},
		OSFamily: "windows",
		Version:  "Windows (WinRM)",
		Weight:   0.85,
	},

	// Linux combinations
	{
		Ports:    []int{22, 111, 2049},
		OSFamily: "linux",
		Version:  "Linux (SSH+NFS)",
		Weight:   0.80,
	},
	{
		Ports:    []int{22, 111},
		OSFamily: "linux",
		Version:  "Linux (SSH+Portmapper)",
		Weight:   0.65,
	},
	{
		Ports:    []int{22, 631},
		OSFamily: "linux",
		Version:  "Linux (SSH+CUPS)",
		Weight:   0.55,
	},

	// macOS combinations
	{
		Ports:    []int{22, 548},
		OSFamily: "macos",
		Version:  "macOS (SSH+AFP)",
		Weight:   0.90,
	},
	{
		Ports:    []int{548, 631},
		OSFamily: "macos",
		Version:  "macOS (AFP+CUPS)",
		Weight:   0.85,
	},
	{
		Ports:    []int{548, 3283},
		OSFamily: "macos",
		Version:  "macOS (AFP+ARD)",
		Weight:   0.95,
	},
	{
		Ports:    []int{22, 548, 3283},
		OSFamily: "macos",
		Version:  "macOS",
		Weight:   0.95,
	},
}

// PortAnalysisResult contains the result of port-based OS analysis
type PortAnalysisResult struct {
	OSFamily     string
	OSVersion    string
	Confidence   float64
	Indicators   []PortIndicator
	Combinations []PortCombination
	TotalWeight  float64
}

// AnalyzePorts analyzes a list of open ports to determine likely OS
func AnalyzePorts(openPorts []int) PortAnalysisResult {
	result := PortAnalysisResult{
		Indicators:   make([]PortIndicator, 0),
		Combinations: make([]PortCombination, 0),
	}

	if len(openPorts) == 0 {
		return result
	}

	// Create port set for fast lookup
	portSet := make(map[int]bool)
	for _, p := range openPorts {
		portSet[p] = true
	}

	// Score by OS family
	scores := make(map[string]float64)
	versions := make(map[string]string)

	// Check individual port indicators
	for _, indicator := range portIndicators {
		if portSet[indicator.Port] {
			result.Indicators = append(result.Indicators, indicator)
			scores[indicator.OSFamily] += indicator.Weight
		}
	}

	// Check port combinations (stronger indicators)
	for _, combo := range portCombinations {
		if hasAllPorts(portSet, combo.Ports) {
			result.Combinations = append(result.Combinations, combo)
			scores[combo.OSFamily] += combo.Weight
			versions[combo.OSFamily] = combo.Version
		}
	}

	// Find the highest scoring OS
	maxScore := 0.0
	for family, score := range scores {
		if score > maxScore {
			maxScore = score
			result.OSFamily = family
			result.TotalWeight = score
			if v, ok := versions[family]; ok {
				result.OSVersion = v
			}
		}
	}

	// Calculate confidence (normalize to 0-1)
	// Max possible score is roughly 3.0 for a full match
	result.Confidence = minFloat(maxScore/3.0, 1.0)

	return result
}

// hasAllPorts checks if all required ports are in the set
func hasAllPorts(portSet map[int]bool, required []int) bool {
	for _, p := range required {
		if !portSet[p] {
			return false
		}
	}
	return true
}

// minFloat returns the minimum of two floats
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// GetPortIndicator returns the indicator for a specific port, if any
func GetPortIndicator(port int) (PortIndicator, bool) {
	for _, indicator := range portIndicators {
		if indicator.Port == port {
			return indicator, true
		}
	}
	return PortIndicator{}, false
}

// IsOSSpecificPort returns true if the port is a known OS-specific indicator
func IsOSSpecificPort(port int) bool {
	_, found := GetPortIndicator(port)
	return found
}
