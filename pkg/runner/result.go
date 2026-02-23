package runner

import (
	"encoding/json"
	"time"

	"github.com/SiriusScan/ping++/fingerprint"
	"github.com/SiriusScan/ping++/pkg/probes"
)

// Result contains the aggregated results for a single host.
// This is the primary output type from ping++ scans.
type Result struct {
	// IP is the target IP address
	IP string `json:"ip"`

	// Hostname is the resolved hostname (if DNS lookup enabled)
	Hostname string `json:"hostname,omitempty"`

	// IsAlive indicates whether the host responded to any probe
	IsAlive bool `json:"is_alive"`

	// OSFamily is the detected operating system family (linux, windows, macos, cisco, unknown)
	OSFamily string `json:"os_family"`

	// OSVersion provides the detected OS version (e.g., "Ubuntu 22.04", "Windows 11")
	OSVersion string `json:"os_version,omitempty"`

	// OSConfidence is the confidence level in OS detection (0.0-1.0)
	OSConfidence float64 `json:"os_confidence,omitempty"`

	// OSReason explains why this OS was detected
	OSReason string `json:"os_reason,omitempty"`

	// Evidence contains all fingerprint evidence collected
	Evidence []fingerprint.Evidence `json:"evidence,omitempty"`

	// TTL is the observed TTL value from successful probes
	TTL int `json:"ttl,omitempty"`

	// OriginalTTL is the calculated original TTL before network hops
	OriginalTTL int `json:"original_ttl,omitempty"`

	// Latency is the minimum observed latency across all probes
	Latency time.Duration `json:"latency,omitempty"`

	// DiscoverySources lists which probes detected the host as alive
	DiscoverySources []string `json:"discovery_sources,omitempty"`

	// OpenPorts lists all ports found open during scanning
	OpenPorts []int `json:"open_ports,omitempty"`

	// Probes contains the individual probe results
	Probes []probes.ProbeResult `json:"probes,omitempty"`

	// Service banners captured
	SSHBanner  string `json:"ssh_banner,omitempty"`
	HTTPServer string `json:"http_server,omitempty"`
	SMBDialect string `json:"smb_dialect,omitempty"`

	// Details contains additional metadata
	Details map[string]string `json:"details,omitempty"`

	// Timestamp is when the scan was completed
	Timestamp time.Time `json:"timestamp"`
}

// NewResult creates a new Result with initialized fields.
func NewResult(ip string) *Result {
	return &Result{
		IP:               ip,
		OSFamily:         "unknown",
		Details:          make(map[string]string),
		Probes:           make([]probes.ProbeResult, 0),
		DiscoverySources: make([]string, 0),
		OpenPorts:        make([]int, 0),
		Evidence:         make([]fingerprint.Evidence, 0),
		Timestamp:        time.Now(),
	}
}

// AddProbeResult adds a probe result and updates aggregated fields.
func (r *Result) AddProbeResult(pr probes.ProbeResult) {
	r.Probes = append(r.Probes, pr)

	if pr.Success {
		r.IsAlive = true

		// Track which probe detected the host
		if pr.Protocol != "" {
			r.DiscoverySources = appendUnique(r.DiscoverySources, pr.Protocol)
		}

		// Track open ports
		if pr.Port > 0 {
			r.OpenPorts = appendUniqueInt(r.OpenPorts, pr.Port)
		}

		// Update TTL if this probe has one and we don't have one yet,
		// or if this probe's TTL is more useful (non-zero)
		if pr.TTL > 0 && (r.TTL == 0 || pr.TTL < r.TTL) {
			r.TTL = pr.TTL
		}

		// Track minimum latency
		if pr.Latency > 0 && (r.Latency == 0 || pr.Latency < r.Latency) {
			r.Latency = pr.Latency
		}

		// Capture service banners
		if banner, ok := pr.Details["ssh_banner"]; ok && banner != "" {
			r.SSHBanner = banner
		}
		if server, ok := pr.Details["http_server"]; ok && server != "" {
			r.HTTPServer = server
		}
		if dialect, ok := pr.Details["smb_dialect"]; ok && dialect != "" {
			r.SMBDialect = dialect
		}

		// Merge details
		for k, v := range pr.Details {
			r.Details[k] = v
		}
	}
}

// appendUniqueInt appends an int to a slice only if it doesn't already exist.
func appendUniqueInt(slice []int, value int) []int {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// appendUnique appends a value to a slice only if it doesn't already exist.
func appendUnique(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// JSON returns the result as a JSON string.
func (r *Result) JSON() string {
	data, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// String returns a human-readable representation of the result.
func (r *Result) String() string {
	status := "down"
	if r.IsAlive {
		status = "up"
	}

	result := r.IP
	if r.Hostname != "" {
		result += " (" + r.Hostname + ")"
	}
	result += " [" + status + "]"

	if r.IsAlive {
		result += " OS:" + r.OSFamily
		if r.TTL > 0 {
			result += " TTL:" + string(rune(r.TTL+'0'))
		}
	}

	return result
}

// ToSiriusHost converts the Result to a format compatible with go-api sirius.Host.
// This enables integration with the Sirius scanning ecosystem.
func (r *Result) ToSiriusHost() map[string]interface{} {
	return map[string]interface{}{
		"ip":         r.IP,
		"hostname":   r.Hostname,
		"os":         r.OSFamily,
		"osVersion":  r.OSVersion,
		"confidence": r.OSConfidence,
	}
}
