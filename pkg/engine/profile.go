package engine

import "time"

// ProbeOutcome distinguishes collector results without collapsing everything
// into Success bool + Error string.
type ProbeOutcome string

const (
	OutcomeSuccess       ProbeOutcome = "success"
	OutcomeNoMatch       ProbeOutcome = "no_match"
	OutcomeRefused       ProbeOutcome = "refused"
	OutcomeTimeout       ProbeOutcome = "timeout"
	OutcomeFiltered      ProbeOutcome = "filtered"
	OutcomeProtocolError ProbeOutcome = "protocol_error"
	OutcomeInternalError ProbeOutcome = "internal_error"
)

// ProfileName selects planner/budget configuration.
type ProfileName string

const (
	ProfileQuick   ProfileName = "quick"
	ProfileDefault ProfileName = "default"
	ProfileDeep    ProfileName = "deep"
)

// Profile is planner/budget configuration — not a separate implementation.
type Profile struct {
	Name                ProfileName
	TCPPorts            []uint16
	UDPPorts            []uint16
	DiscoveryCollectors []string
	CollectCollectors   []string
	Budget              Budget
	SkipDiscovery       bool
}

// Budget limits scan effort.
type Budget struct {
	MaxConcurrentHosts     int
	MaxConcurrentPerHost   int
	MaxRequestsPerEndpoint int
	MaxProbesPerHost       int
	MaxArtifactBytes       int64
	MaxBytesPerHost        int64
	ProbeTimeout           time.Duration
	HTTPTimeout            time.Duration
	RatePerSecond          int
	ProbesUsed             int
	BytesUsed              int64
	MaxNetworkOps          int
	NetworkOps             int
	Connections            int
}

// DefaultBudget returns conservative starting defaults from the PRD.
func DefaultBudget() Budget {
	return Budget{
		MaxConcurrentHosts:     50,
		MaxConcurrentPerHost:   4,
		MaxRequestsPerEndpoint: 8,
		MaxProbesPerHost:       64,
		MaxArtifactBytes:       256 * 1024,
		MaxBytesPerHost:        2 * 1024 * 1024,
		ProbeTimeout:           3 * time.Second,
		HTTPTimeout:            5 * time.Second,
		RatePerSecond:          100,
		MaxNetworkOps:          1024,
	}
}

// QuickPorts is the small externally-facing set.
var QuickPorts = []uint16{22, 80, 443, 445, 3389}

// DefaultPorts is the curated Internet + enterprise set (PRD §18).
var DefaultPorts = []uint16{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143,
	389, 443, 445, 465, 515, 548, 554, 587, 631, 636, 873,
	902, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049,
	2375, 2376, 3000, 3128, 3268, 3269, 3306, 3389,
	5000, 5060, 5432, 5601, 5672, 5900, 5985, 5986,
	6379, 6443, 8000, 8008, 8080, 8081, 8088, 8181,
	8443, 8888, 9000, 9090, 9200, 9300, 9418, 10000,
	11211, 15672, 27017,
}

// DefaultUDPPorts is the narrow UDP set (PRD §19).
var DefaultUDPPorts = []uint16{53, 123, 161, 500, 1900, 4500, 5353}

// ProfileFor returns planner configuration for a named profile.
func ProfileFor(name ProfileName) Profile {
	b := DefaultBudget()
	switch name {
	case ProfileQuick:
		b.MaxProbesPerHost = 24
		return Profile{
			Name:                ProfileQuick,
			TCPPorts:            append([]uint16(nil), QuickPorts...),
			DiscoveryCollectors: []string{"discovery.icmp", "discovery.tcp"},
			CollectCollectors:   []string{"enumerate.tcp", "collect.tls", "collect.http", "collect.ssh", "collect.smb"},
			Budget:              b,
		}
	case ProfileDeep:
		b.MaxProbesPerHost = 256
		b.MaxRequestsPerEndpoint = 16
		return Profile{
			Name:                ProfileDeep,
			TCPPorts:            append([]uint16(nil), DefaultPorts...),
			UDPPorts:            append([]uint16(nil), DefaultUDPPorts...),
			DiscoveryCollectors: []string{"discovery.icmp", "discovery.tcp"},
			CollectCollectors:   []string{"enumerate.tcp", "enumerate.udp", "collect.tls", "collect.http", "collect.ssh", "collect.smb"},
			Budget:              b,
		}
	default:
		return Profile{
			Name:                ProfileDefault,
			TCPPorts:            append([]uint16(nil), DefaultPorts...),
			UDPPorts:            append([]uint16(nil), DefaultUDPPorts...),
			DiscoveryCollectors: []string{"discovery.icmp", "discovery.tcp"},
			CollectCollectors:   []string{"enumerate.tcp", "enumerate.udp", "collect.tls", "collect.http", "collect.ssh", "collect.smb"},
			Budget:              b,
		}
	}
}

// RemainingProbes reports whether the budget allows another collector run.
func (b *Budget) RemainingProbes() bool {
	if b.MaxProbesPerHost <= 0 {
		return true
	}
	return b.ProbesUsed < b.MaxProbesPerHost
}

// RemainingNetworkOps reports whether another dial/packet is allowed.
func (b *Budget) RemainingNetworkOps() bool {
	if b.MaxNetworkOps <= 0 {
		return true
	}
	return b.NetworkOps < b.MaxNetworkOps
}

// Remaining reports whether collector or network budget remains.
func (b *Budget) Remaining() bool {
	return b.RemainingProbes() && b.RemainingNetworkOps()
}

// ConsumeProbe increments the collector-run counter.
func (b *Budget) ConsumeProbe() {
	b.ProbesUsed++
}

// ConsumeNetwork adds dial/byte accounting from a collector result.
func (b *Budget) ConsumeNetwork(ops int, bytes int64) {
	if ops > 0 {
		b.NetworkOps += ops
		b.Connections += ops
	}
	if bytes > 0 {
		b.BytesUsed += bytes
	}
}
