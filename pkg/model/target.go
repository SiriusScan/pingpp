package model

// Target is a resolved scan input prior to asset creation.
type Target struct {
	// Input is the original user-supplied string (IP, CIDR member, or hostname).
	Input string `json:"input"`

	// Hostname is set when Input was a hostname (preserved for HTTP Host / TLS SNI).
	Hostname string `json:"hostname,omitempty"`

	// Addresses are the resolved IPs for this input.
	Addresses []Address `json:"addresses,omitempty"`
}

// NewTargetIP creates a target from a literal IP.
func NewTargetIP(ip string) Target {
	return Target{
		Input:     ip,
		Addresses: []Address{NewAddress(ip)},
	}
}

// NewTargetHostname creates a target that retains hostname context for SNI/Host.
func NewTargetHostname(hostname string, ips ...string) Target {
	addrs := make([]Address, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, NewAddress(ip))
	}
	return Target{
		Input:     hostname,
		Hostname:  hostname,
		Addresses: addrs,
	}
}
