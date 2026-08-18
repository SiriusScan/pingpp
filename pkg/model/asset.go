// Package model defines the canonical ping++ domain types.
//
// Collectors produce Observations. Fingerprint rules produce Claims.
// Assets aggregate endpoints, observations, and claims.
// Protocol-specific fields must never be added to Asset; they belong in
// typed observation payloads referenced by ObservationRecord.Payload.
package model

import "fmt"

// Address represents a network address owned by an asset.
type Address struct {
	// IP is the textual IP address (IPv4 or IPv6).
	IP string `json:"ip"`

	// Version is 4 or 6.
	Version int `json:"version"`

	// MAC is an optional link-layer address when known.
	MAC string `json:"mac,omitempty"`
}

// NewAddress parses a textual IP into an Address with version set.
// It does not validate aggressively; Version is 4, 6, or 0 if unknown.
func NewAddress(ip string) Address {
	a := Address{IP: ip}
	if stringsContainsColon(ip) {
		a.Version = 6
	} else if ip != "" {
		a.Version = 4
	}
	return a
}

func stringsContainsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

// Asset is the top-level identity unit for a scanned host/device.
// For this phase, one scanned IP typically maps to one Asset.
type Asset struct {
	ID           string              `json:"id"`
	Addresses    []Address           `json:"addresses,omitempty"`
	Hostnames    []string            `json:"hostnames,omitempty"`
	Endpoints    []Endpoint          `json:"endpoints,omitempty"`
	Claims       []Claim             `json:"claims,omitempty"`
	Observations []ObservationRecord `json:"observations,omitempty"`
}

// NewAssetFromIP creates an asset for a single IP (1 IP ≈ 1 asset).
func NewAssetFromIP(ip string) *Asset {
	return &Asset{
		ID:        "asset:" + ip,
		Addresses: []Address{NewAddress(ip)},
	}
}

// AddEndpoint appends an endpoint if not already present (same addr/port/transport).
func (a *Asset) AddEndpoint(ep Endpoint) {
	for i := range a.Endpoints {
		if a.Endpoints[i].Equal(ep) {
			if a.Endpoints[i].State == EndpointOpen && ep.State == EndpointResponsive {
				mergeEndpointExecution(&a.Endpoints[i], ep.Execution)
				return
			}
			a.Endpoints[i].State = ep.State
			mergeEndpointExecution(&a.Endpoints[i], ep.Execution)
			return
		}
	}
	a.Endpoints = append(a.Endpoints, ep)
}

func mergeEndpointExecution(dst *Endpoint, incoming EndpointExecution) {
	if dst == nil || incoming == "" {
		return
	}
	switch dst.Execution {
	case ExecutionAttempted, ExecutionTimedOut:
		if incoming == ExecutionTimedOut {
			dst.Execution = incoming
		}
		return
	default:
		dst.Execution = incoming
	}
}

// AddObservation appends an observation record.
func (a *Asset) AddObservation(obs ObservationRecord) {
	a.Observations = append(a.Observations, obs)
}

// AddClaim appends a claim.
func (a *Asset) AddClaim(c Claim) {
	a.Claims = append(a.Claims, c)
}

// EndpointKey returns a stable key for an endpoint.
func EndpointKey(address string, port uint16, transport Transport) string {
	return fmt.Sprintf("%s/%s/%d", address, transport, port)
}
