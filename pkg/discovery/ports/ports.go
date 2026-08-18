// Package ports holds curated port prior lists used by enumeration profiles.
// Ports are places to look first — never protocol identity.
package ports

import "github.com/SiriusScan/ping++/pkg/engine"

// TCPDefault is the curated Internet + enterprise TCP prior list.
func TCPDefault() []uint16 {
	return append([]uint16(nil), engine.DefaultPorts...)
}

// TCPQuick is the small externally-facing prior list.
func TCPQuick() []uint16 {
	return append([]uint16(nil), engine.QuickPorts...)
}

// UDPDefault is the narrow UDP prior list.
func UDPDefault() []uint16 {
	return append([]uint16(nil), engine.DefaultUDPPorts...)
}
