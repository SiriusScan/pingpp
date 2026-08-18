// Package tcp provides TCP connect discovery/enumeration collectors.
package tcp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const (
	discoveryID   = "discovery.tcp"
	enumerationID = "enumerate.tcp"
)

// DefaultPorts used when config does not specify ports.
var DefaultPorts = []uint16{22, 80, 443, 135, 139, 445, 3389, 548}

// DiscoveryCollector checks whether any configured port responds (connect or RST).
type DiscoveryCollector struct {
	timeout time.Duration
	ports   []uint16
}

// EnumerateCollector probes every configured port and emits per-endpoint observations.
type EnumerateCollector struct {
	timeout time.Duration
	ports   []uint16
}

func portsFromConfig(cfg engine.Config) []uint16 {
	if len(cfg.Ports) > 0 {
		return append([]uint16(nil), cfg.Ports...)
	}
	return append([]uint16(nil), DefaultPorts...)
}

// NewDiscovery creates a TCP discovery collector.
func NewDiscovery(cfg engine.Config) (*DiscoveryCollector, error) {
	return &DiscoveryCollector{
		timeout: engine.EffectiveTimeout(cfg),
		ports:   portsFromConfig(cfg),
	}, nil
}

// NewEnumerate creates a TCP enumeration collector.
func NewEnumerate(cfg engine.Config) (*EnumerateCollector, error) {
	return &EnumerateCollector{
		timeout: engine.EffectiveTimeout(cfg),
		ports:   portsFromConfig(cfg),
	}, nil
}

// Metadata implements engine.Collector.
func (c *DiscoveryCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             discoveryID,
		Stage:          engine.StageDiscovery,
		Transports:     []model.Transport{model.TransportTCP},
		DefaultPorts:   append([]uint16(nil), DefaultPorts...),
		Cost:           2,
		Priority:       80,
		SideEffectRisk: "low",
		SafeForOT:      true,
	}
}

// Metadata implements engine.Collector.
func (c *EnumerateCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             enumerationID,
		Stage:          engine.StageEnumeration,
		Transports:     []model.Transport{model.TransportTCP},
		DefaultPorts:   append([]uint16(nil), DefaultPorts...),
		Cost:           5,
		Priority:       90,
		SideEffectRisk: "low",
		SafeForOT:      true,
	}
}

// Run implements engine.Collector for discovery: one summary observation.
func (c *DiscoveryCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	return runPorts(ctx, in, c.ports, c.timeout, discoveryID, false)
}

// Run implements engine.Collector for enumeration: per-port observations.
func (c *EnumerateCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	return runPorts(ctx, in, c.ports, c.timeout, enumerationID, true)
}

func runPorts(ctx context.Context, in engine.CollectorInput, ports []uint16, timeout time.Duration, probeID string, perPort bool) ([]model.ObservationRecord, error) {
	ip := in.PrimaryIP()
	if ip == "" {
		return nil, fmt.Errorf("tcp: no target IP")
	}
	if in.Timeout > 0 {
		timeout = in.Timeout
	}

	var observations []model.ObservationRecord
	var anyOpen, anyRST bool

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return observations, ctx.Err()
		default:
		}

		state, latency := dialPort(ip, port, timeout)
		if state == model.EndpointOpen {
			anyOpen = true
		}
		if state == model.EndpointClosed {
			anyRST = true
		}

		if !perPort {
			continue
		}

		ep := model.NewEndpoint(ip, port, model.TransportTCP, state)
		ref := ep.Ref()
		obs := model.ObservationRecord{
			ID:               fmt.Sprintf("obs:tcp:%s:%d:%d", ip, port, time.Now().UnixNano()),
			ProbeID:          probeID,
			ObservationType:  model.ObservationTCPEndpoint,
			Endpoint:         &ref,
			Timestamp:        time.Now().UTC(),
			CorrelationGroup: fmt.Sprintf("tcp:%s:%d", ip, port),
			Completeness:     "full",
		}
		if in.Asset != nil {
			obs.AssetID = in.Asset.ID
		}
		_ = obs.SetPayload(model.TCPEndpointObservation{
			State:   state,
			Latency: latency.String(),
		})
		observations = append(observations, obs)
	}

	if perPort {
		return observations, nil
	}

	// Discovery summary
	obs := model.ObservationRecord{
		ID:               fmt.Sprintf("obs:tcp-discovery:%s:%d", ip, time.Now().UnixNano()),
		ProbeID:          probeID,
		ObservationType:  model.ObservationTCPEndpoint,
		Timestamp:        time.Now().UTC(),
		CorrelationGroup: "tcp-discovery:" + ip,
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	state := model.EndpointFiltered
	switch {
	case anyOpen:
		state = model.EndpointOpen
		obs.Completeness = "full"
	case anyRST:
		state = model.EndpointClosed
		obs.Completeness = "partial"
	default:
		obs.Completeness = "none"
		obs.Error = "no tcp response"
	}
	_ = obs.SetPayload(model.TCPEndpointObservation{State: state})
	return []model.ObservationRecord{obs}, nil
}

func dialPort(ip string, port uint16, timeout time.Duration) (model.EndpointState, time.Duration) {
	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	latency := time.Since(start)
	if err == nil {
		_ = conn.Close()
		return model.EndpointOpen, latency
	}
	if strings.Contains(err.Error(), "refused") {
		return model.EndpointClosed, latency
	}
	return model.EndpointFiltered, latency
}

// Register adds TCP discovery and enumeration collectors.
func Register(r *engine.Registry) {
	r.MustRegister(discoveryID, func(cfg engine.Config) (engine.Collector, error) {
		return NewDiscovery(cfg)
	})
	r.MustRegister(enumerationID, func(cfg engine.Config) (engine.Collector, error) {
		return NewEnumerate(cfg)
	})
}
