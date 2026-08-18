// Package tcp provides TCP connect discovery/enumeration collectors.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const (
	discoveryID   = "discovery.tcp"
	enumerationID = "enumerate.tcp"
)

// DefaultPorts used when config does not specify ports.
var DefaultPorts = []uint16{22, 80, 443, 135, 139, 445, 3389, 548}

// DiscoveryCollector checks whether any configured port responds (connect or RST).
type DiscoveryCollector struct {
	timeout     time.Duration
	ports       []uint16
	concurrency int
}

// EnumerateCollector probes every configured port and emits per-endpoint observations.
type EnumerateCollector struct {
	timeout     time.Duration
	ports       []uint16
	concurrency int
}

func portsFromConfig(cfg engine.Config) []uint16 {
	if len(cfg.Ports) > 0 {
		return append([]uint16(nil), cfg.Ports...)
	}
	return append([]uint16(nil), DefaultPorts...)
}

func concurrencyFromConfig(cfg engine.Config) int {
	if cfg.Concurrency > 0 {
		return cfg.Concurrency
	}
	return 8
}

// NewDiscovery creates a TCP discovery collector.
func NewDiscovery(cfg engine.Config) (*DiscoveryCollector, error) {
	return &DiscoveryCollector{
		timeout:     engine.EffectiveTimeout(cfg),
		ports:       portsFromConfig(cfg),
		concurrency: concurrencyFromConfig(cfg),
	}, nil
}

// NewEnumerate creates a TCP enumeration collector.
func NewEnumerate(cfg engine.Config) (*EnumerateCollector, error) {
	return &EnumerateCollector{
		timeout:     engine.EffectiveTimeout(cfg),
		ports:       portsFromConfig(cfg),
		concurrency: concurrencyFromConfig(cfg),
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
	return runPorts(ctx, in, c.ports, c.timeout, c.concurrency, discoveryID, false)
}

// Run implements engine.Collector for enumeration: per-port observations.
func (c *EnumerateCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	return runPorts(ctx, in, c.ports, c.timeout, c.concurrency, enumerationID, true)
}

type portHit struct {
	port    uint16
	state   model.EndpointState
	latency time.Duration
}

func runPorts(ctx context.Context, in engine.CollectorInput, ports []uint16, timeout time.Duration, concurrency int, probeID string, perPort bool) ([]model.ObservationRecord, error) {
	ip := in.PrimaryIP()
	if ip == "" {
		return nil, fmt.Errorf("tcp: no target IP")
	}
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	hits := probePorts(ctx, ip, ports, timeout, concurrency)
	cancelled := ctx.Err()

	var observations []model.ObservationRecord
	var anyConnect, anyRST bool
	for _, hit := range hits {
		if hit.state == "" {
			continue
		}
		if hit.state == model.EndpointResponsive {
			anyConnect = true
		}
		if hit.state == model.EndpointClosed {
			anyRST = true
		}
		if !perPort {
			continue
		}
		ep := model.NewEndpoint(ip, hit.port, model.TransportTCP, hit.state)
		ref := ep.Ref()
		obs := model.ObservationRecord{
			ID:               fmt.Sprintf("obs:tcp:%s:%d:%d", ip, hit.port, time.Now().UnixNano()),
			ProbeID:          probeID,
			ObservationType:  model.ObservationTCPEndpoint,
			Endpoint:         &ref,
			Timestamp:        time.Now().UTC(),
			CorrelationGroup: fmt.Sprintf("tcp:%s:%d", ip, hit.port),
			Completeness:     "full",
		}
		if in.Asset != nil {
			obs.AssetID = in.Asset.ID
		}
		_ = obs.SetPayload(model.TCPEndpointObservation{
			State:   hit.state,
			Latency: hit.latency.String(),
		})
		observations = append(observations, obs)
	}

	if perPort {
		return observations, cancelled
	}

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
	case anyConnect:
		state = model.EndpointResponsive
		obs.Completeness = "full"
	case anyRST:
		state = model.EndpointClosed
		obs.Completeness = "partial"
	default:
		obs.Completeness = "none"
		obs.Error = "no tcp response"
	}
	_ = obs.SetPayload(model.TCPEndpointObservation{State: state})
	return []model.ObservationRecord{obs}, cancelled
}

func probePorts(ctx context.Context, ip string, ports []uint16, timeout time.Duration, concurrency int) []portHit {
	hits := make([]portHit, len(ports))
	if len(ports) == 0 {
		return hits
	}
	workers := concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(ports) {
		workers = len(ports)
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					hits[idx] = portHit{port: ports[idx], state: model.EndpointUnknown}
					continue
				}
				state, latency := dialPort(ctx, ip, ports[idx], timeout)
				hits[idx] = portHit{port: ports[idx], state: state, latency: latency}
			}
		}()
	}

	for i := range ports {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return hits
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return hits
}

func dialPort(ctx context.Context, ip string, port uint16, timeout time.Duration) (model.EndpointState, time.Duration) {
	start := time.Now()
	conn, err := transport.DialTCP(ctx, ip, port, timeout)
	latency := time.Since(start)
	if err == nil {
		_ = conn.Close()
		// Connect is not service identity — only "something accepted the SYN".
		return model.EndpointResponsive, latency
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, transport.ErrBudgetExceeded) {
		return model.EndpointUnknown, latency
	}
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
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
