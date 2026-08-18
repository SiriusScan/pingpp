// Package udp provides UDP enumeration collectors.
package udp

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

const enumerationID = "enumerate.udp"

// Collector probes configured UDP ports and emits per-endpoint observations.
type Collector struct {
	timeout     time.Duration
	ports       []uint16
	concurrency int
}

func portsFromConfig(cfg engine.Config) []uint16 {
	if len(cfg.UDPPorts) > 0 {
		return append([]uint16(nil), cfg.UDPPorts...)
	}
	return append([]uint16(nil), engine.DefaultUDPPorts...)
}

// NewEnumerate creates a UDP enumeration collector.
func NewEnumerate(cfg engine.Config) (*Collector, error) {
	conc := cfg.Concurrency
	if conc < 1 {
		conc = 8
	}
	return &Collector{
		timeout:     engine.EffectiveTimeout(cfg),
		ports:       portsFromConfig(cfg),
		concurrency: conc,
	}, nil
}

// Metadata implements engine.Collector.
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             enumerationID,
		Stage:          engine.StageEnumeration,
		Transports:     []model.Transport{model.TransportUDP},
		DefaultPorts:   append([]uint16(nil), engine.DefaultUDPPorts...),
		Cost:           5,
		Priority:       85,
		SideEffectRisk: "low",
		SafeForOT:      true,
	}
}

// Run implements engine.Collector.
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	ip := in.PrimaryIP()
	if ip == "" {
		return nil, fmt.Errorf("udp: no target IP")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	hits := probePorts(ctx, ip, c.ports, timeout, c.concurrency)
	var observations []model.ObservationRecord
	for _, hit := range hits {
		ep := model.NewEndpoint(ip, hit.port, model.TransportUDP, hit.state)
		ref := ep.Ref()
		obs := model.ObservationRecord{
			ID:               fmt.Sprintf("obs:udp:%s:%d:%d", ip, hit.port, time.Now().UnixNano()),
			ProbeID:          enumerationID,
			ObservationType:  model.ObservationUDPEndpoint,
			Endpoint:         &ref,
			Timestamp:        time.Now().UTC(),
			CorrelationGroup: fmt.Sprintf("udp:%s:%d", ip, hit.port),
			Completeness:     "full",
		}
		if in.Asset != nil {
			obs.AssetID = in.Asset.ID
		}
		_ = obs.SetPayload(model.UDPEndpointObservation{State: hit.state, Latency: hit.latency.String()})
		observations = append(observations, obs)
	}
	return observations, ctx.Err()
}

type portHit struct {
	port    uint16
	state   model.EndpointState
	latency time.Duration
}

func probePorts(ctx context.Context, ip string, ports []uint16, timeout time.Duration, concurrency int) []portHit {
	hits := make([]portHit, len(ports))
	if len(ports) == 0 {
		return hits
	}
	workers := concurrency
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
	conn, err := transport.DialUDP(ctx, ip, port, timeout)
	if err != nil {
		return classifyUDPErr(err), time.Since(start)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// A generic datagram can surface ICMP port-unreachable (closed).
	// Silence is unknown — protocol collectors decide responsiveness.
	_, _ = conn.Write([]byte{0})
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	latency := time.Since(start)
	if n > 0 {
		return model.EndpointResponsive, latency
	}
	return classifyUDPErr(err), latency
}

func classifyUDPErr(err error) model.EndpointState {
	if err == nil {
		return model.EndpointUnknown
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, transport.ErrBudgetExceeded) {
		return model.EndpointUnknown
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "refused") || strings.Contains(msg, "port unreachable") {
		return model.EndpointClosed
	}
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") {
		return model.EndpointUnknown
	}
	return model.EndpointUnknown
}

// Register adds the UDP enumeration collector.
func Register(r *engine.Registry) {
	r.MustRegister(enumerationID, func(cfg engine.Config) (engine.Collector, error) {
		return NewEnumerate(cfg)
	})
}
