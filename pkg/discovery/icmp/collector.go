// Package icmp provides an ICMP echo discovery collector.
package icmp

import (
	"context"
	"fmt"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const collectorID = "discovery.icmp"

// Collector performs ICMP echo and emits icmp.echo observations.
type Collector struct {
	timeout time.Duration
	retries int
}

// New creates an ICMP discovery collector.
func New(cfg engine.Config) (*Collector, error) {
	return &Collector{
		timeout: engine.EffectiveTimeout(cfg),
		retries: 1,
	}, nil
}

// Metadata implements engine.Collector.
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             collectorID,
		Stage:          engine.StageDiscovery,
		Cost:           1,
		Priority:       100,
		SideEffectRisk: "none",
		SafeForOT:      true,
	}
}

// Run implements engine.Collector.
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	ip := in.PrimaryIP()
	if ip == "" {
		return nil, fmt.Errorf("icmp: no target IP")
	}

	pinger, err := probing.NewPinger(ip)
	if err != nil {
		return nil, err
	}
	pinger.Count = 1
	pinger.Timeout = c.timeout
	if in.Timeout > 0 {
		pinger.Timeout = in.Timeout
	}
	pinger.SetPrivileged(true)
	if err := transport.CountDial(ctx); err != nil {
		return nil, err
	}

	var ttl int
	var latency time.Duration
	pinger.OnRecv = func(pkt *probing.Packet) {
		ttl = pkt.TTL
		latency = pkt.Rtt
	}

	err = pinger.Run()
	if err != nil {
		pinger.SetPrivileged(false)
		err = pinger.Run()
	}

	stats := pinger.Statistics()
	obs := model.ObservationRecord{
		ID:              fmt.Sprintf("obs:icmp:%s:%d", ip, time.Now().UnixNano()),
		ProbeID:         collectorID,
		ObservationType: model.ObservationICMPEcho,
		Timestamp:       time.Now().UTC(),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}

	if stats.PacketsRecv == 0 {
		obs.Error = "no response"
		if err != nil {
			obs.Error = err.Error()
		}
		obs.Completeness = "none"
		return []model.ObservationRecord{obs}, nil
	}

	payload := model.ICMPObservation{
		TTL:     ttl,
		Latency: latency.String(),
	}
	if err := obs.SetPayload(payload); err != nil {
		return nil, err
	}
	obs.Completeness = "full"
	obs.CorrelationGroup = "icmp:" + ip
	return []model.ObservationRecord{obs}, nil
}

// Register adds the ICMP collector to the registry.
func Register(r *engine.Registry) {
	r.MustRegister(collectorID, func(cfg engine.Config) (engine.Collector, error) {
		return New(cfg)
	})
}
