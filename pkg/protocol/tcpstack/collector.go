// Package tcpstack collects lightweight TCP SYN-ACK stack features as observations.
// Features are never turned into OS labels inside this collector.
package tcpstack

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const id = "collect.tcpstack"

type Collector struct{ timeout time.Duration }

// Observation holds reusable TCP/IP stack features.
type Observation struct {
	RemoteAddr string `json:"remote_addr,omitempty"`
	LocalAddr  string `json:"local_addr,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Connected  bool   `json:"connected"`
	// Note: true remote TTL/MSS/option-order require raw sockets / pcap.
	// This lite collector records connect-level features only; richer
	// fields are reserved for platform-supported capture later.
	PlatformLimited bool `json:"platform_limited"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, Cost: 1, Priority: 30, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("tcpstack: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:tcpstack:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "tcp.stack", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("tcpstack:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	start := time.Now()
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(in.Endpoint.Address, fmt.Sprintf("%d", in.Endpoint.Port)))
	payload := Observation{PlatformLimited: true}
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
	} else {
		payload.Connected = true
		payload.LatencyMS = time.Since(start).Milliseconds()
		payload.RemoteAddr = conn.RemoteAddr().String()
		payload.LocalAddr = conn.LocalAddr().String()
		_ = conn.Close()
		obs.Completeness = "partial"
	}
	_ = obs.SetPayload(payload)
	return []model.ObservationRecord{obs}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
