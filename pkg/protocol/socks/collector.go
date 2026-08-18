package socks

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.socks"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Version5 bool `json:"version5"`
	Method   int  `json:"method,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{1080}, Cost: 1, Priority: 40, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("socks: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:socks:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "socks", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("socks:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return []model.ObservationRecord{obs}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // VER=5, NMETHODS=1, NO AUTH
	buf := make([]byte, 2)
	n, err := conn.Read(buf)
	payload := Observation{}
	if err == nil && n == 2 && buf[0] == 0x05 {
		payload.Version5 = true
		payload.Method = int(buf[1])
		obs.Completeness = "full"
	} else {
		obs.Completeness = "none"
		if err != nil {
			obs.Error = err.Error()
		}
	}
	_ = obs.SetPayload(payload)
	return []model.ObservationRecord{obs}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
