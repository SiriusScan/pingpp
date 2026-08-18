package rdp

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.rdp"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Negotiated bool   `json:"negotiated"`
	Protocol   string `json:"protocol,omitempty"`
	RawHint    string `json:"raw_hint,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{3389}, Cost: 2, Priority: 60, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("rdp: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:rdp:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "rdp", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("rdp:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
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
	// TPKT + X.224 Connection Request with RDP Negotiation Request
	pkt := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
		0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // RDP_NEG_REQ (PROTOCOL_RDP)
	}
	_, _ = conn.Write(pkt)
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	payload := Observation{}
	if err == nil && n >= 11 && buf[0] == 0x03 {
		payload.Negotiated = true
		payload.Protocol = "rdp"
		payload.RawHint = fmt.Sprintf("len=%d", n)
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
