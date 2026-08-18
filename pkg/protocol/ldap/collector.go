package ldap

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.ldap"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Responded bool   `json:"responded"`
	RawHint   string `json:"raw_hint,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{389, 636}, Cost: 2, Priority: 55, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("ldap: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:ldap:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "ldap", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("ldap:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
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
	// LDAP anonymous bind request (messageID=1)
	bind := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	_, _ = conn.Write(bind)
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	payload := Observation{}
	if err == nil && n > 0 && buf[0] == 0x30 {
		payload.Responded = true
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
