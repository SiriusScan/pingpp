package ldap

import (
	"context"
	"fmt"
	"io"
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
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("ldap: endpoint required")
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
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	// LDAP SearchRequest for RootDSE: base="", scope=base, filter=present(objectClass).
	search := []byte{
		0x30, 0x25,
		0x02, 0x01, 0x01,
		0x63, 0x20,
		0x04, 0x00,
		0x0a, 0x01, 0x00,
		0x0a, 0x01, 0x00,
		0x02, 0x01, 0x00,
		0x02, 0x01, 0x00,
		0x01, 0x01, 0x00,
		0x87, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
		0x30, 0x00,
	}
	_, _ = conn.Write(search)
	buf := make([]byte, 512)
	n, err := io.ReadFull(conn, buf[:2])
	if err != nil && n < 1 {
		obs.Completeness = "none"
		if err != nil {
			obs.Error = err.Error()
		}
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
	}
	if buf[0] != 0x30 {
		obs.Error = "not ldap ber"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
	}
	rest := int(buf[1])
	if rest > 0 && rest < 400 {
		more := make([]byte, rest)
		_, _ = io.ReadFull(conn, more)
		n += len(more)
	}
	payload := Observation{Responded: true, RawHint: fmt.Sprintf("len=%d", n)}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
