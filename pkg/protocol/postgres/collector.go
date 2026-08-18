package postgres

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.postgres"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Recognized bool   `json:"recognized"`
	SSLAllowed bool   `json:"ssl_allowed,omitempty"`
	AuthType   string `json:"auth_type,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{5432}, Cost: 2, Priority: 55, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("postgres: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:pg:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "postgres", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("postgres:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "postgres", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	pkt := make([]byte, 8)
	binary.BigEndian.PutUint32(pkt[0:4], 8)
	binary.BigEndian.PutUint32(pkt[4:8], 80877103)
	_, _ = conn.Write(pkt)
	resp := make([]byte, 1)
	n, err := io.ReadFull(conn, resp)
	payload := Observation{}
	if err == nil && n == 1 && (resp[0] == 'S' || resp[0] == 'N') {
		payload.Recognized = true
		payload.SSLAllowed = resp[0] == 'S'
		obs.Completeness = "full"
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "postgres", Observations: []model.ObservationRecord{obs}}, nil
	}
	obs.Completeness = "none"
	obs.Error = "not postgres ssl response"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "postgres", Observations: []model.ObservationRecord{obs}}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
