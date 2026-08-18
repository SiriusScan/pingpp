package mqtt

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.mqtt"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Connack    bool `json:"connack"`
	ReturnCode int  `json:"return_code,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{1883}, Cost: 2, Priority: 45, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("mqtt: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:mqtt:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "mqtt", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("mqtt:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "mqtt", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	connect := []byte{
		0x10, 0x12,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,
		0x02,
		0x00, 0x3c,
		0x00, 0x06, 'p', 'i', 'n', 'g', 'p', 'p',
	}
	_, _ = conn.Write(connect)
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	payload := Observation{}
	if err == nil && n >= 4 && buf[0] == 0x20 {
		payload.Connack = true
		payload.ReturnCode = int(buf[3])
		obs.Completeness = "full"
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "mqtt", Observations: []model.ObservationRecord{obs}}, nil
	}
	obs.Completeness = "none"
	if err != nil {
		obs.Error = err.Error()
	} else {
		obs.Error = "not mqtt connack"
	}
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mqtt", Observations: []model.ObservationRecord{obs}}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
