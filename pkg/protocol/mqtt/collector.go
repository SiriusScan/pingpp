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
	if in.Endpoint == nil {
		return nil, fmt.Errorf("mqtt: endpoint required")
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
		return []model.ObservationRecord{obs}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	// MQTT CONNECT (v3.1.1) with clientID=pingpp
	connect := []byte{
		0x10, 0x12, // CONNECT, remaining length
		0x00, 0x04, 'M', 'Q', 'T', 'T', // protocol name
		0x04,       // protocol level 4
		0x02,       // flags: clean session
		0x00, 0x3c, // keepalive 60
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
