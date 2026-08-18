package telnet

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

const id = "collect.telnet"

type Collector struct{ timeout time.Duration }

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{23}, Cost: 2, Priority: 40, SideEffectRisk: "medium", SafeForOT: false}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("telnet: endpoint required")
	}
	obs, err := textproto.CollectBanner(ctx, in, c.timeout, id, textproto.ObsTelnet, "")
	return []model.ObservationRecord{obs}, err
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
