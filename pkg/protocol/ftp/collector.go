package ftp

import (
	"context"
	"fmt"
	"time"

	"strings"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

const id = "collect.ftp"

type Collector struct{ timeout time.Duration }

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{21}, Cost: 2, Priority: 50, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("ftp: endpoint required")
	}
	return textproto.CollectBannerResult(ctx, in, c.timeout, id, textproto.ObsFTP, "ftp", "FEAT\r\n", matchFTP)
}
func matchFTP(p textproto.BannerObservation) bool {
	if !strings.HasPrefix(p.Banner, "220") {
		return false
	}
	u := strings.ToUpper(p.Banner)
	return !strings.Contains(u, "SMTP")
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
