package telnet

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
	"strings"
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
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("telnet: endpoint required")
	}
	return textproto.CollectBannerResult(ctx, in, c.timeout, id, textproto.ObsTelnet, "telnet", "", matchTelnet)
}
func matchTelnet(p textproto.BannerObservation) bool {
	if p.Banner == "" || strings.HasPrefix(p.Banner, "SSH-") || strings.HasPrefix(p.Banner, "HTTP/") {
		return false
	}
	if strings.Contains(p.Banner, "\xff") {
		return true
	}
	u := strings.ToLower(p.Banner)
	return strings.Contains(u, "login") || strings.Contains(u, "username") ||
		strings.Contains(u, "password") || strings.Contains(u, "telnet")
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
