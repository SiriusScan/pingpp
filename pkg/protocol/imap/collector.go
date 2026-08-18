package imap

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
	"strings"
)

const id = "collect.imap"

type Collector struct{ timeout time.Duration }

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{143, 993}, Cost: 2, Priority: 45, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("imap: endpoint required")
	}
	return textproto.CollectSession(ctx, in, c.timeout, textproto.SessionConfig{
		ProbeID:  id,
		ObsType:  textproto.ObsIMAP,
		Protocol: "imap",
		Match: func(p textproto.BannerObservation) bool {
			return strings.Contains(p.Banner, "OK") && (strings.HasPrefix(p.Banner, "*") || strings.Contains(strings.ToUpper(p.Banner), "IMAP"))
		},
		StartTLS: "A001 STARTTLS\r\n",
		StartTLSOK: func(reply string) bool {
			for _, line := range strings.Split(reply, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && f[0] == "A001" && strings.EqualFold(f[1], "OK") {
					return true
				}
			}
			return false
		},
		PostTLSHello: "A002 CAPABILITY\r\n",
		Tagged:       true,
	})
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
