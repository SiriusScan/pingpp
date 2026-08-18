package smtp

import (
	"context"
	"fmt"
	"time"

	"strings"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

const id = "collect.smtp"

type Collector struct{ timeout time.Duration }

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{25, 465, 587}, Cost: 2, Priority: 50, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("smtp: endpoint required")
	}
	return textproto.CollectSession(ctx, in, c.timeout, textproto.SessionConfig{
		ProbeID:  id,
		ObsType:  textproto.ObsSMTP,
		Protocol: "smtp",
		Hello:    "EHLO pingpp.local\r\n",
		Match:    matchSMTP,
		StartTLS: "STARTTLS\r\n",
		StartTLSOK: func(reply string) bool {
			return textproto.HasCode(reply, "220")
		},
		WantStartTLS: smtpAdvertisesStartTLS,
		PostTLSHello: "EHLO pingpp.local\r\n",
	})
}
func matchSMTP(p textproto.BannerObservation) bool {
	if !strings.HasPrefix(p.Banner, "220") {
		return false
	}
	if strings.Contains(strings.ToUpper(p.Banner), "FTP") {
		return false
	}
	return textproto.HasCode(p.Reply, "250")
}

func smtpAdvertisesStartTLS(p textproto.BannerObservation) bool {
	for _, f := range p.Features {
		if strings.EqualFold(f, "STARTTLS") {
			return true
		}
	}
	return false
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
