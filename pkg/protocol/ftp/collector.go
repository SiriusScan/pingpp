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
	if strings.Contains(u, "SMTP") || strings.Contains(u, "ESMTP") {
		return false
	}
	if textproto.HasCode(p.Reply, "250") && !textproto.HasCode(p.Reply, "211") {
		return false
	}
	if textproto.HasCode(p.Reply, "211") {
		return true
	}
	// FEAT unimplemented is still FTP when the reply is a 5xx without SMTP enhanced status.
	return ftpError(p.Reply)
}

func ftpError(reply string) bool {
	if reply == "" {
		return false
	}
	if !textproto.HasCode(reply, "500") && !textproto.HasCode(reply, "502") && !textproto.HasCode(reply, "551") {
		return false
	}
	if strings.Contains(reply, ".") {
		for _, f := range strings.Fields(reply) {
			if len(f) >= 5 && f[1] == '.' && f[3] == '.' {
				return false
			}
		}
	}
	return true
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
