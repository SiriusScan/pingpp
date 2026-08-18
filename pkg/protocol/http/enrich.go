package httpcol

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const enrichID = "collect.http.enrich"

// EnrichCollector fetches a small number of extra same-host URLs.
type EnrichCollector struct {
	timeout time.Duration
}

func NewEnrich(cfg engine.Config) (*EnrichCollector, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return &EnrichCollector{timeout: c.timeout}, nil
}

func (c *EnrichCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             enrichID,
		Stage:          engine.StageEnrich,
		Transports:     []model.Transport{model.TransportTCP},
		Cost:           3,
		Priority:       15,
		SideEffectRisk: "low",
		SafeForOT:      true,
	}
}

func (c *EnrichCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}

func (c *EnrichCollector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("http enrich: endpoint required")
	}
	paths := []string{"/favicon.ico", "/robots.txt"}
	if in.Extra != nil {
		if extra := in.Extra["urls"]; extra != "" {
			paths = strings.Split(extra, ",")
		} else if extra := in.Extra["paths"]; extra != "" {
			paths = strings.Split(extra, ",")
		}
	}
	if len(paths) > 3 {
		paths = paths[:3]
	}
	var out []model.ObservationRecord
	var bytes int64
	base := in.Extra
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		sub := in
		sub.Extra = map[string]string{}
		for k, v := range base {
			sub.Extra[k] = v
		}
		sub.Extra["path"] = path
		inner := &Collector{timeout: c.timeout}
		res, err := inner.RunResult(ctx, sub)
		if err != nil {
			continue
		}
		out = append(out, res.Observations...)
		bytes += res.BytesRead
	}
	if len(out) == 0 {
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "http"}, nil
	}
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "http", Observations: out, BytesRead: bytes}, nil
}
