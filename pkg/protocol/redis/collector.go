package redis

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.redis"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Pong    bool   `json:"pong,omitempty"`
	Info    string `json:"info,omitempty"`
	Version string `json:"version,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{6379}, Cost: 2, Priority: 55, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("redis: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:redis:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "redis", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("redis:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "redis", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	_, _ = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	payload := Observation{Pong: strings.Contains(line, "PONG")}
	_, _ = conn.Write([]byte("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"))
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	infoHdr, _ := br.ReadString('\n')
	if strings.HasPrefix(infoHdr, "$") {
		var n int
		if _, err := fmt.Sscanf(infoHdr, "$%d", &n); err != nil {
			n = 0
		}
		if n > 0 && n < 65536 {
			buf := make([]byte, n+2)
			_, _ = br.Read(buf)
			payload.Info = string(buf)
			for _, part := range strings.Split(payload.Info, "\n") {
				if strings.HasPrefix(part, "redis_version:") {
					payload.Version = strings.TrimSpace(strings.TrimPrefix(part, "redis_version:"))
				}
			}
		}
	}
	if payload.Pong {
		obs.Completeness = "full"
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "redis", Observations: []model.ObservationRecord{obs}}, nil
	}
	obs.Completeness = "none"
	obs.Error = "no redis pong"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "redis", Observations: []model.ObservationRecord{obs}}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
