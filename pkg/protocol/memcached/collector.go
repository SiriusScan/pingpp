package memcached

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

const id = "collect.memcached"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Version string `json:"version,omitempty"`
	Stats   bool   `json:"stats,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{11211}, Cost: 1, Priority: 45, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("memcached: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:memcached:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "memcached", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("memcached:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
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
	_, _ = conn.Write([]byte("version\r\n"))
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	payload := Observation{}
	if strings.HasPrefix(strings.ToUpper(line), "VERSION") {
		payload.Version = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "VERSION"))
		payload.Version = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(line)), "VERSION"))
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) > 1 {
			payload.Version = parts[1]
		}
		obs.Completeness = "full"
	} else {
		obs.Completeness = "none"
		obs.Error = "not memcached"
	}
	_ = obs.SetPayload(payload)
	return []model.ObservationRecord{obs}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
