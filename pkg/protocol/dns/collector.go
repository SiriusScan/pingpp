package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const id = "collect.dns"

type Collector struct{ timeout time.Duration }
type Observation struct {
	Responded bool     `json:"responded"`
	Answers   []string `json:"answers,omitempty"`
	Server    string   `json:"server,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportUDP, model.TransportTCP}, DefaultPorts: []uint16{53}, Cost: 2, Priority: 60, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("dns: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:dns:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "dns", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("dns:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: c.timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(in.Endpoint.Address, fmt.Sprintf("%d", in.Endpoint.Port)))
		},
	}
	ctx2, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx2, "example.com")
	payload := Observation{Server: in.Endpoint.Address}
	if err == nil {
		payload.Responded = true
		payload.Answers = addrs
		obs.Completeness = "full"
	} else {
		obs.Error = err.Error()
		obs.Completeness = "none"
	}
	_ = obs.SetPayload(payload)
	return []model.ObservationRecord{obs}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
