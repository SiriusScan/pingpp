package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const id = "collect.dns"

// Collector identifies DNS by speaking DNS to the endpoint (not the OS resolver).
type Collector struct{ timeout time.Duration }

// Observation is the typed DNS payload.
type Observation struct {
	Responded     bool     `json:"responded"`
	Rcode         string   `json:"rcode,omitempty"`
	Answers       []string `json:"answers,omitempty"`
	Authoritative bool     `json:"authoritative,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"`
	QueryName     string   `json:"query_name,omitempty"`
	QueryType     string   `json:"query_type,omitempty"`
	Server        string   `json:"server,omitempty"`
	Transport     string   `json:"transport,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}

func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID: id, Stage: engine.StageCollect,
		Transports:   []model.Transport{model.TransportUDP, model.TransportTCP},
		DefaultPorts: []uint16{53},
		Cost:         2, Priority: 60,
		SideEffectRisk: "low", SafeForOT: true,
	}
}

func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}

func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("dns: endpoint required")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	netw := "udp"
	if in.Endpoint.Transport == model.TransportTCP {
		netw = "tcp"
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID: fmt.Sprintf("obs:dns:%d", time.Now().UnixNano()), ProbeID: id,
		ObservationType: "dns", Endpoint: &ref, Timestamp: time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("dns:%s:%d", in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}

	payload := Observation{
		Server:    in.Endpoint.Address,
		Transport: netw,
		QueryName: ".",
		QueryType: "NS",
	}
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)
	msg.RecursionDesired = true

	client := &dns.Client{Net: netw, Timeout: timeout}
	addr := net.JoinHostPort(in.Endpoint.Address, fmt.Sprintf("%d", in.Endpoint.Port))
	resp, _, err := client.ExchangeContext(ctx, msg, addr)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		out := engine.OutcomeFromError(err)
		if out == engine.OutcomeInternalError {
			out = engine.OutcomeNoMatch
		}
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: out, Protocol: "dns", Observations: []model.ObservationRecord{obs}}, nil
	}
	if resp == nil || !resp.Response {
		obs.Completeness = "none"
		obs.Error = "not a dns response"
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "dns", Observations: []model.ObservationRecord{obs}}, nil
	}
	payload.Responded = true
	payload.Rcode = dns.RcodeToString[resp.Rcode]
	payload.Authoritative = resp.Authoritative
	payload.Truncated = resp.Truncated
	for _, rr := range resp.Answer {
		payload.Answers = append(payload.Answers, rr.String())
	}
	for _, rr := range resp.Ns {
		payload.Answers = append(payload.Answers, rr.String())
	}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{
		Outcome:      engine.OutcomeSuccess,
		Protocol:     "dns",
		Observations: []model.ObservationRecord{obs},
	}, nil
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
