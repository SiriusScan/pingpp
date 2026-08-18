package ldap

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.ldap"

type Collector struct{ timeout time.Duration }

// Observation holds decoded RootDSE fields. Protocol-specific data stays here.
type Observation struct {
	Responded               bool     `json:"responded"`
	LDAPS                   bool     `json:"ldaps,omitempty"`
	VendorName              string   `json:"vendor_name,omitempty"`
	VendorVersion           string   `json:"vendor_version,omitempty"`
	NamingContexts          []string `json:"naming_contexts,omitempty"`
	DefaultNamingContext    string   `json:"default_naming_context,omitempty"`
	RootDomainNamingContext string   `json:"root_domain_naming_context,omitempty"`
	DNSHostName             string   `json:"dns_host_name,omitempty"`
	SupportedCapabilities   []string `json:"supported_capabilities,omitempty"`
	SupportedLDAPVersion    []string `json:"supported_ldap_version,omitempty"`
	SupportedSASLMechanisms []string `json:"supported_sasl_mechanisms,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}

func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID: id, Stage: engine.StageCollect,
		Transports:   []model.Transport{model.TransportTCP},
		DefaultPorts: []uint16{389, 636},
		Cost:         2, Priority: 55,
		SideEffectRisk: "low", SafeForOT: true,
	}
}

func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}

func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("ldap: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID: fmt.Sprintf("obs:ldap:%d", time.Now().UnixNano()), ProbeID: id,
		ObservationType: "ldap", Endpoint: &ref, Timestamp: time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("ldap:%s:%d", in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	useTLS := in.Endpoint.Port == 636 || (in.Extra != nil && in.Extra["tls"] == "1")
	if !useTLS && in.State != nil {
		useTLS = in.State.HasProtocol(in.Endpoint.Key(), "tls")
	}
	serverName := in.Endpoint.Address
	if in.Target != nil && in.Target.Hostname != "" {
		serverName = in.Target.Hostname
	}
	var conn io.ReadWriteCloser
	var err error
	if useTLS {
		conn, err = transport.DialTLS(ctx, in.Endpoint.Address, in.Endpoint.Port, serverName, c.timeout)
	} else {
		conn, err = transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	}
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dl.SetDeadline(time.Now().Add(c.timeout))
	}
	if _, err := conn.Write(encodeRootDSESearch()); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
	}
	msg, err := readBER(conn, 64*1024)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
	}
	payload, ok := decodeRootDSE(msg)
	if !ok {
		obs.Error = "not ldap search result"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
	}
	payload.LDAPS = useTLS
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "ldap", Observations: []model.ObservationRecord{obs}}, nil
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
