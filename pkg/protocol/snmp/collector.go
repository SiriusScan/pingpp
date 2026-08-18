package snmp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.snmp"

// Collector performs an unauthenticated SNMPv2c GET of system OIDs.
type Collector struct {
	timeout   time.Duration
	community string
}

// Observation holds sys* fields. Community is never serialized.
type Observation struct {
	SysDescr         string `json:"sys_descr,omitempty"`
	SysObjectID      string `json:"sys_object_id,omitempty"`
	SysName          string `json:"sys_name,omitempty"`
	EntPhysicalDescr string `json:"ent_physical_descr,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	community := "public"
	if cfg.Extra != nil && cfg.Extra["community"] != "" {
		community = cfg.Extra["community"]
	}
	return &Collector{timeout: engine.EffectiveTimeout(cfg), community: community}, nil
}

func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID: id, Stage: engine.StageCollect,
		Transports:   []model.Transport{model.TransportUDP},
		DefaultPorts: []uint16{161},
		Cost:         3, Priority: 65,
		SideEffectRisk: "low", SafeForOT: true,
	}
}

func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}

func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("snmp: endpoint required")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID: fmt.Sprintf("obs:snmp:%d", time.Now().UnixNano()), ProbeID: id,
		ObservationType: "snmp", Endpoint: &ref, Timestamp: time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("snmp:%s:%d", in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}

	if err := transport.CountDial(ctx); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{
			Outcome:      engine.OutcomeFromError(err),
			Protocol:     "snmp",
			Observations: []model.ObservationRecord{obs},
		}, nil
	}
	g := &gosnmp.GoSNMP{
		Target:    in.Endpoint.Address,
		Port:      in.Endpoint.Port,
		Community: c.community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   0,
		MaxOids:   8,
		Context:   ctx,
	}
	if err := g.Connect(); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{
			Outcome:      engine.OutcomeFromError(err),
			Protocol:     "snmp",
			Observations: []model.ObservationRecord{obs},
		}, nil
	}
	g.Conn = transport.WrapConn(ctx, g.Conn)
	defer func() { _ = g.Conn.Close() }()

	oids := []string{
		"1.3.6.1.2.1.1.1.0",          // sysDescr
		"1.3.6.1.2.1.1.2.0",          // sysObjectID
		"1.3.6.1.2.1.1.5.0",          // sysName
		"1.3.6.1.2.1.47.1.1.1.1.2.1", // entPhysicalDescr.1
	}
	pkt, err := g.Get(oids)
	payload := Observation{}
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		out := engine.OutcomeFromError(err)
		if out == engine.OutcomeInternalError {
			out = engine.OutcomeNoMatch
		}
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: out, Protocol: "snmp", Observations: []model.ObservationRecord{obs}}, nil
	}
	for _, pdu := range pkt.Variables {
		val := pduString(pdu)
		switch {
		case strings.HasPrefix(pdu.Name, ".1.3.6.1.2.1.1.1.0") || pdu.Name == "1.3.6.1.2.1.1.1.0":
			payload.SysDescr = val
		case strings.HasPrefix(pdu.Name, ".1.3.6.1.2.1.1.2.0") || pdu.Name == "1.3.6.1.2.1.1.2.0":
			payload.SysObjectID = val
		case strings.HasPrefix(pdu.Name, ".1.3.6.1.2.1.1.5.0") || pdu.Name == "1.3.6.1.2.1.1.5.0":
			payload.SysName = val
		case strings.Contains(pdu.Name, "1.3.6.1.2.1.47.1.1.1.1.2"):
			payload.EntPhysicalDescr = val
		}
	}
	_ = obs.SetPayload(payload)
	if payload.SysDescr == "" && payload.SysObjectID == "" && payload.SysName == "" {
		obs.Completeness = "none"
		obs.Error = "no system oids"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "snmp", Observations: []model.ObservationRecord{obs}}, nil
	}
	obs.Completeness = "full"
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "snmp", Observations: []model.ObservationRecord{obs}}, nil
}

func pduString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case nil:
		return ""
	default:
		s := fmt.Sprint(v)
		if s == "<nil>" {
			return ""
		}
		return s
	}
}

// MarshalJSONForTest asserts community is not present in serialized observations.
func CommunityAbsent(payload []byte) bool {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return false
	}
	_, ok := raw["community"]
	return !ok
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
