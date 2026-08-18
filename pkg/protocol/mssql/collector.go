package mssql

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.mssql"

const (
	tdsPrelogin  byte = 0x12
	tdsResponse  byte = 0x04
	tokenVersion byte = 0x00
	tokenTerm    byte = 0xff
)

type Collector struct{ timeout time.Duration }

type Observation struct {
	Prelogin bool   `json:"prelogin"`
	Version  string `json:"version,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{1433}, Cost: 2, Priority: 50, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("mssql: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:mssql:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "mssql", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("mssql:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := conn.Write(preloginRequest()); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
	}
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
	}
	if hdr[0] != tdsResponse {
		obs.Error = "not tds response"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < 8 || total > 16*1024 {
		obs.Error = "bad tds length"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
	}
	body := make([]byte, total-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		obs.Error = "short tds body"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
	}
	ver, ok := parsePreloginVersion(body)
	if !ok {
		obs.Error = "no prelogin version"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
	}
	payload := Observation{Prelogin: true, Version: ver}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "mssql", Observations: []model.ObservationRecord{obs}}, nil
}

func preloginRequest() []byte {
	return []byte{0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func parsePreloginVersion(body []byte) (string, bool) {
	i := 0
	for i+5 <= len(body) {
		tok := body[i]
		if tok == tokenTerm {
			return "", false
		}
		off := int(binary.BigEndian.Uint16(body[i+1 : i+3]))
		ln := int(binary.BigEndian.Uint16(body[i+3 : i+5]))
		i += 5
		if tok == tokenVersion && off >= 0 && ln >= 6 && off+ln <= len(body) {
			v := body[off : off+ln]
			major, minor := v[0], v[1]
			build := binary.BigEndian.Uint16(v[2:4])
			return fmt.Sprintf("%d.%d.%d", major, minor, build), true
		}
	}
	return "", false
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
