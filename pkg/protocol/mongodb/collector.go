package mongodb

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

const id = "collect.mongodb"

const (
	opReply int32 = 1
	opMsg   int32 = 2013
	opQuery int32 = 2004
)

type Collector struct{ timeout time.Duration }

type Observation struct {
	Opcode    int32 `json:"opcode,omitempty"`
	MsgLength int32 `json:"msg_length,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{27017}, Cost: 2, Priority: 50, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("mongodb: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:mongo:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "mongodb", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("mongodb:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "mongodb", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := conn.Write(isMasterQuery()); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mongodb", Observations: []model.ObservationRecord{obs}}, nil
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mongodb", Observations: []model.ObservationRecord{obs}}, nil
	}
	msgLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	opcode := int32(binary.LittleEndian.Uint32(hdr[12:16]))
	if msgLen < 16 || msgLen > 48*1024*1024 {
		obs.Error = "invalid mongo message length"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mongodb", Observations: []model.ObservationRecord{obs}}, nil
	}
	if opcode != opReply && opcode != opMsg {
		obs.Error = fmt.Sprintf("not mongo opcode %d", opcode)
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "mongodb", Observations: []model.ObservationRecord{obs}}, nil
	}
	rest := int(msgLen) - 16
	if rest > 0 && rest < 64*1024 {
		body := make([]byte, rest)
		_, _ = io.ReadFull(conn, body)
	}
	payload := Observation{Opcode: opcode, MsgLength: msgLen}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "mongodb", Observations: []model.ObservationRecord{obs}}, nil
}

func isMasterQuery() []byte {
	bson := []byte{13, 0, 0, 0, 0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bson[0:4], uint32(len(bson)))
	msgLen := 16 + 4 + len("admin.$cmd") + 1 + 8 + len(bson)
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opQuery))
	copy(msg[20:], "admin.$cmd")
	off := 20 + len("admin.$cmd") + 1
	binary.LittleEndian.PutUint32(msg[off+4:off+8], 1)
	copy(msg[off+8:], bson)
	return msg
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
