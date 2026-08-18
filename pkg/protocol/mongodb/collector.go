package mongodb

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.mongodb"

type Collector struct{ timeout time.Duration }
type Observation struct {
	IsMongo bool   `json:"is_mongo"`
	RawHint string `json:"raw_hint,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{27017}, Cost: 2, Priority: 50, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("mongodb: endpoint required")
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
		return []model.ObservationRecord{obs}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	// Minimal OP_QUERY isMaster (legacy) — enough to see if service speaks Mongo wire protocol.
	// Build a tiny BSON {isMaster:1}
	bson := []byte{13, 0, 0, 0, 0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bson[0:4], uint32(len(bson)))
	msgLen := 16 + 4 + len("admin.$cmd") + 1 + 8 + len(bson)
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(msg[12:16], 2004) // OP_QUERY
	copy(msg[20:], "admin.$cmd")
	off := 20 + len("admin.$cmd") + 1
	binary.LittleEndian.PutUint32(msg[off:off+4], 0) // numberToSkip
	binary.LittleEndian.PutUint32(msg[off+4:off+8], 1)
	copy(msg[off+8:], bson)
	_, _ = conn.Write(msg)
	hdr := make([]byte, 16)
	n, err := conn.Read(hdr)
	payload := Observation{}
	if err == nil && n >= 16 {
		payload.IsMongo = true
		payload.RawHint = fmt.Sprintf("reply_len=%d opcode=%d", binary.LittleEndian.Uint32(hdr[0:4]), binary.LittleEndian.Uint32(hdr[12:16]))
		obs.Completeness = "full"
	} else {
		obs.Completeness = "none"
		if err != nil {
			obs.Error = err.Error()
		}
	}
	_ = obs.SetPayload(payload)
	return []model.ObservationRecord{obs}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
