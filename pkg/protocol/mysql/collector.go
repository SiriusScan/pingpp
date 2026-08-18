package mysql

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const id = "collect.mysql"

type Collector struct{ timeout time.Duration }

type Observation struct {
	ProtocolVersion uint8  `json:"protocol_version,omitempty"`
	ServerVersion   string `json:"server_version,omitempty"`
	ConnectionID    uint32 `json:"connection_id,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{3306}, Cost: 2, Priority: 55, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("mysql: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:mysql:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "mysql", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("mysql:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return []model.ObservationRecord{obs}, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	hdr := make([]byte, 4)
	if _, err := conn.Read(hdr); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return []model.ObservationRecord{obs}, nil
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	body := make([]byte, length)
	if _, err := conn.Read(body); err != nil || len(body) < 5 {
		obs.Error = "short handshake"
		obs.Completeness = "partial"
		return []model.ObservationRecord{obs}, nil
	}
	payload := Observation{ProtocolVersion: body[0]}
	// null-terminated version string
	end := 1
	for end < len(body) && body[end] != 0 {
		end++
	}
	payload.ServerVersion = string(body[1:end])
	if end+4 < len(body) {
		payload.ConnectionID = binary.LittleEndian.Uint32(body[end+1 : end+5])
	}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return []model.ObservationRecord{obs}, nil
}
func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
