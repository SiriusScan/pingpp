package rdp

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

const id = "collect.rdp"

const (
	protoRDP      uint32 = 0x00000000
	protoSSL      uint32 = 0x00000001
	protoHybrid   uint32 = 0x00000002
	protoHybridEx uint32 = 0x00000008
)

type Collector struct{ timeout time.Duration }

type Observation struct {
	Negotiated        bool   `json:"negotiated"`
	X224Confirm       bool   `json:"x224_confirm,omitempty"`
	SelectedProtocol  string `json:"selected_protocol,omitempty"`
	SelectedProtocolN uint32 `json:"selected_protocol_n,omitempty"`
	Failure           bool   `json:"failure,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportTCP}, DefaultPorts: []uint16{3389}, Cost: 2, Priority: 60, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}

func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("rdp: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:rdp:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "rdp", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("rdp:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, c.timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := conn.Write(x224ConnectionRequest()); err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		obs.Completeness = "none"
		obs.Error = err.Error()
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
	}
	if hdr[0] != 0x03 {
		obs.Error = "not tpkt"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < 7 || total > 4096 {
		obs.Error = "bad tpkt length"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
	}
	rest := make([]byte, total-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		obs.Error = "short rdp pdu"
		obs.Completeness = "none"
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
	}
	payload, ok := parseNegotiation(append(hdr, rest...))
	if !ok {
		obs.Error = "not x.224 confirm"
		obs.Completeness = "none"
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
	}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "rdp", Observations: []model.ObservationRecord{obs}}, nil
}

func x224ConnectionRequest() []byte {
	cookie := []byte("Cookie: mstshash=pingpp\r\n")
	neg := []byte{0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00} // TYPE_RDP_NEG_REQ, SSL|HYBRID|HYBRID_EX
	x224Data := []byte{0xe0, 0x00, 0x00, 0x00, 0x00, 0x00}
	x224Data = append(x224Data, cookie...)
	x224Data = append(x224Data, neg...)
	li := byte(len(x224Data) + 1)
	x224 := append([]byte{li}, x224Data...)
	total := 4 + len(x224)
	tpkt := make([]byte, total)
	tpkt[0] = 0x03
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	copy(tpkt[4:], x224)
	return tpkt
}

func parseNegotiation(pkt []byte) (Observation, bool) {
	var out Observation
	if len(pkt) < 11 || pkt[0] != 0x03 || pkt[5] != 0xd0 {
		return out, false
	}
	out.X224Confirm = true
	out.Negotiated = true
	// TPKT (4) + LI (1) + CC header (0xD0, dst-ref, src-ref, class) = 11.
	// RDP Negotiation Response lives in the X.224 user-data that follows.
	neg := pkt[11:]
	if len(neg) >= 8 {
		switch neg[0] {
		case 0x02: // TYPE_RDP_NEG_RSP
			sel := binary.LittleEndian.Uint32(neg[4:8])
			out.SelectedProtocolN = sel
			out.SelectedProtocol = protocolName(sel)
		case 0x03: // TYPE_RDP_NEG_FAILURE
			out.Failure = true
			out.SelectedProtocol = "failure"
		default:
			out.SelectedProtocol = "rdp"
			out.SelectedProtocolN = protoRDP
		}
	} else {
		out.SelectedProtocol = "rdp"
		out.SelectedProtocolN = protoRDP
	}
	return out, true
}

func protocolName(n uint32) string {
	switch {
	case n&protoHybridEx != 0:
		return "hybrid_ex"
	case n&protoHybrid != 0:
		return "hybrid"
	case n&protoSSL != 0:
		return "ssl"
	default:
		return "rdp"
	}
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
