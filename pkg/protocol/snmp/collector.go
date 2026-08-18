package snmp

import (
	"context"
	"encoding/asn1"
	"fmt"
	"net"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const id = "collect.snmp"

type Collector struct {
	timeout   time.Duration
	community string
}

type Observation struct {
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	Community   string `json:"community,omitempty"`
}

func New(cfg engine.Config) (*Collector, error) {
	community := "public"
	if cfg.Extra != nil && cfg.Extra["community"] != "" {
		community = cfg.Extra["community"]
	}
	return &Collector{timeout: engine.EffectiveTimeout(cfg), community: community}, nil
}
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: id, Stage: engine.StageCollect, Transports: []model.Transport{model.TransportUDP}, DefaultPorts: []uint16{161}, Cost: 3, Priority: 65, SideEffectRisk: "low", SafeForOT: true}
}
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("snmp: endpoint required")
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{ID: fmt.Sprintf("obs:snmp:%d", time.Now().UnixNano()), ProbeID: id, ObservationType: "snmp", Endpoint: &ref, Timestamp: time.Now().UTC(), CorrelationGroup: fmt.Sprintf("snmp:%s:%d", in.Endpoint.Address, in.Endpoint.Port)}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	// SNMPv2c GET for sysDescr (1.3.6.1.2.1.1.1.0) — no community bruteforce.
	pdu := buildSNMPv2cGet(c.community, []int{1, 3, 6, 1, 2, 1, 1, 1, 0})
	addr := &net.UDPAddr{IP: net.ParseIP(in.Endpoint.Address), Port: int(in.Endpoint.Port)}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return []model.ObservationRecord{obs}, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	_, _ = conn.Write(pdu)
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	payload := Observation{Community: c.community}
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
	} else {
		payload.SysDescr = extractOctetString(buf[:n])
		obs.Completeness = "partial"
		if payload.SysDescr != "" {
			obs.Completeness = "full"
		}
	}
	_ = obs.SetPayload(payload)
	return []model.ObservationRecord{obs}, nil
}

func buildSNMPv2cGet(community string, oid []int) []byte {
	// Minimal hand-rolled SNMPv2c GetRequest.
	var oidBytes []byte
	if len(oid) >= 2 {
		oidBytes = append(oidBytes, byte(oid[0]*40+oid[1]))
		for _, v := range oid[2:] {
			oidBytes = append(oidBytes, encodeBase128(v)...)
		}
	}
	oidTLV := append([]byte{0x06, byte(len(oidBytes))}, oidBytes...)
	nullTLV := []byte{0x05, 0x00}
	varbind := append([]byte{0x30, byte(len(oidTLV) + len(nullTLV))}, append(oidTLV, nullTLV...)...)
	varbindList := append([]byte{0x30, byte(len(varbind))}, varbind...)
	requestID := []byte{0x02, 0x01, 0x01}
	errorStatus := []byte{0x02, 0x01, 0x00}
	errorIndex := []byte{0x02, 0x01, 0x00}
	pduBody := append(append(append(requestID, errorStatus...), errorIndex...), varbindList...)
	pdu := append([]byte{0xa0, byte(len(pduBody))}, pduBody...)
	version := []byte{0x02, 0x01, 0x01} // v2c
	comm := append([]byte{0x04, byte(len(community))}, []byte(community)...)
	msg := append(append(version, comm...), pdu...)
	return append([]byte{0x30, byte(len(msg))}, msg...)
}

func encodeBase128(v int) []byte {
	if v < 128 {
		return []byte{byte(v)}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0x7f)}, out...)
		v >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func extractOctetString(data []byte) string {
	// Best-effort scan for an OCTET STRING (0x04) with printable content.
	for i := 0; i+2 < len(data); i++ {
		if data[i] == 0x04 {
			l := int(data[i+1])
			if l > 0 && i+2+l <= len(data) {
				s := string(data[i+2 : i+2+l])
				if isPrintable(s) {
					return s
				}
			}
		}
	}
	_ = asn1.TagOctetString
	return ""
}

func isPrintable(s string) bool {
	if len(s) < 3 {
		return false
	}
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

func Register(r *engine.Registry) {
	r.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) { return New(cfg) })
}
