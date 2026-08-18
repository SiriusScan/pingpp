package snmp_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/snmp"
)

func TestSNMPObservationOmitsCommunity(t *testing.T) {
	raw, err := json.Marshal(snmp.Observation{SysDescr: "router", SysName: "edge"})
	if err != nil {
		t.Fatal(err)
	}
	if !snmp.CommunityAbsent(raw) {
		t.Fatalf("community leaked: %s", raw)
	}
	if string(raw) == "" || !containsDescr(raw) {
		t.Fatalf("payload=%s", raw)
	}
}

func TestSNMPNoMatchOnGarbageUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 1500)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr)
	}()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	c, err := snmp.New(engine.Config{Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportUDP, model.EndpointResponsive)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome == engine.OutcomeSuccess {
		t.Fatal("garbage UDP must not be SNMP success")
	}
	if len(res.Observations) == 1 {
		var raw map[string]any
		_ = json.Unmarshal(res.Observations[0].Payload, &raw)
		if _, ok := raw["community"]; ok {
			t.Fatal("community must not appear in observation JSON")
		}
	}
}

func containsDescr(raw []byte) bool {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	_, ok := m["sys_descr"]
	return ok
}
