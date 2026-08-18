package rdp_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/rdp"
)

func TestRDPNegotiationHybrid(t *testing.T) {
	ln := serve(t, rdpConfirm(0x00000002))
	defer func() { _ = ln.Close() }()
	res := run(t, ln)
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var payload struct {
		X224Confirm      bool   `json:"x224_confirm"`
		SelectedProtocol string `json:"selected_protocol"`
	}
	_ = json.Unmarshal(res.Observations[0].Payload, &payload)
	if !payload.X224Confirm || payload.SelectedProtocol != "hybrid" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRDPNegotiationSSL(t *testing.T) {
	ln := serve(t, rdpConfirm(0x00000001))
	defer func() { _ = ln.Close() }()
	res := run(t, ln)
	var payload struct {
		SelectedProtocol string `json:"selected_protocol"`
	}
	_ = json.Unmarshal(res.Observations[0].Payload, &payload)
	if res.Outcome != engine.OutcomeSuccess || payload.SelectedProtocol != "ssl" {
		t.Fatalf("outcome=%q proto=%q", res.Outcome, payload.SelectedProtocol)
	}
}

func TestRDPRejectsTPKTWithoutConfirm(t *testing.T) {
	pkt := []byte{0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00}
	ln := serve(t, pkt)
	defer func() { _ = ln.Close() }()
	res := run(t, ln)
	if res.Outcome != engine.OutcomeNoMatch {
		t.Fatalf("TPKT without X.224 CC must be no_match, got %q", res.Outcome)
	}
}

func TestRDPRejectsHTTPLookalike(t *testing.T) {
	ln := serve(t, []byte("HTTP/1.1 200 OK\r\n\r\n"))
	defer func() { _ = ln.Close() }()
	res := run(t, ln)
	if res.Outcome != engine.OutcomeNoMatch {
		t.Fatalf("outcome=%q", res.Outcome)
	}
}

func rdpConfirm(proto uint32) []byte {
	neg := []byte{0x02, 0x00, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(neg[4:8], proto)
	x224 := append([]byte{0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00}, neg...)
	pkt := make([]byte, 4+len(x224))
	pkt[0] = 0x03
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[4:], x224)
	return pkt
}

func run(t *testing.T, ln net.Listener) engine.CollectorResult {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := rdp.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func serve(t *testing.T, reply []byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		_, _ = c.Write(reply)
	}()
	return ln
}
