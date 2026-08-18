package mssql_test

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/mssql"
)

func TestMSSQLPreloginVersionSuccess(t *testing.T) {
	ln := serve(t, preloginResponse())
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
}

func TestMSSQLRejectsHTTPLookalike(t *testing.T) {
	ln := serve(t, []byte("HTTP/1.1 200 OK\r\n\r\n"))
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestMSSQLRejectsResponseWithoutVersion(t *testing.T) {
	// TDS response type 0x04 but no PRELOGIN VERSION token.
	body := []byte{0xff}
	pkt := make([]byte, 8+len(body))
	pkt[0] = 0x04
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[8:], body)
	ln := serve(t, pkt)
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func preloginResponse() []byte {
	// VERSION token at offset 6 (after 5-byte token + 0xff terminator), length 6.
	body := []byte{
		0x00, 0x00, 0x06, 0x00, 0x06, // VERSION token
		0xff,             // terminator
		15, 0, 0x07, 0xd0, 0, 0, // 15.0.2000
	}
	pkt := make([]byte, 8+len(body))
	pkt[0] = 0x04
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[8:], body)
	return pkt
}

func assertOutcome(t *testing.T, ln net.Listener, want engine.ProbeOutcome) {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := mssql.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != want {
		t.Fatalf("outcome=%q want %q", res.Outcome, want)
	}
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
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write(reply)
	}()
	return ln
}
