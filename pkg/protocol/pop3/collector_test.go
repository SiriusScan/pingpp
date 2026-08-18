package pop3_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/internal/tlstest"
	"github.com/SiriusScan/ping++/pkg/protocol/pop3"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

func TestPOP3AdvertisesPOP3S(t *testing.T) {
	c, _ := pop3.New(engine.Config{})
	found := false
	for _, p := range c.Metadata().DefaultPorts {
		if p == 995 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 995, got %v", c.Metadata().DefaultPorts)
	}
}

func TestPOP3AcceptsOK(t *testing.T) {
	ln := serve(t, "+OK POP3 server ready\r\n")
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
}

func TestPOP3RejectsRandomBanner(t *testing.T) {
	ln := serve(t, "220 ftp.example.com FTP server ready\r\n")
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestPOP3RejectsHTTPLookalike(t *testing.T) {
	ln := serve(t, "HTTP/1.1 200 OK\r\n")
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestPOP3STLSUpgrade(t *testing.T) {
	ln := servePOP3STLS(t, true)
	defer func() { _ = ln.Close() }()
	res := runPOP3(t, ln)
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var p textproto.BannerObservation
	_ = res.Observations[0].DecodePayload(&p)
	if !p.StartTLS || !p.TLS {
		t.Fatalf("payload=%+v want starttls+tls", p)
	}
}

func TestPOP3STLSRejectKeepsPlaintextMatch(t *testing.T) {
	ln := servePOP3STLS(t, false)
	defer func() { _ = ln.Close() }()
	res := runPOP3(t, ln)
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var p textproto.BannerObservation
	_ = res.Observations[0].DecodePayload(&p)
	if p.StartTLS {
		t.Fatal("rejected STLS must not set starttls")
	}
}

func assertOutcome(t *testing.T, ln net.Listener, want engine.ProbeOutcome) {
	t.Helper()
	res := runPOP3(t, ln)
	if res.Outcome != want {
		t.Fatalf("outcome=%q want %q", res.Outcome, want)
	}
}

func runPOP3(t *testing.T, ln net.Listener) engine.CollectorResult {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := pop3.New(engine.Config{Timeout: 2 * time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func serve(t *testing.T, banner string) net.Listener {
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
		_, _ = c.Write([]byte(banner))
	}()
	return ln
}

func servePOP3STLS(t *testing.T, allow bool) net.Listener {
	t.Helper()
	cert := tlstest.Certificate(t)
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
		_, _ = c.Write([]byte("+OK POP3 server ready\r\n"))
		br := bufio.NewReader(c)
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		if !allow {
			_, _ = c.Write([]byte("-ERR TLS unavailable\r\n"))
			return
		}
		_, _ = c.Write([]byte("+OK Begin TLS negotiation\r\n"))
		sc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := sc.Handshake(); err != nil {
			return
		}
		_ = sc.Close()
	}()
	return ln
}
