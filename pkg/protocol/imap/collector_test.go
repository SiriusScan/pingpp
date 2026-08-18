package imap_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/imap"
	"github.com/SiriusScan/ping++/pkg/internal/tlstest"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

func TestIMAPAdvertisesIMAPS(t *testing.T) {
	c, _ := imap.New(engine.Config{})
	found := false
	for _, p := range c.Metadata().DefaultPorts {
		if p == 993 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 993, got %v", c.Metadata().DefaultPorts)
	}
}

func TestIMAPAcceptsGreeting(t *testing.T) {
	ln := serve(t, "* OK IMAP4rev1 Service Ready\r\n")
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
}

func TestIMAPRejectsRandomBanner(t *testing.T) {
	ln := serve(t, "220 ftp.example.com FTP server ready\r\n")
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestIMAPRejectsHTTPLookalike(t *testing.T) {
	ln := serve(t, "HTTP/1.1 200 OK\r\n")
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestIMAPStartTLSUpgrade(t *testing.T) {
	ln := serveIMAPStartTLS(t, true)
	defer func() { _ = ln.Close() }()
	res := runIMAP(t, ln)
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var p textproto.BannerObservation
	_ = res.Observations[0].DecodePayload(&p)
	if !p.StartTLS || !p.TLS {
		t.Fatalf("payload=%+v want starttls+tls", p)
	}
	found := false
	for _, f := range p.Features {
		if strings.EqualFold(f, "AUTH=PLAIN") || strings.EqualFold(f, "IMAP4REV1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-TLS CAPABILITY features=%v", p.Features)
	}
}

func TestIMAPStartTLSRejectKeepsPlaintextMatch(t *testing.T) {
	ln := serveIMAPStartTLS(t, false)
	defer func() { _ = ln.Close() }()
	res := runIMAP(t, ln)
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var p textproto.BannerObservation
	_ = res.Observations[0].DecodePayload(&p)
	if p.StartTLS {
		t.Fatal("rejected STARTTLS must not set starttls")
	}
}

func assertOutcome(t *testing.T, ln net.Listener, want engine.ProbeOutcome) {
	t.Helper()
	res := runIMAP(t, ln)
	if res.Outcome != want {
		t.Fatalf("outcome=%q want %q", res.Outcome, want)
	}
}

func runIMAP(t *testing.T, ln net.Listener) engine.CollectorResult {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := imap.New(engine.Config{Timeout: 2 * time.Second})
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

func serveIMAPStartTLS(t *testing.T, allow bool) net.Listener {
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
		_, _ = c.Write([]byte("* OK IMAP4rev1 Service Ready\r\n"))
		br := bufio.NewReader(c)
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		if !allow {
			_, _ = c.Write([]byte("A001 BAD Command unknown\r\n"))
			return
		}
		_, _ = c.Write([]byte("A001 OK Begin TLS negotiation now\r\n"))
		sc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := sc.Handshake(); err != nil {
			return
		}
		defer func() { _ = sc.Close() }()
		tr := bufio.NewReader(sc)
		if _, err := tr.ReadString('\n'); err != nil {
			return
		}
		_, _ = sc.Write([]byte("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA002 OK CAPABILITY completed\r\n"))
	}()
	return ln
}
