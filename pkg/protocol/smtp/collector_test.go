package smtp_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/internal/tlstest"
	"github.com/SiriusScan/ping++/pkg/protocol/smtp"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

func TestSMTPAcceptsSMTP(t *testing.T) {
	ln := serveLines(t, []string{
		"220 mail.example.com ESMTP Postfix\r\n",
		"250-mail.example.com\r\n",
		"250 STARTTLS\r\n",
	})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
}

func TestSMTPAcceptsGenericGreetingWithEHLO(t *testing.T) {
	ln := serveLines(t, []string{
		"220 mail.example.com ready\r\n",
		"250-mail.example.com\r\n",
		"250 STARTTLS\r\n",
	})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
}

func TestSMTPRejectsFTP(t *testing.T) {
	ln := serveLines(t, []string{"220 ftp.example.com FTP server ready\r\n"})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestSMTPRejectsHTTPLookalike(t *testing.T) {
	ln := serveLines(t, []string{"HTTP/1.1 200 OK\r\n"})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestSMTPStartTLSUpgrade(t *testing.T) {
	ln := serveSMTPStartTLS(t, true)
	defer func() { _ = ln.Close() }()
	res := runSMTP(t, ln)
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
		if strings.EqualFold(f, "AUTH") {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-TLS EHLO features=%v", p.Features)
	}
}

func TestSMTPStartTLSRejectKeepsPlaintextMatch(t *testing.T) {
	ln := serveSMTPStartTLS(t, false)
	defer func() { _ = ln.Close() }()
	res := runSMTP(t, ln)
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var p textproto.BannerObservation
	_ = res.Observations[0].DecodePayload(&p)
	if p.StartTLS {
		t.Fatal("rejected STARTTLS must not set starttls")
	}
}

func TestSMTPSkipsStartTLSWhenNotAdvertised(t *testing.T) {
	var startTLS atomic.Bool
	ln := serveSMTPCommands(t, []string{
		"220 mail.example.com ESMTP\r\n",
		"250-mail.example.com\r\n",
		"250 SIZE 10240000\r\n",
	}, func(cmd string) {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(cmd)), "STARTTLS") {
			startTLS.Store(true)
		}
	})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
	if startTLS.Load() {
		t.Fatal("STARTTLS must not be sent unless EHLO advertises it")
	}
}

func assertOutcome(t *testing.T, ln net.Listener, want engine.ProbeOutcome) {
	t.Helper()
	res := runSMTP(t, ln)
	if res.Outcome != want {
		t.Fatalf("outcome=%q want %q", res.Outcome, want)
	}
}

func runSMTP(t *testing.T, ln net.Listener) engine.CollectorResult {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := smtp.New(engine.Config{Timeout: 2 * time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func serveLines(t *testing.T, lines []string) net.Listener {
	t.Helper()
	return serveSMTPCommands(t, lines, nil)
}

func serveSMTPCommands(t *testing.T, lines []string, onCmd func(string)) net.Listener {
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
		_, _ = c.Write([]byte(lines[0]))
		if len(lines) > 1 {
			br := bufio.NewReader(c)
			cmd, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if onCmd != nil {
				onCmd(cmd)
			}
			for _, line := range lines[1:] {
				_, _ = c.Write([]byte(line))
			}
		}
	}()
	return ln
}

func serveSMTPStartTLS(t *testing.T, allow bool) net.Listener {
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
		br := bufio.NewReader(c)
		_, _ = c.Write([]byte("220 mail.example.com ESMTP\r\n"))
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		_, _ = c.Write([]byte("250-mail.example.com\r\n250 STARTTLS\r\n"))
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		if !allow {
			_, _ = c.Write([]byte("454 TLS not available\r\n"))
			return
		}
		_, _ = c.Write([]byte("220 Ready to start TLS\r\n"))
		sc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := sc.Handshake(); err != nil {
			return
		}
		defer func() { _ = sc.Close() }()
		tr := bufio.NewReader(sc)
		if _, err := tr.ReadString('\n'); err != nil {
			return
		}
		_, _ = sc.Write([]byte("250-mail.example.com\r\n250 AUTH PLAIN\r\n"))
	}()
	return ln
}
