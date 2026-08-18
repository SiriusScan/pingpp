package textproto_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/ftp"
	"github.com/SiriusScan/ping++/pkg/protocol/smtp"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

func TestUseTLSImplicitPorts(t *testing.T) {
	ep993 := model.NewEndpoint("127.0.0.1", 993, model.TransportTCP, model.EndpointOpen)
	if !textproto.UseTLS(engine.CollectorInput{Endpoint: &ep993}) {
		t.Fatal("993 should use implicit TLS")
	}
	ep25 := model.NewEndpoint("127.0.0.1", 25, model.TransportTCP, model.EndpointOpen)
	if textproto.UseTLS(engine.CollectorInput{Endpoint: &ep25}) {
		t.Fatal("25 should not use implicit TLS")
	}
	if !textproto.UseTLS(engine.CollectorInput{Endpoint: &ep25, Extra: map[string]string{"tls": "1"}}) {
		t.Fatal("tls=1 extra should enable TLS")
	}
}

func TestFTPBanner(t *testing.T) {
	ln := serveLines(t, []string{"220 Welcome to ftp.example\r\n"})
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := ftp.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	obs, err := c.Run(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	var p textproto.BannerObservation
	_ = obs[0].DecodePayload(&p)
	if p.Banner == "" || p.Banner[:3] != "220" {
		t.Fatalf("banner=%q", p.Banner)
	}
}

func TestSMTPEHLOFeatures(t *testing.T) {
	ln := serveLines(t, []string{
		"220 mail.example ESMTP\r\n",
		"250-mail.example\r\n",
		"250-STARTTLS\r\n",
		"250 SIZE 10240000\r\n",
	})
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := smtp.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	obs, err := c.Run(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	var p textproto.BannerObservation
	_ = obs[0].DecodePayload(&p)
	if p.Banner[:3] != "220" {
		t.Fatalf("banner=%q", p.Banner)
	}
	found := false
	for _, f := range p.Features {
		if f == "STARTTLS" {
			found = true
		}
	}
	if !found {
		t.Fatalf("features=%v", p.Features)
	}
}

func TestFTPRejectsHTTPLookalike(t *testing.T) {
	ln := serveLines(t, []string{"HTTP/1.1 200 OK\r\n"})
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := ftp.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeNoMatch {
		t.Fatalf("HTTP lookalike ftp outcome=%q", res.Outcome)
	}
}

func TestSMTPSuccessOn220(t *testing.T) {
	ln := serveLines(t, []string{
		"220 mail.example ESMTP\r\n",
		"250-mail.example\r\n",
		"250 STARTTLS\r\n",
	})
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := smtp.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("smtp outcome=%q", res.Outcome)
	}
}

func serveLines(t *testing.T, lines []string) net.Listener {
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
			_, _ = br.ReadString('\n')
			for _, line := range lines[1:] {
				_, _ = c.Write([]byte(line))
			}
		}
	}()
	return ln
}
