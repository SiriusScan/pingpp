package ftp_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/ftp"
)

func TestFTPAcceptsFTP(t *testing.T) {
	ln := serveLines(t, []string{"220 ftp.example.com FTP server ready\r\n"})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
}

func TestFTPRejectsSMTP(t *testing.T) {
	ln := serveLines(t, []string{"220 mail.example.com ESMTP Postfix\r\n"})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func TestFTPRejectsHTTPLookalike(t *testing.T) {
	ln := serveLines(t, []string{"HTTP/1.1 200 OK\r\n"})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func assertOutcome(t *testing.T, ln net.Listener, want engine.ProbeOutcome) {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := ftp.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != want {
		t.Fatalf("outcome=%q want %q", res.Outcome, want)
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
