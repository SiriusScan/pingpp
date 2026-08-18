package sshcol_test

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	sshcol "github.com/SiriusScan/ping++/pkg/protocol/ssh"
)

func TestSSHCollectorBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		br := bufio.NewReader(c)
		_, _ = br.ReadString('\n')
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := sshcol.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	obs, err := c.Run(context.Background(), engine.CollectorInput{Endpoint: &ep, Asset: model.NewAssetFromIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	var p model.SSHObservation
	_ = obs[0].DecodePayload(&p)
	if p.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("banner=%q", p.Banner)
	}
	if p.ProtocolVersion != "2.0" {
		t.Fatalf("proto=%q", p.ProtocolVersion)
	}
}

func TestSSHCollectorRejectsHTTPLookalike(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n"))
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := sshcol.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeNoMatch {
		t.Fatalf("HTTP lookalike outcome=%q want no_match", res.Outcome)
	}
}
