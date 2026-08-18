package sshcol_test

import (
	"bufio"
	"context"
	"encoding/binary"
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

func TestSSHFramedKEXINITAfterIgnore(t *testing.T) {
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
		_, _ = c.Write(sshPacket([]byte{2})) // IGNORE
		_, _ = c.Write(sshPacket(kexinitPayload()))
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := sshcol.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var p model.SSHObservation
	_ = res.Observations[0].DecodePayload(&p)
	if len(p.KexAlgorithms) == 0 || p.KexAlgorithms[0] != "curve25519-sha256" {
		t.Fatalf("kex=%v", p.KexAlgorithms)
	}
	if len(p.HostKeyAlgorithms) == 0 || p.HostKeyAlgorithms[0] != "ssh-ed25519" {
		t.Fatalf("hostkey=%v", p.HostKeyAlgorithms)
	}
}

func sshPacket(payload []byte) []byte {
	pad := 4
	n := 1 + len(payload) + pad
	out := make([]byte, 4+n)
	binary.BigEndian.PutUint32(out[0:4], uint32(n))
	out[4] = byte(pad)
	copy(out[5:], payload)
	return out
}

func kexinitPayload() []byte {
	b := []byte{20}
	b = append(b, make([]byte, 16)...)
	writeName := func(s string) {
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp, uint32(len(s)))
		b = append(b, tmp...)
		b = append(b, s...)
	}
	writeName("curve25519-sha256")
	writeName("ssh-ed25519")
	writeName("aes128-ctr")
	writeName("aes128-ctr")
	writeName("hmac-sha2-256")
	writeName("hmac-sha2-256")
	writeName("none")
	writeName("none")
	writeName("")
	writeName("")
	b = append(b, 0, 0, 0, 0, 0)
	return b
}
