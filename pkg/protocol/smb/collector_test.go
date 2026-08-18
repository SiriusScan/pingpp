package smbcol_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	smbcol "github.com/SiriusScan/ping++/pkg/protocol/smb"
)

func TestSMBCollectorMetadata(t *testing.T) {
	c, err := smbcol.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	md := c.Metadata()
	if md.ID != "collect.smb" {
		t.Fatalf("id=%q", md.ID)
	}
	if md.Stage != engine.StageCollect {
		t.Fatalf("stage=%q", md.Stage)
	}
}

func TestSMBRejectsHTTPLookalike(t *testing.T) {
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
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	col, _ := smbcol.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := col.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeNoMatch {
		t.Fatalf("HTTP lookalike outcome=%q want no_match", res.Outcome)
	}
}

func TestSMBAuthDeniedIsProtocolEvidence(t *testing.T) {
	cases := []struct {
		err  string
		want bool
	}{
		{"STATUS_ACCESS_DENIED", true},
		{"NT_STATUS_LOGON_FAILURE from Samba", true},
		{"Logon failed", true},
		{"SMB signing required by server", true},
		{"STATUS_ACCOUNT_DISABLED", true},
		{"connection reset by peer", false},
		{"HTTP/1.1 400 Bad Request", false},
	}
	for _, tc := range cases {
		if got := smbcol.SMBProtocolEvidence(tc.err); got != tc.want {
			t.Fatalf("%q evidence=%v want %v", tc.err, got, tc.want)
		}
	}
}
