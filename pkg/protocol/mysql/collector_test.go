package mysql_test

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/mysql"
)

func mysqlHandshake() []byte {
	ver := append([]byte("8.0.36"), 0)
	body := []byte{0x0a}
	body = append(body, ver...)
	cid := make([]byte, 4)
	binary.LittleEndian.PutUint32(cid, 42)
	body = append(body, cid...)
	body = append(body, make([]byte, 23)...)
	hdr := []byte{byte(len(body)), 0, 0, 0}
	return append(hdr, body...)
}

func TestMySQLHandshakeSuccess(t *testing.T) {
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
		_, _ = c.Write(mysqlHandshake())
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	col, _ := mysql.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := col.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
}

func TestMySQLRejectsShortGarbage(t *testing.T) {
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
	col, _ := mysql.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := col.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeNoMatch {
		t.Fatalf("outcome=%q", res.Outcome)
	}
}
