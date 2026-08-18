package tcp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTCPProbeEnumeratesAllOpenPorts(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 1: %v", err)
	}
	defer func() { _ = ln1.Close() }()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 2: %v", err)
	}
	defer func() { _ = ln2.Close() }()

	port1 := ln1.Addr().(*net.TCPAddr).Port
	port2 := ln2.Addr().(*net.TCPAddr).Port

	// Accept and immediately close so Dial succeeds.
	go acceptLoop(ln1)
	go acceptLoop(ln2)

	probe := New([]int{port1, port2}, time.Second)
	result, err := probe.Probe(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected Success, got error=%q details=%v", result.Error, result.Details)
	}

	open := result.Details["open_ports"]
	if open == "" {
		t.Fatal("expected open_ports detail")
	}
	got := csvToSet(open)
	if !got[port1] || !got[port2] {
		t.Fatalf("open_ports=%q want both %d and %d", open, port1, port2)
	}
	if result.TTL != 0 {
		t.Fatalf("TCP probe must not set TTL, got %d", result.TTL)
	}
}

func TestTCPProbeDoesNotSetTTL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go acceptLoop(ln)

	port := ln.Addr().(*net.TCPAddr).Port
	probe := New([]int{port}, time.Second)
	result, err := probe.Probe(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got %q", result.Error)
	}
	if result.TTL != 0 {
		t.Fatalf("TTL = %d, want 0 (local sockopt TTL must not be used)", result.TTL)
	}
}

func TestTCPProbeRecordsClosedPorts(t *testing.T) {
	// Bind then close to obtain a free port that will refuse connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	openLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen open: %v", err)
	}
	defer func() { _ = openLn.Close() }()
	go acceptLoop(openLn)
	openPort := openLn.Addr().(*net.TCPAddr).Port

	probe := New([]int{openPort, closedPort}, time.Second)
	result, err := probe.Probe(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success because one port is open, got %q", result.Error)
	}

	openSet := csvToSet(result.Details["open_ports"])
	if !openSet[openPort] {
		t.Fatalf("open_ports=%q missing %d", result.Details["open_ports"], openPort)
	}
	closedSet := csvToSet(result.Details["closed_ports"])
	if !closedSet[closedPort] {
		t.Fatalf("closed_ports=%q missing %d", result.Details["closed_ports"], closedPort)
	}
}

func TestTCPProbeAllClosedIsNotSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	probe := New([]int{port}, time.Second)
	result, err := probe.Probe(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if result.Success {
		t.Fatal("expected Success=false when no ports are open")
	}
	closedSet := csvToSet(result.Details["closed_ports"])
	if !closedSet[port] {
		t.Fatalf("closed_ports=%q missing %d", result.Details["closed_ports"], port)
	}
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func csvToSet(s string) map[int]bool {
	out := make(map[int]bool)
	if s == "" {
		return out
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err == nil {
			out[n] = true
		}
	}
	return out
}
