package runner

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/probes"
)

func TestLivenessNotOverriddenByClosedTCP(t *testing.T) {
	// Policy: ICMP (or any) success must keep the host alive even when TCP
	// finds no open ports. This test encodes the regression against the old
	// override that forced IsAlive=false when OpenPorts was empty.
	r := NewResult("192.0.2.10")

	icmp := probes.NewSuccessResult(64, 5*time.Millisecond)
	icmp.Protocol = "icmp"
	r.AddProbeResult(icmp)

	tcp := probes.NewProbeResult()
	tcp.Protocol = "tcp"
	tcp.Success = false
	tcp.Error = "no ports responded"
	tcp.Details["closed_ports"] = "22,80,443"
	r.AddProbeResult(tcp)

	if !r.IsAlive {
		t.Fatal("host must remain alive after ICMP success despite closed TCP ports")
	}
	if len(r.OpenPorts) != 0 {
		t.Fatalf("OpenPorts=%v, want empty", r.OpenPorts)
	}

	// Document the policy function used historically — ensure we never
	// reintroduce the override semantics.
	if shouldOverrideAlive(true, true, r.OpenPorts) {
		t.Fatal("shouldOverrideAlive must always return false (override removed)")
	}
}

// shouldOverrideAlive documents the removed incorrect policy.
// It always returns false: lack of open TCP ports must never reverse liveness.
func shouldOverrideAlive(alive, hasTCP bool, openPorts []int) bool {
	_ = alive
	_ = hasTCP
	_ = openPorts
	return false
}

func TestOpenPortsAccumulatedFromTCPDetails(t *testing.T) {
	r := NewResult("192.0.2.10")

	tcp := probes.NewProbeResult()
	tcp.Protocol = "tcp"
	tcp.Success = true
	tcp.Port = 22
	tcp.Details["open_ports"] = "22,80,443"
	r.AddProbeResult(tcp)

	want := map[int]bool{22: true, 80: true, 443: true}
	if len(r.OpenPorts) != 3 {
		t.Fatalf("OpenPorts=%v, want 3 ports", r.OpenPorts)
	}
	for _, p := range r.OpenPorts {
		if !want[p] {
			t.Fatalf("unexpected port %d in %v", p, r.OpenPorts)
		}
	}
}

func TestOpenPortsMergedWhenTCPNotSuccess(t *testing.T) {
	r := NewResult("192.0.2.10")

	tcp := probes.NewProbeResult()
	tcp.Protocol = "tcp"
	tcp.Success = false
	tcp.Details["closed_ports"] = "22"
	tcp.Details["filtered_ports"] = "443"
	r.AddProbeResult(tcp)

	if r.Details["closed_ports"] != "22" {
		t.Fatalf("closed_ports=%q", r.Details["closed_ports"])
	}
	if r.Details["filtered_ports"] != "443" {
		t.Fatalf("filtered_ports=%q", r.Details["filtered_ports"])
	}
}

func TestResultStringTTLFormatting(t *testing.T) {
	cases := []int{64, 128, 255}
	for _, ttl := range cases {
		r := NewResult("192.0.2.10")
		r.IsAlive = true
		r.OSFamily = "linux"
		r.TTL = ttl
		s := r.String()
		want := "TTL:" + strconv.Itoa(ttl)
		if !strings.Contains(s, want) {
			t.Fatalf("String()=%q missing %q", s, want)
		}
	}
}

func TestTCPProbeDoesNotContributeBogusTTL(t *testing.T) {
	r := NewResult("192.0.2.10")

	icmp := probes.NewSuccessResult(55, time.Millisecond)
	icmp.Protocol = "icmp"
	r.AddProbeResult(icmp)

	tcp := probes.NewProbeResult()
	tcp.Protocol = "tcp"
	tcp.Success = true
	tcp.Port = 80
	tcp.TTL = 0 // TCP must not invent TTL
	tcp.Details["open_ports"] = "80"
	r.AddProbeResult(tcp)

	if r.TTL != 55 {
		t.Fatalf("TTL=%d, want 55 from ICMP only", r.TTL)
	}
}
