package engine

import (
	"strings"
	"testing"
)

func TestSkipICMPKeepsTCPDiscovery(t *testing.T) {
	p := applyEngineOptions(ProfileFor(ProfileQuick), Options{SkipICMP: true})
	if p.SkipDiscovery {
		t.Fatal("DisableICMP/SkipICMP must not skip all discovery")
	}
	joined := strings.Join(p.DiscoveryCollectors, ",")
	if strings.Contains(joined, "discovery.icmp") {
		t.Fatalf("icmp still present: %v", p.DiscoveryCollectors)
	}
	if !strings.Contains(joined, "discovery.tcp") {
		t.Fatalf("tcp discovery missing: %v", p.DiscoveryCollectors)
	}
}

func TestProbeTypesFilterCollectors(t *testing.T) {
	p := applyEngineOptions(ProfileFor(ProfileDefault), Options{ProbeTypes: []string{"icmp", "tcp"}})
	allow := strings.Join(p.AllowCollectors, ",")
	if strings.Contains(allow, "collect.ssh") || strings.Contains(allow, "collect.http") {
		t.Fatalf("icmp+tcp must not enable protocol collectors: %v", p.AllowCollectors)
	}
	if !strings.Contains(allow, "enumerate.tcp") {
		t.Fatalf("tcp probe type should allow enumerate.tcp: %v", p.AllowCollectors)
	}
	pl := NewPlanner(NewRegistry(), p)
	if pl.collectorAllowed("collect.ssh") {
		t.Fatal("collect.ssh should be filtered")
	}
	if !pl.collectorAllowed("enumerate.tcp") {
		t.Fatal("enumerate.tcp should be allowed")
	}
}
