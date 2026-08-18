package scan_test

import (
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestDefaultConfigUsesDefaultProfilePorts(t *testing.T) {
	cfg := scan.DefaultConfig()
	opts, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	prof := engine.PrepareProfile(opts)
	want := engine.ProfileFor(engine.ProfileDefault)
	if len(prof.TCPPorts) != len(want.TCPPorts) {
		t.Fatalf("tcp ports=%d want %d", len(prof.TCPPorts), len(want.TCPPorts))
	}
	if len(prof.UDPPorts) != len(want.UDPPorts) {
		t.Fatalf("udp ports=%d want %d", len(prof.UDPPorts), len(want.UDPPorts))
	}
	if opts.OverrideTCPPorts || opts.OverrideUDPPorts {
		t.Fatal("default config must not override ports")
	}
}

func TestConfigAppliesNamedProfile(t *testing.T) {
	cfg := scan.DefaultConfig()
	cfg.Profile.Name = engine.ProfileQuick
	opts, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	prof := engine.PrepareProfile(opts)
	if prof.Name != engine.ProfileQuick {
		t.Fatalf("profile=%q", prof.Name)
	}
	if len(prof.TCPPorts) != len(engine.QuickPorts) {
		t.Fatalf("quick tcp=%d", len(prof.TCPPorts))
	}
}

func TestConfigUDPNoneDisablesUDP(t *testing.T) {
	cfg := scan.DefaultConfig()
	cfg.Ports.UDP = scan.PortSelection{Override: true, Ports: nil}
	opts, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if !opts.OverrideUDPPorts {
		t.Fatal("UDP none must set OverrideUDPPorts")
	}
	prof := engine.PrepareProfile(opts)
	if len(prof.UDPPorts) != 0 {
		t.Fatalf("udp ports=%v want empty", prof.UDPPorts)
	}
}

func TestConfigCustomTCPPorts(t *testing.T) {
	cfg := scan.DefaultConfig()
	cfg.Ports.TCP = scan.PortSelection{Override: true, Ports: []uint16{22, 80}}
	opts, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	prof := engine.PrepareProfile(opts)
	if len(prof.TCPPorts) != 2 || prof.TCPPorts[0] != 22 || prof.TCPPorts[1] != 80 {
		t.Fatalf("tcp=%v", prof.TCPPorts)
	}
}

func TestConfigNoICMPIsNotSkipDiscovery(t *testing.T) {
	cfg := scan.DefaultConfig()
	cfg.Discovery.DisableICMP = true
	opts, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if opts.SkipDiscovery {
		t.Fatal("DisableICMP must not set SkipDiscovery")
	}
	if !opts.DisableICMP {
		t.Fatal("DisableICMP not compiled")
	}
	prof := engine.PrepareProfile(opts)
	if prof.SkipDiscovery {
		t.Fatal("profile must still run discovery")
	}
	foundICMP, foundTCP := false, false
	for _, id := range prof.DiscoveryCollectors {
		if id == "discovery.icmp" {
			foundICMP = true
		}
		if id == "discovery.tcp" {
			foundTCP = true
		}
	}
	if foundICMP {
		t.Fatal("DisableICMP should remove discovery.icmp")
	}
	if !foundTCP {
		t.Fatal("DisableICMP must keep discovery.tcp")
	}

	skip := scan.DefaultConfig()
	skip.Discovery.SkipDiscovery = true
	sopts, err := skip.Compile()
	if err != nil {
		t.Fatal(err)
	}
	sprof := engine.PrepareProfile(sopts)
	if !sprof.SkipDiscovery {
		t.Fatal("SkipDiscovery must skip the stage")
	}
}

func TestConfigRejectsInvalidValues(t *testing.T) {
	t.Run("profile", func(t *testing.T) {
		cfg := scan.DefaultConfig()
		cfg.Profile.Name = "nope"
		if _, err := cfg.Compile(); err == nil {
			t.Fatal("expected unknown profile")
		}
	})
	t.Run("tcp port 0", func(t *testing.T) {
		cfg := scan.DefaultConfig()
		cfg.Ports.TCP = scan.PortSelection{Override: true, Ports: []uint16{0}}
		if _, err := cfg.Compile(); err == nil {
			t.Fatal("expected invalid port")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		cfg := scan.DefaultConfig()
		cfg.Limits.ProbeTimeout = -time.Second
		if _, err := cfg.Compile(); err == nil {
			t.Fatal("expected invalid timeout")
		}
	})
}

func TestConfigCompilesBannerFile(t *testing.T) {
	cfg := scan.DefaultConfig()
	cfg.Unknowns.BannerFile = "/tmp/unmatched.jsonl"
	opts, err := cfg.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if opts.UnmatchedBannerFile != "/tmp/unmatched.jsonl" {
		t.Fatalf("banner file=%q", opts.UnmatchedBannerFile)
	}
}
