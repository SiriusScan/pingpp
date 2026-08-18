package scan_test

import (
	"context"
	"testing"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestSessionLoadsFingerprintsOnce(t *testing.T) {
	before := fingerprint.BuiltinLoadCount()
	cfg := scan.DefaultConfig()
	cfg.Discovery.SkipDiscovery = true
	cfg.Ports.TCP = scan.PortSelection{Override: true}
	cfg.Ports.UDP = scan.PortSelection{Override: true}
	sess, err := scan.NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	afterNew := fingerprint.BuiltinLoadCount()
	if afterNew-before != 1 {
		t.Fatalf("NewSession builtin loads=%d want 1", afterNew-before)
	}

	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if _, err := sess.Scan(ctx, "192.0.2.1"); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
	}
	if fingerprint.BuiltinLoadCount()-before != 1 {
		t.Fatalf("packs reloaded: start=%d now=%d", before, fingerprint.BuiltinLoadCount())
	}
}

func TestScanOneShotUsesSession(t *testing.T) {
	before := fingerprint.BuiltinLoadCount()
	ctx := context.Background()
	if _, err := scan.Scan(ctx, "192.0.2.1", scan.ScanOptions{
		Options: engine.Options{
			SkipDiscovery:    true,
			OverrideTCPPorts: true,
			OverrideUDPPorts: true,
		},
	}); err != nil {
		t.Fatalf("one-shot scan: %v", err)
	}
	if fingerprint.BuiltinLoadCount() <= before {
		t.Fatal("one-shot Scan must load packs through Session")
	}
}

func TestSessionRejectsScanAfterClose(t *testing.T) {
	sess, err := scan.NewSession(scan.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Scan(context.Background(), "192.0.2.1"); err == nil {
		t.Fatal("expected closed session error")
	}
}
