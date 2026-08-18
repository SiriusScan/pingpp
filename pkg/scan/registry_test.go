package scan_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestNewRegistryHasSSHAndSMB(t *testing.T) {
	r := scan.NewRegistry()
	for _, id := range []string{"collect.ssh", "collect.smb", "collect.http", "collect.tls", "enumerate.tcp", "enumerate.udp", "collect.banner"} {
		if !r.Has(id) {
			t.Fatalf("missing %s", id)
		}
	}
	if r.Has("collect.tcpstack") {
		t.Fatal("collect.tcpstack must not be registered in the production registry")
	}
}
