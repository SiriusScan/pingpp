package scan_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestNewRegistryHasSSHAndSMB(t *testing.T) {
	r := scan.NewRegistry()
	for _, id := range []string{"collect.ssh", "collect.smb", "collect.http", "collect.tls", "enumerate.tcp"} {
		if !r.Has(id) {
			t.Fatalf("missing %s", id)
		}
	}
}
