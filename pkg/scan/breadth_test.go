package scan_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestRegistryHasProtocolBreadth(t *testing.T) {
	r := scan.NewRegistry()
	want := []string{
		"collect.ftp", "collect.smtp", "collect.pop3", "collect.imap", "collect.telnet",
		"collect.mysql", "collect.mssql", "collect.postgres", "collect.redis", "collect.mongodb", "collect.memcached",
		"collect.ldap", "collect.rdp", "collect.dns", "collect.snmp",
		"collect.mqtt", "collect.vnc", "collect.socks", "collect.amqp",
	}
	for _, id := range want {
		if !r.Has(id) {
			t.Errorf("missing collector %s", id)
		}
	}
}
