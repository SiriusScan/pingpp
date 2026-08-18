// Package scan wires collectors into a ready-to-use registry.
// Kept separate from pkg/engine to avoid import cycles with protocol packages.
package scan

import (
	"github.com/SiriusScan/ping++/pkg/discovery/icmp"
	"github.com/SiriusScan/ping++/pkg/discovery/tcp"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/protocol/amqp"
	"github.com/SiriusScan/ping++/pkg/protocol/dns"
	"github.com/SiriusScan/ping++/pkg/protocol/ftp"
	httpcol "github.com/SiriusScan/ping++/pkg/protocol/http"
	"github.com/SiriusScan/ping++/pkg/protocol/imap"
	"github.com/SiriusScan/ping++/pkg/protocol/ldap"
	"github.com/SiriusScan/ping++/pkg/protocol/memcached"
	"github.com/SiriusScan/ping++/pkg/protocol/mongodb"
	"github.com/SiriusScan/ping++/pkg/protocol/mqtt"
	"github.com/SiriusScan/ping++/pkg/protocol/mssql"
	"github.com/SiriusScan/ping++/pkg/protocol/mysql"
	"github.com/SiriusScan/ping++/pkg/protocol/pop3"
	"github.com/SiriusScan/ping++/pkg/protocol/postgres"
	"github.com/SiriusScan/ping++/pkg/protocol/rdp"
	"github.com/SiriusScan/ping++/pkg/protocol/redis"
	smbcol "github.com/SiriusScan/ping++/pkg/protocol/smb"
	"github.com/SiriusScan/ping++/pkg/protocol/smtp"
	"github.com/SiriusScan/ping++/pkg/protocol/snmp"
	"github.com/SiriusScan/ping++/pkg/protocol/socks"
	sshcol "github.com/SiriusScan/ping++/pkg/protocol/ssh"
	"github.com/SiriusScan/ping++/pkg/protocol/tcpstack"
	"github.com/SiriusScan/ping++/pkg/protocol/telnet"
	tlscol "github.com/SiriusScan/ping++/pkg/protocol/tls"
	"github.com/SiriusScan/ping++/pkg/protocol/vnc"
)

// NewRegistry registers discovery and all baseline protocol collectors.
func NewRegistry() *engine.Registry {
	return engine.BuildDefaultRegistry(
		icmp.Register,
		tcp.Register,
		tlscol.Register,
		httpcol.Register,
		sshcol.Register,
		smbcol.Register,
		ftp.Register,
		smtp.Register,
		pop3.Register,
		imap.Register,
		telnet.Register,
		mysql.Register,
		mssql.Register,
		postgres.Register,
		redis.Register,
		mongodb.Register,
		memcached.Register,
		ldap.Register,
		rdp.Register,
		dns.Register,
		snmp.Register,
		mqtt.Register,
		vnc.Register,
		socks.Register,
		amqp.Register,
		tcpstack.Register,
	)
}
