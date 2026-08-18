// Package scan wires collectors into a ready-to-use registry.
// Kept separate from pkg/engine to avoid import cycles with protocol packages.
package scan

import (
	"github.com/SiriusScan/ping++/pkg/discovery/icmp"
	"github.com/SiriusScan/ping++/pkg/discovery/tcp"
	"github.com/SiriusScan/ping++/pkg/engine"
	httpcol "github.com/SiriusScan/ping++/pkg/protocol/http"
	smbcol "github.com/SiriusScan/ping++/pkg/protocol/smb"
	sshcol "github.com/SiriusScan/ping++/pkg/protocol/ssh"
	tlscol "github.com/SiriusScan/ping++/pkg/protocol/tls"
)

// NewRegistry registers discovery and baseline protocol collectors.
func NewRegistry() *engine.Registry {
	return engine.BuildDefaultRegistry(
		icmp.Register,
		tcp.Register,
		tlscol.Register,
		httpcol.Register,
		sshcol.Register,
		smbcol.Register,
	)
}
