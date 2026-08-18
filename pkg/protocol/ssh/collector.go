// Package sshcol collects SSH protocol observations (capabilities + banner).
// Product/OS claims are produced by the fingerprint engine, not this collector.
package sshcol

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const collectorID = "collect.ssh"

// Collector gathers SSH banners and negotiation algorithm lists.
type Collector struct {
	timeout time.Duration
}

// New creates an SSH collector.
func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}

// Metadata implements engine.Collector.
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID: collectorID, Stage: engine.StageCollect,
		Transports:   []model.Transport{model.TransportTCP},
		DefaultPorts: []uint16{22}, Cost: 2, Priority: 75,
		SideEffectRisk: "low", SafeForOT: true,
	}
}

// Run implements engine.Collector.
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Endpoint == nil {
		return nil, fmt.Errorf("ssh: endpoint required")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, timeout)
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID:      fmt.Sprintf("obs:ssh:%s:%d:%d", in.Endpoint.Address, in.Endpoint.Port, time.Now().UnixNano()),
		ProbeID: collectorID, ObservationType: model.ObservationSSH,
		Endpoint: &ref, Timestamp: time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("ssh:%s:%d", in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return []model.ObservationRecord{obs}, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	payload := model.SSHObservation{}
	if err == nil {
		payload.Banner = strings.TrimSpace(banner)
		if strings.HasPrefix(payload.Banner, "SSH-") {
			parts := strings.SplitN(payload.Banner, "-", 3)
			if len(parts) >= 2 {
				payload.ProtocolVersion = parts[1]
			}
		}
	}

	// Send a client identification to elicit KEXINIT, then parse algorithm lists.
	_, _ = conn.Write([]byte("SSH-2.0-pingpp_0.1\r\n"))
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 16*1024)
	n, _ := reader.Read(buf)
	if n > 0 {
		parseKEXINIT(buf[:n], &payload)
	}
	obs.Completeness = "full"
	if payload.Banner == "" {
		obs.Completeness = "partial"
	}
	if err := obs.SetPayload(payload); err != nil {
		return nil, err
	}
	return []model.ObservationRecord{obs}, nil
}

// parseKEXINIT extracts name-lists from an SSH_MSG_KEXINIT payload if present.
func parseKEXINIT(data []byte, payload *model.SSHObservation) {
	// Find SSH_MSG_KEXINIT (message type 20) after optional packet framing.
	idx := -1
	for i := 0; i+1 < len(data); i++ {
		if data[i] == 20 && i+16 < len(data) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	// Skip message type (1) + cookie (16)
	pos := idx + 1 + 16
	readList := func() []string {
		if pos+4 > len(data) {
			return nil
		}
		length := int(data[pos])<<24 | int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if length < 0 || pos+length > len(data) {
			return nil
		}
		s := string(data[pos : pos+length])
		pos += length
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	payload.KexAlgorithms = readList()
	payload.HostKeyAlgorithms = readList()
	payload.EncryptionAlgorithms = readList() // client-to-server
	_ = readList()                            // server-to-client enc
	payload.MACAlgorithms = readList()
	_ = readList() // s2c mac
	payload.Compression = readList()
}

// Register adds the SSH collector.
func Register(r *engine.Registry) {
	r.MustRegister(collectorID, func(cfg engine.Config) (engine.Collector, error) {
		return New(cfg)
	})
}
