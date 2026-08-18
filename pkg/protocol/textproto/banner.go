// Package textproto provides helpers for banner-oriented text protocols.
package textproto

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

// BannerObservation is a generic text-protocol payload.
type BannerObservation struct {
	Banner   string   `json:"banner,omitempty"`
	Reply    string   `json:"reply,omitempty"`
	Features []string `json:"features,omitempty"`
}

// CollectBanner dials, reads an initial line, optionally writes a command and reads more.
func CollectBanner(ctx context.Context, in engine.CollectorInput, timeout time.Duration, probeID, obsType string, command string) (model.ObservationRecord, error) {
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID:      fmt.Sprintf("obs:%s:%s:%d:%d", probeID, in.Endpoint.Address, in.Endpoint.Port, time.Now().UnixNano()),
		ProbeID: probeID, ObservationType: obsType,
		Endpoint: &ref, Timestamp: time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("%s:%s:%d", probeID, in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	conn, err := dialText(ctx, in, timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return obs, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	payload := BannerObservation{Banner: strings.TrimSpace(banner)}
	if command != "" {
		_, _ = conn.Write([]byte(command))
		var lines []string
		for i := 0; i < 32; i++ {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			lines = append(lines, line)
			if isFinalReply(line) {
				break
			}
		}
		payload.Reply = strings.Join(lines, "\n")
		payload.Features = extractFeatures(lines)
	}
	if payload.Banner == "" && payload.Reply == "" {
		obs.Completeness = "none"
		obs.Error = "no banner"
	} else {
		obs.Completeness = "full"
	}
	_ = obs.SetPayload(payload)
	return obs, nil
}

func dialText(ctx context.Context, in engine.CollectorInput, timeout time.Duration) (net.Conn, error) {
	if UseTLS(in) {
		serverName := in.Endpoint.Address
		if in.Target != nil && in.Target.Hostname != "" {
			serverName = in.Target.Hostname
		}
		return transport.DialTLS(ctx, in.Endpoint.Address, in.Endpoint.Port, serverName, timeout)
	}
	return transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, timeout)
}

// UseTLS reports implicit TLS (port 465/993/995) or Extra/prior TLS state.
func UseTLS(in engine.CollectorInput) bool {
	if in.Extra != nil && in.Extra["tls"] == "1" {
		return true
	}
	if in.Endpoint == nil {
		return false
	}
	switch in.Endpoint.Port {
	case 465, 993, 995:
		return true
	}
	if in.State != nil {
		return in.State.HasProtocol(in.Endpoint.Key(), "tls")
	}
	return false
}

func isFinalReply(line string) bool {
	if len(line) < 3 || line[0] < '1' || line[0] > '5' {
		return false
	}
	if len(line) == 3 {
		return isStatusCode(line)
	}
	if line[3] == '-' {
		return false
	}
	return isStatusCode(line[:3])
}

func isStatusCode(s string) bool {
	if len(s) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// HasCode reports whether reply lines include a complete SMTP/FTP status.
func HasCode(text string, code string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, code+" ") || strings.HasPrefix(line, code+"-") || line == code {
			return true
		}
	}
	return false
}

// CollectBannerResult is CollectBanner plus a protocol match decision.
func CollectBannerResult(ctx context.Context, in engine.CollectorInput, timeout time.Duration, probeID, obsType, protocol, command string, match func(BannerObservation) bool) (engine.CollectorResult, error) {
	obs, err := CollectBanner(ctx, in, timeout, probeID, obsType, command)
	if err != nil {
		return engine.CollectorResult{Outcome: engine.OutcomeFromError(err), Protocol: protocol, Observations: []model.ObservationRecord{obs}}, err
	}
	var payload BannerObservation
	_ = obs.DecodePayload(&payload)
	if obs.Error != "" && payload.Banner == "" {
		out := engine.OutcomeFromError(fmt.Errorf("%s", obs.Error))
		if out == engine.OutcomeInternalError {
			out = engine.OutcomeNoMatch
		}
		return engine.CollectorResult{Outcome: out, Protocol: protocol, Observations: []model.ObservationRecord{obs}}, nil
	}
	if match != nil && match(payload) {
		return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: protocol, Observations: []model.ObservationRecord{obs}}, nil
	}
	obs.Completeness = "none"
	if obs.Error == "" {
		obs.Error = "no match"
	}
	return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: protocol, Observations: []model.ObservationRecord{obs}}, nil
}

func PrefixMatch(prefix string) func(BannerObservation) bool {
	return func(p BannerObservation) bool {
		return strings.HasPrefix(p.Banner, prefix) || strings.HasPrefix(p.Reply, prefix)
	}
}

func extractFeatures(lines []string) []string {
	var out []string
	for _, line := range lines {
		// SMTP: "250-SIZE 52428800" or "250 STARTTLS"
		if len(line) > 4 && (line[3] == '-' || line[3] == ' ') {
			feat := strings.TrimSpace(line[4:])
			if feat != "" {
				out = append(out, strings.Fields(feat)[0])
			}
		}
	}
	return out
}

// Observation type constants for text protocols.
const (
	ObsFTP    = "ftp"
	ObsSMTP   = "smtp"
	ObsPOP3   = "pop3"
	ObsIMAP   = "imap"
	ObsTelnet = "telnet"
)
