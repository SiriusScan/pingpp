// Package textproto provides helpers for banner-oriented text protocols.
package textproto

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const maxBannerLine = 2048

// BannerObservation is a generic text-protocol payload.
// TLS/STARTTLS flags stay here — not on Asset.
type BannerObservation struct {
	Banner   string   `json:"banner,omitempty"`
	Reply    string   `json:"reply,omitempty"`
	Features []string `json:"features,omitempty"`
	TLS      bool     `json:"tls,omitempty"`
	StartTLS bool     `json:"starttls,omitempty"`
}

// SessionConfig drives CollectSession (greeting, optional hello, optional STARTTLS).
type SessionConfig struct {
	ProbeID      string
	ObsType      string
	Protocol     string
	Hello        string
	Match        func(BannerObservation) bool
	StartTLS     string
	StartTLSOK   func(reply string) bool
	WantStartTLS func(BannerObservation) bool
	PostTLSHello string
	// Tagged reads Hello/STARTTLS/PostTLSHello replies until the IMAP tag.
	Tagged bool
}

// CollectBanner dials, reads an initial line, optionally writes a command and reads more.
func CollectBanner(ctx context.Context, in engine.CollectorInput, timeout time.Duration, probeID, obsType string, command string) (model.ObservationRecord, error) {
	obs := newBannerObs(in, probeID, obsType)
	conn, err := dialText(ctx, in, timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return obs, nil
	}
	defer func() { _ = conn.Close() }()

	payload := BannerObservation{TLS: UseTLS(in)}
	banner, err := readLine(conn, timeout)
	if err != nil && banner == "" {
		obs.Error = err.Error()
		obs.Completeness = "none"
		_ = obs.SetPayload(payload)
		return obs, nil
	}
	payload.Banner = banner
	if command != "" {
		_, _ = conn.Write([]byte(command))
		reply, lines, _ := readSMTPReply(conn, timeout)
		payload.Reply = reply
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

func serverName(in engine.CollectorInput) string {
	if in.Target != nil && in.Target.Hostname != "" {
		return in.Target.Hostname
	}
	if in.Endpoint != nil {
		return in.Endpoint.Address
	}
	return ""
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
		u := strings.ToUpper(line)
		if strings.HasPrefix(u, "* CAPABILITY") {
			fields := strings.Fields(line)
			if len(fields) > 2 {
				out = append(out, fields[2:]...)
			}
		}
	}
	return out
}

func newBannerObs(in engine.CollectorInput, probeID, obsType string) model.ObservationRecord {
	obs := model.ObservationRecord{
		ID:               fmt.Sprintf("obs:%s:%s:%d:%d", probeID, in.Endpoint.Address, in.Endpoint.Port, time.Now().UnixNano()),
		ProbeID:          probeID,
		ObservationType:  obsType,
		Endpoint:         endpointRef(in),
		Timestamp:        time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("%s:%s:%d", probeID, in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	return obs
}

func endpointRef(in engine.CollectorInput) *model.EndpointRef {
	if in.Endpoint == nil {
		return nil
	}
	ref := in.Endpoint.Ref()
	return &ref
}

// CollectSession greets, optionally hellos, matches, then may STARTTLS on the
// same connection. A failed upgrade keeps the plaintext protocol match.
func CollectSession(ctx context.Context, in engine.CollectorInput, timeout time.Duration, cfg SessionConfig) (engine.CollectorResult, error) {
	obs := newBannerObs(in, cfg.ProbeID, cfg.ObsType)
	conn, err := dialText(ctx, in, timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		_ = obs.SetPayload(BannerObservation{})
		out := engine.OutcomeFromError(err)
		if out == engine.OutcomeInternalError {
			out = engine.OutcomeNoMatch
		}
		return engine.CollectorResult{Outcome: out, Protocol: cfg.Protocol, Observations: []model.ObservationRecord{obs}}, nil
	}
	defer func() { _ = conn.Close() }()

	payload := BannerObservation{TLS: UseTLS(in)}
	banner, err := readLine(conn, timeout)
	if err != nil && banner == "" {
		obs.Error = err.Error()
		obs.Completeness = "none"
		_ = obs.SetPayload(payload)
		out := engine.OutcomeFromError(err)
		if out == engine.OutcomeInternalError {
			out = engine.OutcomeNoMatch
		}
		return engine.CollectorResult{Outcome: out, Protocol: cfg.Protocol, Observations: []model.ObservationRecord{obs}}, nil
	}
	payload.Banner = banner

	if cfg.Hello != "" {
		_, _ = conn.Write([]byte(cfg.Hello))
		reply, lines, _ := readCommandReply(conn, timeout, cfg.Hello, cfg.Tagged)
		payload.Reply = reply
		payload.Features = extractFeatures(lines)
	}

	if payload.Banner == "" && payload.Reply == "" {
		obs.Completeness = "none"
		obs.Error = "no banner"
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: cfg.Protocol, Observations: []model.ObservationRecord{obs}}, nil
	}

	if cfg.Match == nil || !cfg.Match(payload) {
		obs.Completeness = "none"
		if obs.Error == "" {
			obs.Error = "no match"
		}
		_ = obs.SetPayload(payload)
		return engine.CollectorResult{Outcome: engine.OutcomeNoMatch, Protocol: cfg.Protocol, Observations: []model.ObservationRecord{obs}}, nil
	}

	if !payload.TLS && cfg.StartTLS != "" && (cfg.WantStartTLS == nil || cfg.WantStartTLS(payload)) {
		conn, payload = tryStartTLS(ctx, conn, in, timeout, cfg, payload)
	}

	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: cfg.Protocol, Observations: []model.ObservationRecord{obs}}, nil
}

func tryStartTLS(ctx context.Context, conn net.Conn, in engine.CollectorInput, timeout time.Duration, cfg SessionConfig, payload BannerObservation) (net.Conn, BannerObservation) {
	if _, err := conn.Write([]byte(cfg.StartTLS)); err != nil {
		return conn, payload
	}
	reply, _, err := readCommandReply(conn, timeout, cfg.StartTLS, cfg.Tagged)
	if err != nil || reply == "" {
		return conn, payload
	}
	if cfg.StartTLSOK != nil && !cfg.StartTLSOK(reply) {
		if payload.Reply != "" {
			payload.Reply = payload.Reply + "\n" + reply
		} else {
			payload.Reply = reply
		}
		return conn, payload
	}
	upgraded, err := transport.UpgradeTLS(ctx, conn, serverName(in), timeout)
	if err != nil {
		return conn, payload
	}
	conn = upgraded
	payload.TLS = true
	payload.StartTLS = true
	if payload.Reply != "" {
		payload.Reply = payload.Reply + "\n" + reply
	} else {
		payload.Reply = reply
	}
	if cfg.PostTLSHello == "" {
		return conn, payload
	}
	if _, err := conn.Write([]byte(cfg.PostTLSHello)); err != nil {
		return conn, payload
	}
	post, lines, _ := readCommandReply(conn, timeout, cfg.PostTLSHello, cfg.Tagged)
	if post != "" {
		payload.Reply = payload.Reply + "\n" + post
		if feats := extractFeatures(lines); len(feats) > 0 {
			payload.Features = append(payload.Features, feats...)
		}
	}
	return conn, payload
}

func readCommandReply(conn net.Conn, timeout time.Duration, command string, tagged bool) (string, []string, error) {
	if tagged {
		return readIMAPReply(conn, imapTag(command), timeout)
	}
	trim := strings.ToUpper(strings.TrimSpace(command))
	if strings.HasPrefix(trim, "STLS") {
		line, err := readLine(conn, timeout)
		if line == "" {
			return "", nil, err
		}
		return line, []string{line}, err
	}
	return readSMTPReply(conn, timeout)
}

func imapTag(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func readIMAPReply(conn net.Conn, tag string, timeout time.Duration) (string, []string, error) {
	var lines []string
	var lastErr error
	for i := 0; i < 32; i++ {
		line, err := readLine(conn, timeout)
		if line != "" {
			lines = append(lines, line)
		}
		if err != nil {
			lastErr = err
			break
		}
		fields := strings.Fields(line)
		if tag != "" && len(fields) >= 1 && fields[0] == tag {
			break
		}
		if tag == "" {
			break
		}
	}
	return strings.Join(lines, "\n"), lines, lastErr
}

func readSMTPReply(conn net.Conn, timeout time.Duration) (string, []string, error) {
	var lines []string
	var lastErr error
	for i := 0; i < 32; i++ {
		line, err := readLine(conn, timeout)
		if line != "" {
			lines = append(lines, line)
		}
		if err != nil {
			lastErr = err
			break
		}
		if isFinalReply(line) {
			break
		}
	}
	return strings.Join(lines, "\n"), lines, lastErr
}

func readLine(conn net.Conn, timeout time.Duration) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var b strings.Builder
	tmp := make([]byte, 1)
	for b.Len() < maxBannerLine {
		n, err := conn.Read(tmp)
		if n > 0 {
			if tmp[0] == '\n' {
				return strings.TrimSpace(b.String()), nil
			}
			if tmp[0] != '\r' {
				b.WriteByte(tmp[0])
			}
			continue
		}
		if err != nil {
			s := strings.TrimSpace(b.String())
			if s != "" {
				return s, err
			}
			return "", err
		}
	}
	return strings.TrimSpace(b.String()), nil
}

// Observation type constants for text protocols.
const (
	ObsFTP    = "ftp"
	ObsSMTP   = "smtp"
	ObsPOP3   = "pop3"
	ObsIMAP   = "imap"
	ObsTelnet = "telnet"
)
