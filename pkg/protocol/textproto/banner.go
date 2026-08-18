// Package textproto provides helpers for banner-oriented text protocols.
package textproto

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
	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return obs, nil
	}
	defer conn.Close()
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
			// SMTP EHLO ends with "250 " (space) final line
			if strings.HasPrefix(line, "250 ") {
				break
			}
			if strings.HasPrefix(line, "220 ") && !strings.HasPrefix(command, "EHLO") {
				break
			}
		}
		payload.Reply = strings.Join(lines, "\n")
		payload.Features = extractFeatures(lines)
	}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	return obs, nil
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
