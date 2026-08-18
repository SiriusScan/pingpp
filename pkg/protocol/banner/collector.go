// Package banner collects generic first-bytes evidence without claiming a protocol.
package banner

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const (
	collectorID = "collect.banner"
	maxBanner   = 1024
)

// Collector reads unsolicited bytes from a TCP endpoint.
type Collector struct {
	timeout time.Duration
}

// New creates a banner collector.
func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}

// Metadata implements engine.Collector.
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             collectorID,
		Stage:          engine.StageCollect,
		Transports:     []model.Transport{model.TransportTCP},
		Cost:           1,
		Priority:       20,
		SideEffectRisk: "none",
		SafeForOT:      true,
	}
}

// Run implements engine.Collector.
func (c *Collector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := c.RunResult(ctx, in)
	return res.Observations, err
}

// RunResult implements engine.ResultCollector.
func (c *Collector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	if in.Endpoint == nil {
		return engine.CollectorResult{}, fmt.Errorf("banner: endpoint required")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID:               fmt.Sprintf("obs:banner:%s:%d:%d", in.Endpoint.Address, in.Endpoint.Port, time.Now().UnixNano()),
		ProbeID:          collectorID,
		ObservationType:  model.ObservationBanner,
		Endpoint:         &ref,
		Timestamp:        time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("banner:%s:%d", in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}

	conn, err := transport.DialTCP(ctx, in.Endpoint.Address, in.Endpoint.Port, timeout)
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		return engine.CollectorResult{
			Outcome:      engine.OutcomeFromError(err),
			Protocol:     "banner",
			Observations: []model.ObservationRecord{obs},
		}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, maxBanner+1)
	n, readErr := conn.Read(buf)
	if n <= 0 {
		obs.Completeness = "none"
		if readErr != nil && readErr != io.EOF {
			obs.Error = readErr.Error()
		} else {
			obs.Error = "no banner"
		}
		return engine.CollectorResult{
			Outcome:      engine.OutcomeNoMatch,
			Protocol:     "banner",
			Observations: []model.ObservationRecord{obs},
		}, nil
	}
	raw := buf[:n]
	truncated := n > maxBanner
	if truncated {
		raw = buf[:maxBanner]
	}
	payload := model.BannerObservation{
		Text:      printable(raw),
		Hex:       hex.EncodeToString(raw),
		Length:    len(raw),
		Truncated: truncated,
	}
	obs.Completeness = "full"
	_ = obs.SetPayload(payload)
	if in.Artifacts != nil {
		if art, err := in.Artifacts.Put("application/octet-stream", raw, "tcp banner"); err == nil {
			obs.ArtifactIDs = []string{art.ID}
		}
	}
	return engine.CollectorResult{
		Outcome:      engine.OutcomeSuccess,
		Protocol:     "banner",
		Observations: []model.ObservationRecord{obs},
		BytesRead:    int64(len(raw)),
	}, nil
}

func printable(b []byte) string {
	s := string(b)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return '.'
	}, s)
}

// Register adds the banner collector.
func Register(r *engine.Registry) {
	r.MustRegister(collectorID, func(cfg engine.Config) (engine.Collector, error) {
		return New(cfg)
	})
}
