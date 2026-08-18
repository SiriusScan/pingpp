// Package tlscol implements a TLS metadata collector.
// Package name tlscol avoids colliding with crypto/tls.
package tlscol

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const collectorID = "collect.tls"

// Collector gathers TLS negotiation and certificate observations.
type Collector struct {
	timeout time.Duration
}

// New creates a TLS collector.
func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}

// Metadata implements engine.Collector.
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             collectorID,
		Stage:          engine.StageCollect,
		Transports:     []model.Transport{model.TransportTCP},
		DefaultPorts:   []uint16{443, 8443, 993, 995, 465, 636},
		Cost:           3,
		Priority:       70,
		SideEffectRisk: "low",
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
		return engine.CollectorResult{}, fmt.Errorf("tls: endpoint required")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	serverName := ""
	if in.Target != nil && in.Target.Hostname != "" {
		serverName = in.Target.Hostname
	}

	conn, err := transport.DialTLS(ctx, in.Endpoint.Address, in.Endpoint.Port, serverName, timeout)
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID:               fmt.Sprintf("obs:tls:%s:%d:%d", in.Endpoint.Address, in.Endpoint.Port, time.Now().UnixNano()),
		ProbeID:          collectorID,
		ObservationType:  model.ObservationTLS,
		Endpoint:         &ref,
		Timestamp:        time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("tls:%s:%d", in.Endpoint.Address, in.Endpoint.Port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}
	if err != nil {
		obs.Error = err.Error()
		obs.Completeness = "none"
		out := engine.OutcomeFromError(err)
		if out == engine.OutcomeInternalError {
			out = engine.OutcomeNoMatch
		}
		return engine.CollectorResult{
			Outcome:      out,
			Protocol:     "tls",
			Observations: []model.ObservationRecord{obs},
		}, nil
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	payload := model.TLSObservation{
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		ALPN:        state.NegotiatedProtocol,
		ServerName:  serverName,
	}
	for _, cert := range state.PeerCertificates {
		payload.Certificates = append(payload.Certificates, certObs(cert))
	}
	obs.Completeness = "full"
	if err := obs.SetPayload(payload); err != nil {
		return engine.CollectorResult{}, err
	}
	return engine.CollectorResult{
		Outcome:      engine.OutcomeSuccess,
		Protocol:     "tls",
		Observations: []model.ObservationRecord{obs},
	}, nil
}

func certObs(cert *x509.Certificate) model.CertificateObservation {
	sum := sha256.Sum256(cert.Raw)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return model.CertificateObservation{
		SubjectCN:  cert.Subject.CommonName,
		IssuerCN:   cert.Issuer.CommonName,
		SANs:       append([]string(nil), cert.DNSNames...),
		Serial:     cert.SerialNumber.String(),
		NotBefore:  cert.NotBefore.UTC(),
		NotAfter:   cert.NotAfter.UTC(),
		SHA256:     hex.EncodeToString(sum[:]),
		SPKISHA256: hex.EncodeToString(spki[:]),
	}
}

// Register adds the TLS collector.
func Register(r *engine.Registry) {
	r.MustRegister(collectorID, func(cfg engine.Config) (engine.Collector, error) {
		return New(cfg)
	})
}
