// Package smbcol collects SMB/NTLM observations without emitting OS claims.
package smbcol

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const collectorID = "collect.smb"

// Collector gathers SMB negotiation / NTLM target info as observations.
type Collector struct {
	timeout time.Duration
}

// New creates an SMB collector.
func New(cfg engine.Config) (*Collector, error) {
	return &Collector{timeout: engine.EffectiveTimeout(cfg)}, nil
}

// Metadata implements engine.Collector.
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID: collectorID, Stage: engine.StageCollect,
		Transports:   []model.Transport{model.TransportTCP},
		DefaultPorts: []uint16{445}, Cost: 3, Priority: 70,
		SideEffectRisk: "low", SafeForOT: true,
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
		return engine.CollectorResult{}, fmt.Errorf("smb: endpoint required")
	}
	ip := in.Endpoint.Address
	port := int(in.Endpoint.Port)
	if port == 0 {
		port = 445
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID:      fmt.Sprintf("obs:smb:%s:%d:%d", ip, port, time.Now().UnixNano()),
		ProbeID: collectorID, ObservationType: model.ObservationSMB,
		Endpoint: &ref, Timestamp: time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("smb:%s:%d", ip, port),
	}
	if in.Asset != nil {
		obs.AssetID = in.Asset.ID
	}

	options := gosmb.Options{
		Host: ip, Port: port, DialTimeout: c.timeout,
		Initiator: &spnego.NTLMInitiator{User: "", Password: "", Domain: ""},
	}
	session, err := gosmb.NewConnection(options)
	payload := model.SMBObservation{}
	if err != nil {
		errStr := err.Error()
		if !SMBProtocolEvidence(errStr) {
			obs.Error = errStr
			obs.Completeness = "none"
			out := engine.OutcomeFromError(err)
			if out == engine.OutcomeInternalError {
				out = engine.OutcomeNoMatch
			}
			return engine.CollectorResult{Outcome: out, Protocol: "smb", Observations: []model.ObservationRecord{obs}}, nil
		}
		obs.Completeness = "partial"
		if session != nil {
			fillSMB(session, &payload)
			session.Close()
		}
	} else {
		defer session.Close()
		fillSMB(session, &payload)
		obs.Completeness = "full"
	}
	if err := obs.SetPayload(payload); err != nil {
		return engine.CollectorResult{}, err
	}
	return engine.CollectorResult{Outcome: engine.OutcomeSuccess, Protocol: "smb", Observations: []model.ObservationRecord{obs}}, nil
}

// SMBProtocolEvidence reports whether an error still proves SMB was reached
// (auth denied, logon failure, or signing required) rather than a lookalike.
func SMBProtocolEvidence(errStr string) bool {
	if errStr == "" {
		return false
	}
	u := strings.ToUpper(errStr)
	if strings.Contains(u, "STATUS_ACCESS_DENIED") ||
		strings.Contains(u, "STATUS_LOGON_FAILURE") ||
		strings.Contains(u, "STATUS_ACCOUNT_DISABLED") ||
		strings.Contains(u, "STATUS_LOGON_TYPE_NOT_GRANTED") {
		return true
	}
	l := strings.ToLower(errStr)
	return strings.Contains(l, "logon failed") || strings.Contains(l, "signing")
}

func fillSMB(session *gosmb.Connection, payload *model.SMBObservation) {
	if session.IsSigningRequired() {
		payload.Signing = "required"
	} else {
		payload.Signing = "not_required"
	}
	ti := session.GetTargetInfo()
	if ti == nil {
		return
	}
	osBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(osBytes, ti.OS)
	major, minor := osBytes[0], osBytes[1]
	build := binary.LittleEndian.Uint16(osBytes[2:4])
	if build > 0 && major > 0 {
		payload.OSBuild = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}
	if ti.GuessedOSVersion != "" {
		payload.OSVersionHint = ti.GuessedOSVersion
	}
	payload.ComputerName = ti.NBComputerName
	payload.Domain = ti.NBDomainName
}

// Register adds the SMB collector.
func Register(r *engine.Registry) {
	r.MustRegister(collectorID, func(cfg engine.Config) (engine.Collector, error) {
		return New(cfg)
	})
}
