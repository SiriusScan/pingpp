// Package output renders scan results in canonical and legacy formats.
package output

import (
	"encoding/json"

	"github.com/SiriusScan/ping++/pkg/model"
)

// LegacyResult mirrors the historical runner.Result shape for compatibility.
type LegacyResult struct {
	IP           string            `json:"ip"`
	Hostname     string            `json:"hostname,omitempty"`
	IsAlive      bool              `json:"is_alive"`
	OSFamily     string            `json:"os_family"`
	OSVersion    string            `json:"os_version,omitempty"`
	OSConfidence float64           `json:"os_confidence,omitempty"`
	OpenPorts    []int             `json:"open_ports,omitempty"`
	SSHBanner    string            `json:"ssh_banner,omitempty"`
	HTTPServer   string            `json:"http_server,omitempty"`
	SMBDialect   string            `json:"smb_dialect,omitempty"`
	Details      map[string]string `json:"details,omitempty"`
}

// ToLegacy derives a compatibility Result from the canonical Asset model.
// New internal code must not consume LegacyResult.
func ToLegacy(asset *model.Asset, alive bool) LegacyResult {
	lr := LegacyResult{
		IsAlive:  alive,
		OSFamily: "unknown",
		Details:  map[string]string{},
	}
	if asset == nil {
		return lr
	}
	if len(asset.Addresses) > 0 {
		lr.IP = asset.Addresses[0].IP
	}
	if len(asset.Hostnames) > 0 {
		lr.Hostname = asset.Hostnames[0]
	}
	for _, ep := range asset.Endpoints {
		if ep.State == model.EndpointOpen {
			lr.OpenPorts = append(lr.OpenPorts, int(ep.Port))
		}
	}
	for _, c := range asset.Claims {
		if c.Kind == model.ClaimOS {
			if c.Score >= lr.OSConfidence*100 || lr.OSFamily == "unknown" {
				lr.OSFamily = first(c.Family, c.Product, "unknown")
				lr.OSVersion = c.Version
				lr.OSConfidence = c.Score / 100
			}
		}
	}
	for _, o := range asset.Observations {
		switch o.ObservationType {
		case model.ObservationSSH:
			var p model.SSHObservation
			_ = o.DecodePayload(&p)
			if p.Banner != "" && lr.SSHBanner == "" {
				lr.SSHBanner = p.Banner
			}
		case model.ObservationHTTP:
			var p model.HTTPObservation
			_ = o.DecodePayload(&p)
			if p.Server != "" && lr.HTTPServer == "" {
				lr.HTTPServer = p.Server
			}
		case model.ObservationSMB:
			var p model.SMBObservation
			_ = o.DecodePayload(&p)
			if p.Dialect != "" && lr.SMBDialect == "" {
				lr.SMBDialect = p.Dialect
			}
		}
	}
	return lr
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// AssetJSON marshals the canonical asset.
func AssetJSON(asset *model.Asset) ([]byte, error) {
	return json.Marshal(asset)
}

// ToSiriusHost maps an asset to the minimal Sirius host fields.
func ToSiriusHost(asset *model.Asset, alive bool) map[string]interface{} {
	lr := ToLegacy(asset, alive)
	return map[string]interface{}{
		"ip":         lr.IP,
		"hostname":   lr.Hostname,
		"os":         lr.OSFamily,
		"osVersion":  lr.OSVersion,
		"confidence": lr.OSConfidence,
		"endpoints":  assetEndpoints(asset),
		"claims":     assetClaims(asset),
	}
}

func assetEndpoints(asset *model.Asset) []map[string]interface{} {
	if asset == nil {
		return nil
	}
	var out []map[string]interface{}
	for _, ep := range asset.Endpoints {
		out = append(out, map[string]interface{}{
			"address":   ep.Address,
			"port":      ep.Port,
			"transport": ep.Transport,
			"state":     ep.State,
			"execution": ep.Execution,
		})
	}
	return out
}

func assetClaims(asset *model.Asset) []map[string]interface{} {
	if asset == nil {
		return nil
	}
	var out []map[string]interface{}
	for _, c := range asset.Claims {
		out = append(out, map[string]interface{}{
			"kind":       c.Kind,
			"vendor":     c.Vendor,
			"product":    c.Product,
			"version":    c.Version,
			"confidence": c.Confidence,
			"score":      c.Score,
		})
	}
	return out
}
