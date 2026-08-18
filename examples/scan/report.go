package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/output"
	"github.com/SiriusScan/ping++/pkg/protocol/textproto"
)

// EnumReport is a real-world enumeration result: confirmed services first.
type EnumReport struct {
	Target                string       `json:"target"`
	Profile               string       `json:"profile"`
	Address               string       `json:"address,omitempty"`
	Hostname              string       `json:"hostname,omitempty"`
	Alive                 bool         `json:"alive"`
	Reachability          string       `json:"reachability,omitempty"`
	ReachabilityReasons   []string     `json:"reachability_reasons,omitempty"`
	OS                    string       `json:"os,omitempty"`
	OSVersion             string       `json:"os_version,omitempty"`
	Elapsed               string       `json:"elapsed"`
	ProbesUsed            int          `json:"probes_used"`
	ProbesBudget          int          `json:"probes_budget"`
	ConnectOpen           int          `json:"connect_open"`
	Confirmed             []ServiceHit `json:"confirmed"`
	ConnectOnly           []uint16     `json:"connect_only,omitempty"`
	LikelyConnectAcceptor bool         `json:"likely_connect_acceptor"`
	Claims                []ClaimHit   `json:"claims,omitempty"`
}

// ServiceHit is a protocol-confirmed endpoint.
type ServiceHit struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Summary  string `json:"summary"`
}

// ClaimHit is a fingerprint inference worth showing in an enum report.
type ClaimHit struct {
	Kind       string  `json:"kind"`
	Product    string  `json:"product,omitempty"`
	Family     string  `json:"family,omitempty"`
	Score      float64 `json:"score"`
	Confidence string  `json:"confidence"`
}

func buildReport(input string, profile engine.ProfileName, res *engine.ScanResult, elapsed time.Duration) EnumReport {
	alive := res.State.Reachability.State == model.ReachabilityConfirmed ||
		res.State.Reachability.State == model.ReachabilityProbable
	legacy := output.ToLegacy(res.Asset, alive)

	r := EnumReport{
		Target:              input,
		Profile:             string(profile),
		Address:             legacy.IP,
		Hostname:            legacy.Hostname,
		Alive:               alive,
		Reachability:        string(res.State.Reachability.State),
		ReachabilityReasons: append([]string(nil), res.State.Reachability.Reasons...),
		OS:                  legacy.OSFamily,
		OSVersion:           legacy.OSVersion,
		Elapsed:             elapsed.Round(time.Millisecond).String(),
		ProbesUsed:          res.State.Budget.ProbesUsed,
		ProbesBudget:        res.State.Budget.MaxProbesPerHost,
	}

	confirmedByPort := map[uint16][]ServiceHit{}
	for _, o := range res.Asset.Observations {
		hit, ok := confirmedService(o)
		if !ok {
			continue
		}
		confirmedByPort[hit.Port] = append(confirmedByPort[hit.Port], hit)
	}
	for port, hits := range confirmedByPort {
		r.Confirmed = append(r.Confirmed, mergeHits(port, hits))
	}
	sort.Slice(r.Confirmed, func(i, j int) bool { return r.Confirmed[i].Port < r.Confirmed[j].Port })

	confirmedPorts := map[uint16]bool{}
	for _, h := range r.Confirmed {
		confirmedPorts[h.Port] = true
	}
	for _, ep := range res.Asset.Endpoints {
		if ep.Transport != model.TransportTCP {
			continue
		}
		switch ep.State {
		case model.EndpointOpen:
			r.ConnectOpen++
			if !confirmedPorts[ep.Port] {
				// Protocol upgraded the endpoint; still show it as confirmed-only.
			}
		case model.EndpointResponsive:
			r.ConnectOpen++
			if !confirmedPorts[ep.Port] {
				r.ConnectOnly = append(r.ConnectOnly, ep.Port)
			}
		}
	}
	sort.Slice(r.ConnectOnly, func(i, j int) bool { return r.ConnectOnly[i] < r.ConnectOnly[j] })
	r.LikelyConnectAcceptor = r.ConnectOpen >= 15 && len(r.Confirmed) > 0 &&
		len(r.ConnectOnly)*2 >= r.ConnectOpen

	for _, c := range res.Asset.Claims {
		r.Claims = append(r.Claims, ClaimHit{
			Kind:       string(c.Kind),
			Product:    firstNonEmpty(c.Product, c.Value),
			Family:     c.Family,
			Score:      c.Score,
			Confidence: string(c.Confidence),
		})
	}
	return r
}

func mergeHits(port uint16, hits []ServiceHit) ServiceHit {
	if len(hits) == 1 {
		return hits[0]
	}
	protos := make([]string, 0, len(hits))
	parts := make([]string, 0, len(hits))
	seen := map[string]bool{}
	for _, h := range hits {
		if !seen[h.Protocol] {
			seen[h.Protocol] = true
			protos = append(protos, h.Protocol)
		}
		if h.Summary != "" {
			parts = append(parts, h.Summary)
		}
	}
	return ServiceHit{
		Port:     port,
		Protocol: strings.Join(protos, "+"),
		Summary:  strings.Join(parts, "; "),
	}
}

func confirmedService(o model.ObservationRecord) (ServiceHit, bool) {
	if o.Error != "" || o.Endpoint == nil {
		return ServiceHit{}, false
	}
	if o.ObservationType == model.ObservationTCPEndpoint || o.ObservationType == model.ObservationICMPEcho {
		return ServiceHit{}, false
	}
	summary := serviceSummary(o)
	if summary == "" {
		return ServiceHit{}, false
	}
	return ServiceHit{
		Port:     o.Endpoint.Port,
		Protocol: o.ObservationType,
		Summary:  summary,
	}, true
}

func serviceSummary(o model.ObservationRecord) string {
	switch o.ObservationType {
	case model.ObservationHTTP:
		var p model.HTTPObservation
		if o.DecodePayload(&p) != nil || p.StatusCode == 0 {
			return ""
		}
		s := fmt.Sprintf("HTTP %d", p.StatusCode)
		if p.Server != "" {
			s += " server=" + p.Server
		}
		if p.Title != "" {
			s += " title=" + strconvQuote(p.Title)
		}
		return s
	case model.ObservationTLS:
		var p model.TLSObservation
		if o.DecodePayload(&p) != nil || len(p.Certificates) == 0 {
			return ""
		}
		c := p.Certificates[0]
		return fmt.Sprintf("tls cn=%s issuer=%s", strconvQuote(c.SubjectCN), strconvQuote(c.IssuerCN))
	case model.ObservationSSH:
		var p model.SSHObservation
		if o.DecodePayload(&p) != nil || p.Banner == "" {
			return ""
		}
		return p.Banner
	case model.ObservationSMB:
		var p model.SMBObservation
		if o.DecodePayload(&p) != nil || p.Dialect == "" {
			return ""
		}
		return "smb dialect=" + p.Dialect
	case textproto.ObsFTP, textproto.ObsSMTP, textproto.ObsPOP3, textproto.ObsIMAP, textproto.ObsTelnet:
		var p textproto.BannerObservation
		if o.DecodePayload(&p) != nil || p.Banner == "" {
			return ""
		}
		return p.Banner
	case "dns":
		var p struct {
			Responded bool     `json:"responded"`
			Answers   []string `json:"answers"`
		}
		if o.DecodePayload(&p) != nil || !p.Responded {
			return ""
		}
		return fmt.Sprintf("dns answers=%d", len(p.Answers))
	case "redis":
		var p struct {
			Pong    bool   `json:"pong"`
			Version string `json:"version"`
		}
		if o.DecodePayload(&p) != nil || (!p.Pong && p.Version == "") {
			return ""
		}
		if p.Version != "" {
			return "redis " + p.Version
		}
		return "redis PONG"
	case "mysql":
		var p struct {
			ServerVersion string `json:"server_version"`
		}
		if o.DecodePayload(&p) != nil || p.ServerVersion == "" {
			return ""
		}
		return "mysql " + p.ServerVersion
	default:
		var generic map[string]any
		if json.Unmarshal(o.Payload, &generic) != nil {
			return ""
		}
		if responded, _ := generic["responded"].(bool); responded {
			return o.ObservationType + " responded"
		}
		if banner, _ := generic["banner"].(string); banner != "" {
			return banner
		}
		if ver, _ := generic["version"].(string); ver != "" {
			return o.ObservationType + " " + ver
		}
		if ver, _ := generic["server_version"].(string); ver != "" {
			return o.ObservationType + " " + ver
		}
		return ""
	}
}

func (r EnumReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "enumeration  %s\n", r.Target)
	if r.Hostname != "" && r.Hostname != r.Target {
		fmt.Fprintf(&b, "hostname     %s\n", r.Hostname)
	}
	if r.Address != "" {
		fmt.Fprintf(&b, "address      %s\n", r.Address)
	}
	fmt.Fprintf(&b, "profile      %s\n", r.Profile)
	fmt.Fprintf(&b, "elapsed      %s\n", r.Elapsed)
	fmt.Fprintf(&b, "alive        %t\n", r.Alive)
	if r.Reachability != "" {
		reason := strings.Join(r.ReachabilityReasons, ", ")
		if reason != "" {
			fmt.Fprintf(&b, "reachability %s (%s)\n", r.Reachability, reason)
		} else {
			fmt.Fprintf(&b, "reachability %s\n", r.Reachability)
		}
	}
	osLine := r.OS
	if r.OSVersion != "" {
		osLine += " " + r.OSVersion
	}
	if osLine == "" {
		osLine = "unknown"
	}
	fmt.Fprintf(&b, "os           %s\n", osLine)
	fmt.Fprintf(&b, "probes       %d / %d\n", r.ProbesUsed, r.ProbesBudget)

	fmt.Fprintf(&b, "\nconfirmed services  %d\n", len(r.Confirmed))
	if len(r.Confirmed) == 0 {
		b.WriteString("  (none — TCP connect is not treated as a service)\n")
	}
	for _, s := range r.Confirmed {
		fmt.Fprintf(&b, "  %5d/tcp  %-10s  %s\n", s.Port, s.Protocol, s.Summary)
	}

	fmt.Fprintf(&b, "\nconnect-only ports  %d of %d TCP connects\n", len(r.ConnectOnly), r.ConnectOpen)
	if r.LikelyConnectAcceptor {
		b.WriteString("  note: most connects succeeded without a protocol — likely NLB/firewall accept-all\n")
	}
	if len(r.ConnectOnly) > 0 && len(r.ConnectOnly) <= 16 {
		fmt.Fprintf(&b, "  %s\n", joinPorts(r.ConnectOnly))
	} else if len(r.ConnectOnly) > 16 {
		fmt.Fprintf(&b, "  %s … (%d total)\n", joinPorts(r.ConnectOnly[:12]), len(r.ConnectOnly))
	}

	if len(r.Claims) > 0 {
		b.WriteString("\nclaims\n")
		for _, c := range r.Claims {
			label := firstNonEmpty(c.Product, c.Family)
			fmt.Fprintf(&b, "  %-12s %-20s score=%.0f %s\n", c.Kind, label, c.Score, c.Confidence)
		}
	}
	return b.String()
}

func joinPorts(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ", ")
}

func strconvQuote(s string) string {
	return `"` + s + `"`
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
