package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

// ScanDocument is the full library result for a single target.
// Downstream tools should consume this object, not a summarized view.
type ScanDocument struct {
	Target  string       `json:"target"`
	Profile string       `json:"profile"`
	Elapsed string       `json:"elapsed"`
	State   StateDump    `json:"state"`
	Asset   *model.Asset `json:"asset"`
}

// StateDump is ScanState without the mutex.
type StateDump struct {
	AssetID      string             `json:"asset_id"`
	Reachability model.Reachability `json:"reachability"`
	ProbesUsed   int                `json:"probes_used"`
	MaxProbes    int                `json:"max_probes"`
	Completed    []string           `json:"completed"`
}

func buildDocument(input string, profile engine.ProfileName, res *engine.ScanResult, elapsed time.Duration) ScanDocument {
	completed := make([]string, 0, len(res.State.Completed))
	for id, ok := range res.State.Completed {
		if ok {
			completed = append(completed, id)
		}
	}
	sort.Strings(completed)
	return ScanDocument{
		Target:  input,
		Profile: string(profile),
		Elapsed: elapsed.Round(time.Millisecond).String(),
		State: StateDump{
			AssetID:      res.State.AssetID,
			Reachability: res.State.Reachability,
			ProbesUsed:   res.State.Budget.ProbesUsed,
			MaxProbes:    res.State.Budget.MaxProbesPerHost,
			Completed:    completed,
		},
		Asset: res.Asset,
	}
}

func writeJSON(w io.Writer, docs []ScanDocument) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	payload := any(docs[0])
	if len(docs) > 1 {
		payload = docs
	}
	return enc.Encode(payload)
}

func writeText(w io.Writer, docs []ScanDocument, verbose bool) error {
	for i, doc := range docs {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		text := doc.Text()
		if verbose {
			text = doc.Verbose()
		}
		if _, err := fmt.Fprint(w, text); err != nil {
			return err
		}
	}
	return nil
}

// Text is the default human-readable report: host summary plus every
// positive finding (open/responsive endpoints, protocol matches, fingerprint
// claims, and successful observation payloads). Negative/no-match probes
// are omitted.
func (d ScanDocument) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", d.Target)
	fmt.Fprintf(&b, "  profile       %s\n", d.Profile)
	fmt.Fprintf(&b, "  elapsed       %s\n", d.Elapsed)
	reasons := strings.Join(d.State.Reachability.Reasons, ", ")
	if reasons == "" {
		fmt.Fprintf(&b, "  reachability  %s\n", empty(string(d.State.Reachability.State)))
	} else {
		fmt.Fprintf(&b, "  reachability  %s  (%s)\n", d.State.Reachability.State, reasons)
	}
	fmt.Fprintf(&b, "  probes        %d / %d\n", d.State.ProbesUsed, d.State.MaxProbes)
	if d.Asset != nil {
		ips := make([]string, 0, len(d.Asset.Addresses))
		for _, a := range d.Asset.Addresses {
			ips = append(ips, a.IP)
		}
		if len(ips) > 0 {
			fmt.Fprintf(&b, "  addresses     %s\n", strings.Join(ips, ", "))
		}
		if len(d.Asset.Hostnames) > 0 {
			fmt.Fprintf(&b, "  hostnames     %s\n", strings.Join(d.Asset.Hostnames, ", "))
		}
	}

	if d.Asset == nil {
		fmt.Fprintf(&b, "\nfindings\n  none\n")
		return b.String()
	}

	hostClaims, hostObs := hostFindings(d.Asset)
	eps := positiveEndpoints(d.Asset)
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Address != eps[j].Address {
			return eps[i].Address < eps[j].Address
		}
		if eps[i].Transport != eps[j].Transport {
			return eps[i].Transport < eps[j].Transport
		}
		return eps[i].Port < eps[j].Port
	})

	fmt.Fprintf(&b, "\nfindings\n")
	if len(hostClaims) == 0 && len(hostObs) == 0 && len(eps) == 0 {
		fmt.Fprintf(&b, "  none\n")
		return b.String()
	}
	if len(hostClaims) > 0 || len(hostObs) > 0 {
		fmt.Fprintf(&b, "  host\n")
		writeClaimLines(&b, hostClaims, "    ")
		for _, line := range hostObs {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	for _, ep := range eps {
		fmt.Fprintf(&b, "  %s/%-5d %-12s %s\n", ep.Transport, ep.Port, ep.State, ep.Address)
		claims := claimsForEndpoint(d.Asset, ep)
		obs := observationsForEndpoint(d.Asset, ep)
		writeClaimLines(&b, claims, "    ")
		for _, line := range obs {
			fmt.Fprintf(&b, "    %s\n", line)
		}
		if len(claims) == 0 && len(obs) == 0 && ep.State == model.EndpointResponsive {
			fmt.Fprintf(&b, "    tcp accept; no protocol match\n")
		}
	}
	return b.String()
}

// Verbose is the complete diagnostic dump (every endpoint, observation, claim).
func (d ScanDocument) Verbose() string {
	var b strings.Builder
	fmt.Fprintf(&b, "target        %s\n", d.Target)
	fmt.Fprintf(&b, "profile       %s\n", d.Profile)
	fmt.Fprintf(&b, "elapsed       %s\n", d.Elapsed)
	fmt.Fprintf(&b, "asset_id      %s\n", d.State.AssetID)
	fmt.Fprintf(&b, "reachability  %s (%s)\n", d.State.Reachability.State, strings.Join(d.State.Reachability.Reasons, ", "))
	fmt.Fprintf(&b, "probes        %d / %d\n", d.State.ProbesUsed, d.State.MaxProbes)
	if d.Asset != nil {
		fmt.Fprintf(&b, "hostnames     %s\n", strings.Join(d.Asset.Hostnames, ", "))
		ips := make([]string, 0, len(d.Asset.Addresses))
		for _, a := range d.Asset.Addresses {
			ips = append(ips, a.IP)
		}
		fmt.Fprintf(&b, "addresses     %s\n", strings.Join(ips, ", "))
	}
	fmt.Fprintf(&b, "completed     %s\n", strings.Join(d.State.Completed, ", "))

	if d.Asset == nil {
		return b.String()
	}

	fmt.Fprintf(&b, "\nendpoints (%d)\n", len(d.Asset.Endpoints))
	for _, ep := range d.Asset.Endpoints {
		fmt.Fprintf(&b, "  %s/%-5d %-12s %s\n", ep.Transport, ep.Port, ep.State, ep.Address)
	}

	fmt.Fprintf(&b, "\nclaims (%d)\n", len(d.Asset.Claims))
	for _, c := range d.Asset.Claims {
		raw, _ := json.MarshalIndent(c, "    ", "  ")
		fmt.Fprintf(&b, "  %s\n%s\n", c.ID, raw)
	}

	fmt.Fprintf(&b, "\nobservations (%d)\n", len(d.Asset.Observations))
	for _, o := range d.Asset.Observations {
		port := 0
		addr := ""
		if o.Endpoint != nil {
			port = int(o.Endpoint.Port)
			addr = o.Endpoint.Address
		}
		fmt.Fprintf(&b, "  %s  probe=%s  port=%d  addr=%s  completeness=%s\n", o.ObservationType, o.ProbeID, port, addr, o.Completeness)
		if o.Error != "" {
			fmt.Fprintf(&b, "    error: %s\n", o.Error)
		}
		if o.ID != "" {
			fmt.Fprintf(&b, "    id: %s\n", o.ID)
		}
		if o.CorrelationGroup != "" {
			fmt.Fprintf(&b, "    correlation: %s\n", o.CorrelationGroup)
		}
		if len(o.Payload) > 0 {
			var pretty any
			if json.Unmarshal(o.Payload, &pretty) == nil {
				raw, _ := json.MarshalIndent(pretty, "    ", "  ")
				fmt.Fprintf(&b, "    payload:\n    %s\n", raw)
			} else {
				fmt.Fprintf(&b, "    payload: %s\n", o.Payload)
			}
		}
	}
	return b.String()
}

func positiveEndpoints(asset *model.Asset) []model.Endpoint {
	var out []model.Endpoint
	for _, ep := range asset.Endpoints {
		switch ep.State {
		case model.EndpointOpen, model.EndpointResponsive:
			out = append(out, ep)
		default:
			if len(claimsForEndpoint(asset, ep)) > 0 || len(observationsForEndpoint(asset, ep)) > 0 {
				out = append(out, ep)
			}
		}
	}
	return out
}

func hostFindings(asset *model.Asset) ([]model.Claim, []string) {
	var claims []model.Claim
	for _, c := range asset.Claims {
		if claimEndpointKey(c) == "" {
			claims = append(claims, c)
		}
	}
	sortClaims(claims)
	var lines []string
	for _, o := range asset.Observations {
		if o.Endpoint != nil {
			continue
		}
		if line, ok := observationLine(o); ok {
			lines = append(lines, line)
		}
	}
	return claims, lines
}

func claimsForEndpoint(asset *model.Asset, ep model.Endpoint) []model.Claim {
	key := ep.Key()
	var out []model.Claim
	for _, c := range asset.Claims {
		if claimEndpointKey(c) == key {
			out = append(out, c)
		}
	}
	sortClaims(out)
	return out
}

func observationsForEndpoint(asset *model.Asset, ep model.Endpoint) []string {
	var out []string
	for _, o := range asset.Observations {
		if o.Endpoint == nil {
			continue
		}
		if o.Endpoint.Address != ep.Address || o.Endpoint.Port != ep.Port || o.Endpoint.Transport != ep.Transport {
			continue
		}
		if line, ok := observationLine(o); ok {
			out = append(out, line)
		}
	}
	return out
}

func claimEndpointKey(c model.Claim) string {
	if c.Subject == "" || strings.HasPrefix(c.Subject, "asset:") {
		return ""
	}
	return c.Subject
}

func sortClaims(claims []model.Claim) {
	rank := func(k model.ClaimKind) int {
		switch k {
		case model.ClaimProtocol:
			return 0
		case model.ClaimService:
			return 1
		case model.ClaimProduct:
			return 2
		case model.ClaimApplication:
			return 3
		case model.ClaimOS:
			return 4
		case model.ClaimDevice:
			return 5
		default:
			return 6
		}
	}
	sort.SliceStable(claims, func(i, j int) bool {
		if ri, rj := rank(claims[i].Kind), rank(claims[j].Kind); ri != rj {
			return ri < rj
		}
		if claims[i].Score != claims[j].Score {
			return claims[i].Score > claims[j].Score
		}
		return claims[i].Product < claims[j].Product
	})
}

func writeClaimLines(b *strings.Builder, claims []model.Claim, indent string) {
	for _, c := range claims {
		fmt.Fprintf(b, "%s%-12s %s  %s  %.0f\n", indent, c.Kind, formatClaimValue(c), empty(string(c.Confidence)), c.Score)
	}
}

func formatClaimValue(c model.Claim) string {
	parts := make([]string, 0, 4)
	if c.Vendor != "" && !strings.EqualFold(c.Vendor, c.Product) {
		parts = append(parts, c.Vendor)
	}
	label := firstNonEmpty(c.Product, c.Value, c.Family, c.DeviceType, c.Attribute)
	if label != "" {
		parts = append(parts, label)
	}
	if c.Version != "" {
		parts = append(parts, c.Version)
	}
	if c.Family != "" && !containsFold(parts, c.Family) {
		parts = append(parts, "family="+c.Family)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func observationLine(o model.ObservationRecord) (string, bool) {
	if o.Completeness == "none" && o.Error != "" && o.ObservationType != model.ObservationICMPEcho {
		return "", false
	}
	if o.ObservationType == model.ObservationTCPEndpoint || o.ObservationType == model.ObservationUDPEndpoint {
		return "", false
	}
	switch o.ObservationType {
	case model.ObservationICMPEcho:
		var p model.ICMPObservation
		_ = o.DecodePayload(&p)
		if o.Error != "" && p.TTL == 0 {
			return "", false
		}
		return joinFinding("icmp", kv("ttl", p.TTL), kv("latency", p.Latency)), true
	case model.ObservationHTTP:
		var p model.HTTPObservation
		_ = o.DecodePayload(&p)
		if p.StatusCode == 0 && p.Server == "" && p.Title == "" {
			return "", false
		}
		return joinFinding("http",
			kv("status", p.StatusCode),
			kv("server", p.Server),
			quoted("title", p.Title),
			kv("generator", p.MetaGenerator),
			kv("url", firstNonEmpty(p.EffectiveURL, p.URL)),
		), true
	case model.ObservationTLS:
		var p model.TLSObservation
		_ = o.DecodePayload(&p)
		cn := ""
		if len(p.Certificates) > 0 {
			cn = p.Certificates[0].SubjectCN
		}
		return joinFinding("tls", kv("version", p.Version), kv("alpn", p.ALPN), kv("sni", p.ServerName), kv("cn", cn)), true
	case model.ObservationSSH:
		var p model.SSHObservation
		_ = o.DecodePayload(&p)
		if p.Banner == "" {
			return "", false
		}
		return joinFinding("ssh", p.Banner), true
	case model.ObservationSMB:
		var p model.SMBObservation
		_ = o.DecodePayload(&p)
		if p.Signing == "" && p.OSBuild == "" && p.ComputerName == "" && p.Domain == "" {
			return "", false
		}
		return joinFinding("smb", kv("signing", p.Signing), kv("os", firstNonEmpty(p.OSVersionHint, p.OSBuild)), kv("name", p.ComputerName), kv("domain", p.Domain)), true
	case model.ObservationBanner:
		var p model.BannerObservation
		_ = o.DecodePayload(&p)
		if strings.TrimSpace(p.Text) == "" {
			return "", false
		}
		return joinFinding("banner", strings.TrimSpace(p.Text)), true
	default:
		return genericObservationLine(o)
	}
}

func genericObservationLine(o model.ObservationRecord) (string, bool) {
	if len(o.Payload) == 0 {
		return "", false
	}
	var fields map[string]any
	if err := json.Unmarshal(o.Payload, &fields); err != nil {
		return "", false
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if s := scalar(fields[k]); s != "" {
			parts = append(parts, k+"="+s)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return o.ObservationType + "  " + strings.Join(parts, "  "), true
}

func joinFinding(kind string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return kind
	}
	return kind + "  " + strings.Join(out, "  ")
}

func kv(k string, v any) string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return ""
		}
		return k + "=" + t
	case int:
		if t == 0 {
			return ""
		}
		return k + "=" + strconv.Itoa(t)
	case int64:
		if t == 0 {
			return ""
		}
		return k + "=" + strconv.FormatInt(t, 10)
	case uint16:
		if t == 0 {
			return ""
		}
		return k + "=" + strconv.FormatUint(uint64(t), 10)
	case bool:
		if !t {
			return ""
		}
		return k + "=true"
	default:
		s := strings.TrimSpace(fmt.Sprint(t))
		if s == "" || s == "0" || s == "<nil>" {
			return ""
		}
		return k + "=" + s
	}
}

func quoted(k, v string) string {
	if v == "" {
		return ""
	}
	return k + "=" + strconv.Quote(v)
}

func scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case bool:
		if !t {
			return ""
		}
		return "true"
	case float64:
		if t == 0 {
			return ""
		}
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		var parts []string
		for _, item := range t {
			if s := scalar(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		s := strings.TrimSpace(fmt.Sprint(t))
		if s == "" || s == "0" || s == "map[]" || s == "<nil>" {
			return ""
		}
		return s
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func containsFold(vals []string, want string) bool {
	for _, v := range vals {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func empty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
