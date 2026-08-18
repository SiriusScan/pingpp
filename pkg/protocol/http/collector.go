// Package httpcol implements HTTP observation collection (no product fingerprinting).
package httpcol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

const (
	collectorID  = "collect.http"
	maxBody      = 256 * 1024
	maxRedirects = 5
)

var (
	titleRe       = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	generatorRe   = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	faviconLinkRe = regexp.MustCompile(`(?is)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']`)
)

// Collector collects HTTP fingerprinting surface observations via GET.
type Collector struct {
	timeout time.Duration
}

// New creates an HTTP collector.
func New(cfg engine.Config) (*Collector, error) {
	to := engine.EffectiveTimeout(cfg)
	if to < 5*time.Second {
		to = 5 * time.Second
	}
	return &Collector{timeout: to}, nil
}

// Metadata implements engine.Collector.
func (c *Collector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID:             collectorID,
		Stage:          engine.StageCollect,
		Transports:     []model.Transport{model.TransportTCP},
		DefaultPorts:   []uint16{80, 8080, 8000, 443, 8443},
		Cost:           4,
		Priority:       60,
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
		return engine.CollectorResult{}, fmt.Errorf("http: endpoint required")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	hostHeader := in.Endpoint.Address
	if in.Target != nil && in.Target.Hostname != "" {
		hostHeader = in.Target.Hostname
	}

	useTLS := in.Extra["tls"] == "1"
	if !useTLS && in.State != nil {
		useTLS = in.State.HasProtocol(in.Endpoint.Key(), "tls")
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(in.Endpoint.Address, fmt.Sprintf("%d", in.Endpoint.Port)))
	if path, ok := in.Extra["path"]; ok && path != "" {
		url = fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(in.Endpoint.Address, fmt.Sprintf("%d", in.Endpoint.Port)), path)
	}

	var chain []model.Redirect
	client := newHTTPClient(timeout, hostHeader, func(req *http.Request, via []*http.Request) error {
		prev := via[len(via)-1]
		status := 0
		loc := req.URL.String()
		if prev.Response != nil {
			status = prev.Response.StatusCode
			if l := prev.Response.Header.Get("Location"); l != "" {
				loc = l
			}
		}
		chain = append(chain, model.Redirect{StatusCode: status, Location: loc, URL: prev.URL.String()})
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		if !sameHTTPHost(prev.URL, req.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return engine.CollectorResult{}, err
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "ping++/0.1")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID:               fmt.Sprintf("obs:http:%s:%d:%d", in.Endpoint.Address, in.Endpoint.Port, time.Now().UnixNano()),
		ProbeID:          collectorID,
		ObservationType:  model.ObservationHTTP,
		Endpoint:         &ref,
		Timestamp:        time.Now().UTC(),
		CorrelationGroup: fmt.Sprintf("http-response:%s:%d:/", in.Endpoint.Address, in.Endpoint.Port),
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
			Protocol:     "http",
			Observations: []model.ObservationRecord{obs},
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, truncated := readLimited(resp.Body, maxBody)
	payload := buildHTTPObservation(url, resp, body)
	payload.Truncated = truncated
	if resp.Request != nil && resp.Request.URL != nil {
		payload.EffectiveURL = resp.Request.URL.String()
	}
	payload.RedirectChain = chain
	if in.Artifacts != nil && len(body) > 0 {
		if art, err := in.Artifacts.Put("text/html", body, "http body"); err == nil {
			obs.ArtifactIDs = append(obs.ArtifactIDs, art.ID)
		}
	}
	fetchFavicon(ctx, client, &payload, in)
	obs.Completeness = "full"
	if err := obs.SetPayload(payload); err != nil {
		return engine.CollectorResult{}, err
	}
	return engine.CollectorResult{
		Outcome:      engine.OutcomeSuccess,
		Protocol:     "http",
		Observations: []model.ObservationRecord{obs},
		BytesRead:    int64(len(body)),
	}, nil
}

func buildHTTPObservation(url string, resp *http.Response, body []byte) model.HTTPObservation {
	headers := map[string][]string{}
	for k, v := range resp.Header {
		headers[k] = append([]string(nil), v...)
	}
	rawHash := sha256.Sum256(body)
	norm := normalizeBody(body)
	normHash := sha256.Sum256(norm)

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, c.Name)
	}

	title := ""
	if m := titleRe.FindSubmatch(body); len(m) > 1 {
		title = strings.TrimSpace(stripTags(string(m[1])))
	}
	gen := ""
	if m := generatorRe.FindSubmatch(body); len(m) > 1 {
		gen = string(m[1])
	}

	auth := []string{}
	if www := resp.Header.Get("WWW-Authenticate"); www != "" {
		auth = append(auth, www)
	}

	return model.HTTPObservation{
		URL:              url,
		StatusCode:       resp.StatusCode,
		Headers:          headers,
		Title:            title,
		MetaGenerator:    gen,
		CookieNames:      cookies,
		AuthSchemes:      auth,
		Server:           resp.Header.Get("Server"),
		PoweredBy:        resp.Header.Get("X-Powered-By"),
		Via:              resp.Header.Get("Via"),
		Location:         resp.Header.Get("Location"),
		CSP:              resp.Header.Get("Content-Security-Policy"),
		BodyLength:       int64(len(body)),
		Truncated:        false,
		EffectiveURL:     url,
		RawBodySHA256:    hex.EncodeToString(rawHash[:]),
		NormalizedSHA256: hex.EncodeToString(normHash[:]),
		SimHash:          simpleSimHash(body),
		Favicon:          extractFaviconHint(body),
	}
}

func normalizeBody(body []byte) []byte {
	// Strip common volatile tokens for fuzzy matching.
	s := string(body)
	s = regexp.MustCompile(`(?i)csrf[^"'\s=]*["'=\s]+[a-zA-Z0-9+/=_-]{8,}`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	return []byte(strings.TrimSpace(s))
}

func stripTags(s string) string {
	return regexp.MustCompile(`<[^>]+>`).ReplaceAllString(s, "")
}

func extractFaviconHint(body []byte) *model.FaviconObservation {
	if m := faviconLinkRe.FindSubmatch(body); len(m) > 1 {
		return &model.FaviconObservation{URL: string(m[1])}
	}
	return &model.FaviconObservation{URL: "/favicon.ico"}
}

func newHTTPClient(timeout time.Duration, serverName string, redirect func(*http.Request, []*http.Request) error) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: redirect,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialHTTP(ctx, network, addr, timeout)
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         serverName,
				MinVersion:         tls.VersionTLS10,
			},
			DisableKeepAlives: true,
		},
	}
}

func dialHTTP(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	switch network {
	case "udp", "udp4", "udp6":
		return transport.DialUDP(ctx, host, uint16(port64), timeout)
	default:
		return transport.DialTCP(ctx, host, uint16(port64), timeout)
	}
}

func sameHTTPHost(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return canonicalHTTPHost(a.Hostname()) == canonicalHTTPHost(b.Hostname())
}

func canonicalHTTPHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	return strings.TrimPrefix(h, "www.")
}

func readLimited(r io.Reader, max int) ([]byte, bool) {
	body, _ := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if len(body) > max {
		return body[:max], true
	}
	return body, false
}

func fetchFavicon(ctx context.Context, client *http.Client, payload *model.HTTPObservation, in engine.CollectorInput) {
	if payload == nil {
		return
	}
	base := payload.EffectiveURL
	if base == "" {
		base = payload.URL
	}
	icon := "/favicon.ico"
	if payload.Favicon != nil && payload.Favicon.URL != "" {
		icon = payload.Favicon.URL
	}
	ref, err := url.Parse(base)
	if err != nil {
		return
	}
	u, err := ref.Parse(icon)
	if err != nil || !sameHTTPHost(ref, u) {
		if payload.Favicon == nil {
			payload.Favicon = &model.FaviconObservation{URL: icon}
		}
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if len(data) == 0 {
		return
	}
	sum := sha256.Sum256(data)
	payload.Favicon = &model.FaviconObservation{
		URL:    u.String(),
		SHA256: hex.EncodeToString(sum[:]),
		MMH3:   faviconMMH3(data),
	}
	if in.Artifacts != nil {
		_, _ = in.Artifacts.Put("image/x-icon", data, "favicon")
	}
}

// simpleSimHash is a lightweight 64-bit token hash for fuzzy body similarity.
func simpleSimHash(body []byte) uint64 {
	tokens := strings.Fields(string(body))
	var bits [64]int
	for _, tok := range tokens {
		h := sha256.Sum256([]byte(strings.ToLower(tok)))
		for i := 0; i < 64; i++ {
			bit := (h[i/8] >> uint(i%8)) & 1
			if bit == 1 {
				bits[i]++
			} else {
				bits[i]--
			}
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if bits[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

// Register adds the HTTP collector.
func Register(r *engine.Registry) {
	r.MustRegister(collectorID, func(cfg engine.Config) (engine.Collector, error) {
		return New(cfg)
	})
	r.MustRegister(enrichID, func(cfg engine.Config) (engine.Collector, error) {
		return NewEnrich(cfg)
	})
}

// ParseHeaders is exported for unit tests of header projection without network.
func ParseHeaders(raw string) (server, powered string) {
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
		}
		if strings.HasPrefix(strings.ToLower(line), "x-powered-by:") {
			powered = strings.TrimSpace(line[13:])
		}
	}
	return server, powered
}
