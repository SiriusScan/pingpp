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
	"regexp"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

const (
	collectorID  = "collect.http"
	maxBody      = 64 * 1024
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
	if in.Endpoint == nil {
		return nil, fmt.Errorf("http: endpoint required")
	}
	timeout := c.timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	hostHeader := in.Endpoint.Address
	if in.Target != nil && in.Target.Hostname != "" {
		hostHeader = in.Target.Hostname
	}

	useTLS := in.Endpoint.Port == 443 || in.Endpoint.Port == 8443
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(in.Endpoint.Address, fmt.Sprintf("%d", in.Endpoint.Port)))

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         hostHeader,
				MinVersion:         tls.VersionTLS10,
			},
			DisableKeepAlives: true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
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
		return []model.ObservationRecord{obs}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	payload := buildHTTPObservation(url, resp, body)
	obs.Completeness = "full"
	if err := obs.SetPayload(payload); err != nil {
		return nil, err
	}
	return []model.ObservationRecord{obs}, nil
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
	return nil
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
