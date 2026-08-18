package adapters

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/SiriusScan/ping++/pkg/model"
)

// WappalyzerApp is one technologies.json entry (Wappalyzer-compatible).
type WappalyzerApp struct {
	Cats    []int             `json:"cats"`
	Headers map[string]string `json:"headers"`
	Cookies map[string]string `json:"cookies"`
	HTML    any               `json:"html"`
	Meta    map[string]string `json:"meta"`
	Implies any               `json:"implies"`
	Website string            `json:"website"`
}

// Wappalyzer is a Wappalyzer-format detector. NativeWebTech remains a test fixture.
type Wappalyzer struct {
	apps []compiledWapp
}

type compiledWapp struct {
	name    string
	headers map[string]*regexp.Regexp
	html    []*regexp.Regexp
	meta    map[string]*regexp.Regexp
	cookies []string
}

// LoadWappalyzerJSON loads a technologies.json object.
func LoadWappalyzerJSON(path string) (*Wappalyzer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseWappalyzerJSON(data)
}

// ParseWappalyzerJSON parses Wappalyzer technologies JSON.
func ParseWappalyzerJSON(data []byte) (*Wappalyzer, error) {
	var raw map[string]WappalyzerApp
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	w := &Wappalyzer{}
	for name, app := range raw {
		cw := compiledWapp{name: name, headers: map[string]*regexp.Regexp{}, meta: map[string]*regexp.Regexp{}}
		for h, pat := range app.Headers {
			re, err := compileWappPattern("(?i)", pat)
			if err != nil {
				continue
			}
			cw.headers[h] = re
		}
		for _, pat := range stringList(app.HTML) {
			re, err := compileWappPattern("(?is)", pat)
			if err != nil {
				continue
			}
			cw.html = append(cw.html, re)
		}
		for k, pat := range app.Meta {
			re, err := compileWappPattern("(?i)", pat)
			if err != nil {
				continue
			}
			cw.meta[k] = re
		}
		for cookie := range app.Cookies {
			cw.cookies = append(cw.cookies, cookie)
		}
		w.apps = append(w.apps, cw)
	}
	return w, nil
}

// AppCount returns compiled technology entries.
func (w *Wappalyzer) AppCount() int {
	if w == nil {
		return 0
	}
	return len(w.apps)
}

func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (w *Wappalyzer) Name() string { return "wappalyzer" }

func (w *Wappalyzer) Detect(httpObs model.HTTPObservation) ([]model.Claim, error) {
	body := httpObs.Title + " " + httpObs.MetaGenerator
	var claims []model.Claim
	for _, app := range w.apps {
		if !app.match(httpObs, body) {
			continue
		}
		kind := model.ClaimProduct
		score := 88.0
		tier := model.ConfidenceStrong
		if len(app.html) > 0 || len(app.meta) > 0 {
			kind = model.ClaimApplication
		}
		if len(app.headers) == 0 {
			score = 75
			tier = model.ConfidenceProbable
		}
		claims = append(claims, model.Claim{
			ID:               fmt.Sprintf("wapp:%s:%s", app.name, httpObs.RawBodySHA256),
			Kind:             kind,
			Product:          app.name,
			Value:            app.name,
			Score:            score,
			Confidence:       tier,
			RuleIDs:          []string{"wappalyzer:" + app.name},
			CorrelationGroup: "wappalyzer:" + app.name,
		})
	}
	return claims, nil
}

func (w *Wappalyzer) Match(observations []model.ObservationRecord) ([]model.Claim, error) {
	var out []model.Claim
	for _, obs := range observations {
		if obs.ObservationType != model.ObservationHTTP {
			continue
		}
		var httpObs model.HTTPObservation
		if err := obs.DecodePayload(&httpObs); err != nil {
			continue
		}
		claims, err := w.Detect(httpObs)
		if err != nil {
			return nil, err
		}
		for i := range claims {
			claims[i].EvidenceIDs = []string{obs.ID}
			claims[i].Subject = obs.AssetID
			if obs.Endpoint != nil {
				claims[i].Subject = model.EndpointKey(obs.Endpoint.Address, obs.Endpoint.Port, obs.Endpoint.Transport)
			}
			claims[i].CorrelationGroup = obs.CorrelationGroup
		}
		out = append(out, claims...)
	}
	return out, nil
}

func (a compiledWapp) match(h model.HTTPObservation, body string) bool {
	matched := false
	for name, re := range a.headers {
		if strings.EqualFold(name, "Server") && re.MatchString(h.Server) {
			matched = true
		}
		for _, v := range headerVals(h.Headers, name) {
			if re.MatchString(v) {
				matched = true
			}
		}
	}
	if re, found := a.meta["generator"]; found && re.MatchString(h.MetaGenerator) {
		matched = true
	}
	for _, re := range a.html {
		if re.MatchString(h.Title) || re.MatchString(h.Body) || re.MatchString(body) {
			matched = true
		}
	}
	for _, cookie := range a.cookies {
		for _, c := range h.CookieNames {
			if strings.EqualFold(c, cookie) || strings.HasPrefix(strings.ToLower(c), strings.ToLower(cookie)) {
				matched = true
			}
		}
	}
	return matched
}

func compileWappPattern(flags, pat string) (*regexp.Regexp, error) {
	pat = stripWappVersion(pat)
	if pat == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	return regexp.Compile(flags + pat)
}

func stripWappVersion(pat string) string {
	if i := strings.Index(pat, `\;`); i >= 0 {
		return pat[:i]
	}
	return pat
}
