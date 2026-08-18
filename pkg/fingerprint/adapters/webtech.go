package adapters

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/SiriusScan/ping++/pkg/model"
)

// NativeWebTech is a Wappalyzer-style detector using local rules (no third-party types).
type NativeWebTech struct {
	rules []webRule
}

type webRule struct {
	id      string
	product string
	vendor  string
	kind    model.ClaimKind
	score   float64
	headers map[string]*regexp.Regexp
	title   *regexp.Regexp
	body    *regexp.Regexp
	cookies []string
}

// NewNativeWebTech returns a tiny fixture detector for adapter tests.
// Production matching uses Wappalyzer-format JSON via LoadWappalyzerJSON.
func NewNativeWebTech() *NativeWebTech {
	return &NativeWebTech{rules: defaultWebRules()}
}

func defaultWebRules() []webRule {
	return []webRule{
		{id: "tech-grafana", product: "Grafana", vendor: "Grafana Labs", kind: model.ClaimApplication, score: 92,
			title: regexp.MustCompile(`(?i)grafana`), body: regexp.MustCompile(`(?i)grafana`)},
		{id: "tech-jenkins", product: "Jenkins", vendor: "Jenkins", kind: model.ClaimApplication, score: 92,
			title: regexp.MustCompile(`(?i)jenkins`), headers: map[string]*regexp.Regexp{"X-Jenkins": regexp.MustCompile(`.`)}},
		{id: "tech-wordpress", product: "WordPress", vendor: "WordPress", kind: model.ClaimApplication, score: 90,
			body: regexp.MustCompile(`(?i)wp-content|wordpress`), cookies: []string{"wordpress_"}},
		{id: "tech-nginx", product: "nginx", vendor: "F5", kind: model.ClaimProduct, score: 88,
			headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)nginx`)}},
		{id: "tech-apache", product: "Apache HTTP Server", vendor: "Apache", kind: model.ClaimProduct, score: 88,
			headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)apache`)}},
		{id: "tech-iis", product: "IIS", vendor: "Microsoft", kind: model.ClaimProduct, score: 92,
			headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)Microsoft-IIS`)}},
	}
}

// Name implements FingerprintAdapter.
func (n *NativeWebTech) Name() string { return "native-webtech" }

// Detect implements WebTechDetector.
func (n *NativeWebTech) Detect(httpObs model.HTTPObservation) ([]model.Claim, error) {
	var claims []model.Claim
	for _, r := range n.rules {
		if !r.match(httpObs) {
			continue
		}
		claims = append(claims, model.Claim{
			ID:               fmt.Sprintf("%s:%s", r.id, httpObs.RawBodySHA256),
			Kind:             r.kind,
			Vendor:           r.vendor,
			Product:          r.product,
			Value:            r.product,
			Score:            r.score,
			Confidence:       model.TierFromScore(r.score),
			RuleIDs:          []string{r.id},
			CorrelationGroup: "webtech:" + r.id,
		})
	}
	return claims, nil
}

// Match implements FingerprintAdapter for HTTP observations.
func (n *NativeWebTech) Match(observations []model.ObservationRecord) ([]model.Claim, error) {
	var out []model.Claim
	for _, obs := range observations {
		if obs.ObservationType != model.ObservationHTTP {
			continue
		}
		var httpObs model.HTTPObservation
		if err := obs.DecodePayload(&httpObs); err != nil {
			continue
		}
		claims, err := n.Detect(httpObs)
		if err != nil {
			return nil, err
		}
		for i := range claims {
			claims[i].EvidenceIDs = []string{obs.ID}
			claims[i].Subject = obs.AssetID
			if obs.Endpoint != nil {
				claims[i].Subject = model.EndpointKey(obs.Endpoint.Address, obs.Endpoint.Port, obs.Endpoint.Transport)
			}
			// Keep web-tech signals in one correlation group per HTTP response.
			claims[i].CorrelationGroup = obs.CorrelationGroup
			if claims[i].CorrelationGroup == "" {
				claims[i].CorrelationGroup = "http-webtech"
			}
		}
		out = append(out, claims...)
	}
	return out, nil
}

func (r webRule) match(h model.HTTPObservation) bool {
	ok := r.title != nil && r.title.MatchString(h.Title)
	if r.body != nil && r.body.MatchString(fmt.Sprintf("%s %s", h.Title, h.MetaGenerator)) {
		ok = true
	}
	if r.headers != nil {
		for name, re := range r.headers {
			vals := headerVals(h.Headers, name)
			for _, v := range vals {
				if re.MatchString(v) {
					ok = true
				}
			}
			// Also check convenience fields
			if strings.EqualFold(name, "Server") && re.MatchString(h.Server) {
				ok = true
			}
		}
	}
	for _, prefix := range r.cookies {
		for _, c := range h.CookieNames {
			if strings.HasPrefix(strings.ToLower(c), strings.ToLower(prefix)) {
				ok = true
			}
		}
	}
	return ok
}

func headerVals(h map[string][]string, name string) []string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}
