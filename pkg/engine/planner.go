package engine

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SiriusScan/ping++/pkg/model"
)

// Task is a unit of work produced by the planner.
type Task struct {
	CollectorID string
	Asset       *model.Asset
	Endpoint    *model.Endpoint
	Target      *model.Target
	Stage       Stage
	Priority    int
	Extra       map[string]string
}

// Planner inspects scan state and creates collector tasks.
// Ports are priors for ordering only — never identity.
type Planner struct {
	registry *Registry
	profile  Profile
}

// NewPlanner creates a planner bound to a registry and profile.
func NewPlanner(reg *Registry, profile Profile) *Planner {
	return &Planner{registry: reg, profile: profile}
}

// PlanDiscovery returns host-discovery tasks for a target/asset.
func (p *Planner) PlanDiscovery(asset *model.Asset, target *model.Target, state *ScanState) []Task {
	if p.profile.SkipDiscovery {
		return nil
	}
	var tasks []Task
	for _, id := range p.profile.DiscoveryCollectors {
		if state != nil && state.IsComplete(id) {
			continue
		}
		if !p.registry.Has(id) {
			continue
		}
		md, _ := p.meta(id)
		tasks = append(tasks, Task{
			CollectorID: id,
			Asset:       asset,
			Target:      target,
			Stage:       StageDiscovery,
			Priority:    md.Priority,
		})
	}
	return tasks
}

// PlanEnumeration returns endpoint enumeration tasks.
func (p *Planner) PlanEnumeration(asset *model.Asset, target *model.Target, state *ScanState) []Task {
	var tasks []Task
	for _, id := range p.profile.CollectCollectors {
		if id != "enumerate.tcp" && id != "enumerate.udp" {
			continue
		}
		if state != nil && state.IsComplete(id) {
			continue
		}
		if !p.registry.Has(id) {
			continue
		}
		md, _ := p.meta(id)
		tasks = append(tasks, Task{
			CollectorID: id,
			Asset:       asset,
			Target:      target,
			Stage:       StageEnumeration,
			Priority:    md.Priority,
		})
	}
	return tasks
}

// PlanClassification returns protocol classification tasks for open endpoints.
// Port metadata only affects Priority ordering — never identity.
func (p *Planner) PlanClassification(asset *model.Asset, state *ScanState) []Task {
	if asset == nil {
		return nil
	}
	var tasks []Task
	for i := range asset.Endpoints {
		ep := &asset.Endpoints[i]
		if !classifiableEndpoint(ep) {
			continue
		}
		for _, id := range p.likelyCollectorsForPort(ep.Port, ep.Transport) {
			key := id + ":" + ep.Key()
			if state != nil && state.IsComplete(key) {
				continue
			}
			if !p.registry.Has(id) {
				continue
			}
			md, _ := p.meta(id)
			priority := md.Priority + p.portPriorBoost(ep, id)
			tasks = append(tasks, Task{
				CollectorID: id,
				Asset:       asset,
				Endpoint:    ep,
				Stage:       StageClassify,
				Priority:    priority,
			})
		}
	}
	return tasks
}

// Next returns the next adaptive classification/enrichment tasks.
// One collector is scheduled per endpoint per call so the engine can
// fingerprint and re-plan instead of probing every prior up front.
func (p *Planner) Next(asset *model.Asset, state *ScanState) []Task {
	if asset == nil {
		return nil
	}
	var tasks []Task
	for i := range asset.Endpoints {
		ep := &asset.Endpoints[i]
		if !classifiableEndpoint(ep) {
			continue
		}
		if task, ok := p.nextForEndpoint(asset, ep, state); ok {
			tasks = append(tasks, task)
		}
	}
	return tasks
}

func (p *Planner) nextForEndpoint(asset *model.Asset, ep *model.Endpoint, state *ScanState) (Task, bool) {
	key := ep.Key()
	if state != nil && state.HasExclusiveProtocol(key) {
		return p.maybeEnrich(asset, ep, state)
	}
	if state != nil && state.HasProtocol(key, "tls") {
		if task, ok := p.taskIfAvailable(asset, ep, state, "collect.http", StageCollect); ok {
			task.Extra = map[string]string{"tls": "1"}
			return task, true
		}
	}
	for _, id := range p.classificationSequence(ep) {
		if state != nil && exclusiveProtocol(strings.TrimPrefix(id, "collect.")) && state.HasProtocol(key, "http") && id != "collect.http" && id != "collect.tls" && id != "collect.banner" {
			continue
		}
		if task, ok := p.taskIfAvailable(asset, ep, state, id, StageClassify); ok {
			return task, true
		}
	}
	return p.maybeEnrich(asset, ep, state)
}

func classifiableEndpoint(ep *model.Endpoint) bool {
	if ep == nil {
		return false
	}
	switch ep.State {
	case model.EndpointOpen, model.EndpointResponsive:
		return true
	case model.EndpointClosed:
		return false
	case model.EndpointUnknown, model.EndpointFiltered:
		// UDP silence is unknown, not exclusion. Protocol collectors decide.
		return ep.Transport == model.TransportUDP
	default:
		return false
	}
}

// classificationSequence is port priors first, then the general fallback
// sequence. Ports never exclude collectors; they only order attempts.
func (p *Planner) classificationSequence(ep *model.Endpoint) []string {
	if ep == nil {
		return p.filterRegistered(unknownSequence(model.TransportTCP))
	}
	return uniqueIDs(p.likelyCollectorsForPort(ep.Port, ep.Transport), p.filterRegistered(unknownSequence(ep.Transport)))
}

func uniqueIDs(parts ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ids := range parts {
		for _, id := range ids {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func (p *Planner) maybeEnrich(asset *model.Asset, ep *model.Endpoint, state *ScanState) (Task, bool) {
	if state == nil || !state.HasProtocol(ep.Key(), "http") {
		return Task{}, false
	}
	if strongProductClaim(asset, ep.Key()) {
		return Task{}, false
	}
	return p.taskIfAvailable(asset, ep, state, "collect.http.enrich", StageEnrich)
}

func (p *Planner) taskIfAvailable(asset *model.Asset, ep *model.Endpoint, state *ScanState, id string, stage Stage) (Task, bool) {
	key := id + ":" + ep.Key()
	if state != nil && state.IsComplete(key) {
		return Task{}, false
	}
	if state != nil && state.IsRuledOut(ep.Key(), collectorProtocol(id)) {
		return Task{}, false
	}
	if !p.registry.Has(id) {
		return Task{}, false
	}
	md, _ := p.meta(id)
	return Task{
		CollectorID: id,
		Asset:       asset,
		Endpoint:    ep,
		Stage:       stage,
		Priority:    md.Priority + p.portPriorBoost(ep, id),
	}, true
}

func collectorProtocol(collectorID string) string {
	s := strings.TrimPrefix(collectorID, "collect.")
	s = strings.TrimPrefix(s, "enumerate.")
	s = strings.TrimPrefix(s, "discovery.")
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	return s
}

func strongProductClaim(asset *model.Asset, subject string) bool {
	if asset == nil {
		return false
	}
	for _, c := range asset.Claims {
		if c.Subject != subject {
			continue
		}
		if c.Kind != model.ClaimProduct && c.Kind != model.ClaimApplication {
			continue
		}
		if c.Confidence == model.ConfidenceStrong || c.Confidence == model.ConfidenceExact {
			return true
		}
	}
	return false
}

func (p *Planner) meta(id string) (CollectorMetadata, bool) {
	for _, md := range p.registry.Metadata() {
		if md.ID == id {
			return md, true
		}
	}
	return CollectorMetadata{}, false
}

// likelyCollectorsForPort returns ordered candidate collector IDs derived
// from CollectorMetadata.DefaultPorts. Ports remain priors, never identity.
func (p *Planner) likelyCollectorsForPort(port uint16, transport model.Transport) []string {
	if p == nil || p.registry == nil {
		return unknownSequence(transport)
	}
	type ranked struct {
		id       string
		priority int
	}
	var matched []ranked
	for _, md := range p.registry.Metadata() {
		if skipAsPrior(md.ID) {
			continue
		}
		if !metadataHasTransport(md, transport) {
			continue
		}
		for _, dp := range md.DefaultPorts {
			if dp == port {
				matched = append(matched, ranked{id: md.ID, priority: md.Priority})
				break
			}
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].priority != matched[j].priority {
			return matched[i].priority > matched[j].priority
		}
		return matched[i].id < matched[j].id
	})
	var ids []string
	seen := map[string]bool{}
	for _, m := range matched {
		ids = append(ids, m.id)
		seen[m.id] = true
	}
	if len(ids) == 0 {
		ids = p.filterRegistered(unknownSequence(transport))
	} else if transport == model.TransportTCP && !seen["collect.banner"] && p.registry.Has("collect.banner") {
		ids = append(ids, "collect.banner")
	}
	return ids
}

func (p *Planner) filterRegistered(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if p.registry.Has(id) {
			out = append(out, id)
		}
	}
	return out
}

func (p *Planner) portPriorBoost(ep *model.Endpoint, collectorID string) int {
	if ep == nil {
		return 0
	}
	hints := p.likelyCollectorsForPort(ep.Port, ep.Transport)
	for i, h := range hints {
		if h == collectorID {
			return (len(hints) - i) * 10
		}
	}
	return 0
}

func skipAsPrior(id string) bool {
	switch id {
	case "collect.tcpstack", "collect.http.enrich":
		return true
	}
	return !strings.HasPrefix(id, "collect.")
}

func metadataHasTransport(md CollectorMetadata, t model.Transport) bool {
	if len(md.Transports) == 0 {
		return t == model.TransportTCP
	}
	for _, tr := range md.Transports {
		if tr == t {
			return true
		}
	}
	return false
}

func unknownSequence(t model.Transport) []string {
	if t == model.TransportUDP {
		return append([]string(nil), unknownUDPSequence...)
	}
	return append([]string(nil), unknownTCPSequence...)
}

// unknownTCPSequence: banner → TLS → cheap text → high-value binary.
var unknownTCPSequence = []string{
	"collect.banner",
	"collect.tls",
	"collect.http",
	"collect.ftp", "collect.smtp", "collect.pop3", "collect.imap", "collect.telnet",
	"collect.ssh", "collect.mysql", "collect.postgres", "collect.redis",
	"collect.mongodb", "collect.memcached", "collect.mssql", "collect.ldap",
	"collect.rdp", "collect.smb", "collect.socks", "collect.mqtt", "collect.vnc", "collect.amqp",
	"collect.dns",
}

var unknownUDPSequence = []string{
	"collect.dns",
	"collect.snmp",
}

// RateLimiter is a simple token-bucket style limiter (probes per second).
type RateLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	last     time.Time
}

// NewRateLimiter creates a limiter for rate probes/sec (minimum 1).
func NewRateLimiter(ratePerSecond int) *RateLimiter {
	if ratePerSecond <= 0 {
		ratePerSecond = 100
	}
	return &RateLimiter{
		interval: time.Second / time.Duration(ratePerSecond),
	}
}

// Wait blocks until a token is available or ctx is done.
func (r *RateLimiter) Wait(done <-chan struct{}) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if r.last.IsZero() {
		r.last = now
		return true
	}
	next := r.last.Add(r.interval)
	if now.Before(next) {
		timer := time.NewTimer(next.Sub(now))
		defer timer.Stop()
		select {
		case <-done:
			return false
		case <-timer.C:
		}
	}
	r.last = time.Now()
	return true
}
