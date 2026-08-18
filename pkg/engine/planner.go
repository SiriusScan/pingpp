package engine

import (
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
// Port hints only affect Priority ordering via serviceHints — never identity.
func (p *Planner) PlanClassification(asset *model.Asset, state *ScanState) []Task {
	if asset == nil {
		return nil
	}
	var tasks []Task
	for i := range asset.Endpoints {
		ep := &asset.Endpoints[i]
		if ep.State != model.EndpointOpen {
			continue
		}
		for _, id := range likelyCollectorsForPort(ep.Port, ep.Transport) {
			key := id + ":" + ep.Key()
			if state != nil && state.IsComplete(key) {
				continue
			}
			if !p.registry.Has(id) {
				continue
			}
			md, _ := p.meta(id)
			priority := md.Priority + portPriorBoost(ep.Port, id)
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

func (p *Planner) meta(id string) (CollectorMetadata, bool) {
	for _, md := range p.registry.Metadata() {
		if md.ID == id {
			return md, true
		}
	}
	return CollectorMetadata{}, false
}

// likelyCollectorsForPort returns ordered candidate collector IDs.
// These are priors; confirmation still requires protocol behavior.
func likelyCollectorsForPort(port uint16, transport model.Transport) []string {
	if transport != model.TransportTCP {
		return nil
	}
	hints := serviceHints[port]
	if len(hints) == 0 {
		return []string{"collect.banner"}
	}
	return append([]string(nil), hints...)
}

func portPriorBoost(port uint16, collectorID string) int {
	hints := serviceHints[port]
	for i, h := range hints {
		if h == collectorID {
			return (len(hints) - i) * 10
		}
	}
	return 0
}

// serviceHints maps ports to ordered collector priors (not identity).
var serviceHints = map[uint16][]string{
	22:    {"collect.ssh", "collect.banner"},
	80:    {"collect.http", "collect.banner"},
	443:   {"collect.tls", "collect.http", "collect.banner"},
	445:   {"collect.smb", "collect.banner"},
	3389:  {"collect.rdp", "collect.banner"},
	21:    {"collect.ftp", "collect.banner"},
	25:    {"collect.smtp", "collect.banner"},
	110:   {"collect.pop3", "collect.banner"},
	143:   {"collect.imap", "collect.banner"},
	23:    {"collect.telnet", "collect.banner"},
	3306:  {"collect.mysql", "collect.banner"},
	5432:  {"collect.postgres", "collect.banner"},
	6379:  {"collect.redis", "collect.banner"},
	27017: {"collect.mongodb", "collect.banner"},
	11211: {"collect.memcached", "collect.banner"},
	1433:  {"collect.mssql", "collect.banner"},
	389:   {"collect.ldap", "collect.banner"},
	636:   {"collect.ldap", "collect.tls", "collect.banner"},
	161:   {"collect.snmp"},
	1883:  {"collect.mqtt", "collect.banner"},
	5900:  {"collect.vnc", "collect.banner"},
	5672:  {"collect.amqp", "collect.banner"},
	8080:  {"collect.http", "collect.tls", "collect.banner"},
	8443:  {"collect.tls", "collect.http", "collect.banner"},
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
