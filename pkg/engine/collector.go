// Package engine provides the collector registry, planner, and scan orchestration.
//
// Collectors report observations only. They must never schedule peer collectors
// or emit product fingerprint claims — the planner and fingerprint engine own
// those responsibilities.
package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/SiriusScan/ping++/pkg/artifact"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

// Stage identifies which pipeline stage a collector belongs to.
type Stage string

const (
	StageDiscovery   Stage = "discovery"
	StageEnumeration Stage = "enumeration"
	StageClassify    Stage = "classify"
	StageCollect     Stage = "collect"
	StageEnrich      Stage = "enrich"
)

// Collector is the registry-driven observation producer.
type Collector interface {
	Metadata() CollectorMetadata
	Run(context.Context, CollectorInput) ([]model.ObservationRecord, error)
}

// CollectorResult is the formal collector outcome. Planning must use Outcome,
// never observation Completeness, as the protocol-match signal.
type CollectorResult struct {
	Outcome      ProbeOutcome
	Protocol     string
	Observations []model.ObservationRecord
	NetworkOps   int
	BytesRead    int64
}

// ResultCollector is the planner-facing collector API. Fake collectors in
// tests implement this. Production protocol collectors still use Run until
// they are converted; the engine will not treat their Completeness as a match.
type ResultCollector interface {
	Collector
	RunResult(context.Context, CollectorInput) (CollectorResult, error)
}

// CollectorMetadata describes a collector for planning and registration.
type CollectorMetadata struct {
	ID           string            `json:"id"`
	Stage        Stage             `json:"stage"`
	Transports   []model.Transport `json:"transports,omitempty"`
	DefaultPorts []uint16          `json:"default_ports,omitempty"`
	Cost         int               `json:"cost"`
	Priority     int               `json:"priority"`
	// SafeForOT marks collectors reviewed for OT-safe profiles (future use).
	SafeForOT bool `json:"safe_for_ot,omitempty"`
	// SideEffectRisk is a qualitative risk hint (none/low/medium/high).
	SideEffectRisk string `json:"side_effect_risk,omitempty"`
}

// CollectorInput is the context passed to a collector run.
type CollectorInput struct {
	Asset    *model.Asset
	Endpoint *model.Endpoint
	Target   *model.Target
	State    *ScanState
	// Timeout overrides the default when > 0.
	Timeout time.Duration
	// Extra holds per-task collector options (e.g. tls=1 after a TLS match).
	Extra map[string]string
	// Artifacts is the scan-local evidence store. Collectors may persist
	// raw bodies, banners, and certificates without embedding them in JSON.
	Artifacts artifact.Store
}

// PrimaryIP returns the best IP to contact for this input.
func (in CollectorInput) PrimaryIP() string {
	if in.Endpoint != nil && in.Endpoint.Address != "" {
		return in.Endpoint.Address
	}
	if in.Asset != nil && len(in.Asset.Addresses) > 0 {
		return in.Asset.Addresses[0].IP
	}
	if in.Target != nil && len(in.Target.Addresses) > 0 {
		return in.Target.Addresses[0].IP
	}
	return ""
}

// ScanState is the mutable per-asset scan progress shared with the planner.
type ScanState struct {
	AssetID      string
	Reachability model.Reachability
	Budget       Budget
	Completed    map[string]bool            // collector IDs already run for current subject
	Matched      map[string]map[string]bool // endpoint key -> protocol -> matched
	RuledOut     map[string]map[string]bool
	Requests     map[string]int // endpoint key -> collector runs
	Meter        *transport.Meter
	mu           sync.Mutex
}

// MarkComplete records that a collector finished for planning purposes.
func (s *ScanState) MarkComplete(collectorID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Completed == nil {
		s.Completed = make(map[string]bool)
	}
	s.Completed[collectorID] = true
}

// IsComplete reports whether a collector already ran.
func (s *ScanState) IsComplete(collectorID string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Completed[collectorID]
}

// NoteProtocol records a positive or negative protocol classification.
func (s *ScanState) NoteProtocol(endpointKey, protocol string, match bool) {
	if s == nil || endpointKey == "" || protocol == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if match {
		if s.Matched == nil {
			s.Matched = make(map[string]map[string]bool)
		}
		if s.Matched[endpointKey] == nil {
			s.Matched[endpointKey] = make(map[string]bool)
		}
		s.Matched[endpointKey][protocol] = true
		return
	}
	if s.RuledOut == nil {
		s.RuledOut = make(map[string]map[string]bool)
	}
	if s.RuledOut[endpointKey] == nil {
		s.RuledOut[endpointKey] = make(map[string]bool)
	}
	s.RuledOut[endpointKey][protocol] = true
}

// HasProtocol reports a positive protocol match for an endpoint.
func (s *ScanState) HasProtocol(endpointKey, protocol string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Matched[endpointKey][protocol]
}

// IsRuledOut reports a negative protocol classification for an endpoint.
func (s *ScanState) IsRuledOut(endpointKey, protocol string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.RuledOut[endpointKey][protocol]
}

// HasExclusiveProtocol reports whether an exclusive protocol was identified.
func (s *ScanState) HasExclusiveProtocol(endpointKey string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for proto := range s.Matched[endpointKey] {
		if exclusiveProtocol(proto) {
			return true
		}
	}
	return false
}

// NoteEndpointRequest counts a collector run against MaxRequestsPerEndpoint.
func (s *ScanState) NoteEndpointRequest(endpointKey string) {
	if s == nil || endpointKey == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Requests == nil {
		s.Requests = make(map[string]int)
	}
	s.Requests[endpointKey]++
}

// EndpointRequests returns collector runs already issued for an endpoint.
func (s *ScanState) EndpointRequests(endpointKey string) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Requests[endpointKey]
}

func exclusiveProtocol(protocol string) bool {
	switch protocol {
	case "tls", "http", "banner", "tcp.stack", "tcp.endpoint", "icmp.echo":
		return false
	case "":
		return false
	default:
		return true
	}
}

// Config is collector construction configuration.
type Config struct {
	Timeout     time.Duration
	Ports       []uint16
	UDPPorts    []uint16
	Concurrency int
	// Extra holds collector-specific options (e.g. SNMP community).
	Extra map[string]string
}

// CollectorFactory constructs a collector from config.
type CollectorFactory func(cfg Config) (Collector, error)

// Registry maps collector IDs to factories without a central protocol switch.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]CollectorFactory
	meta       map[string]CollectorMetadata
}

// NewRegistry creates an empty collector registry.
func NewRegistry() *Registry {
	return &Registry{
		collectors: make(map[string]CollectorFactory),
		meta:       make(map[string]CollectorMetadata),
	}
}

// Register adds a collector factory. The factory is invoked once with a zero
// Config to obtain Metadata for planning; construction errors on that probe
// are ignored for metadata-only registration if Metadata() is available via
// a prototype pattern — factories should be cheap for zero config.
func (r *Registry) Register(id string, factory CollectorFactory) error {
	if id == "" {
		return fmt.Errorf("collector id required")
	}
	if factory == nil {
		return fmt.Errorf("factory required for %s", id)
	}
	c, err := factory(Config{})
	if err != nil {
		return fmt.Errorf("register %s: %w", id, err)
	}
	md := c.Metadata()
	if md.ID == "" {
		md.ID = id
	}
	if md.ID != id {
		return fmt.Errorf("register %s: metadata id %q mismatch", id, md.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.collectors[id]; exists {
		return fmt.Errorf("collector already registered: %s", id)
	}
	r.collectors[id] = factory
	r.meta[id] = md
	return nil
}

// MustRegister panics on registration failure (for package init wiring).
func (r *Registry) MustRegister(id string, factory CollectorFactory) {
	if err := r.Register(id, factory); err != nil {
		panic(err)
	}
}

// Create constructs a collector by id.
func (r *Registry) Create(id string, cfg Config) (Collector, error) {
	r.mu.RLock()
	factory, ok := r.collectors[id]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown collector: %s", id)
	}
	return factory(cfg)
}

// Metadata returns metadata for all registered collectors, sorted by ID.
func (r *Registry) Metadata() []CollectorMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CollectorMetadata, 0, len(r.meta))
	for _, md := range r.meta {
		out = append(out, md)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Has reports whether a collector id is registered.
func (r *Registry) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.collectors[id]
	return ok
}

// IDs returns registered collector identifiers sorted.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.collectors))
	for id := range r.collectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
