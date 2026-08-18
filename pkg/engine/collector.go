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
	Completed    map[string]bool // collector IDs already run for current subject
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

// Config is collector construction configuration.
type Config struct {
	Timeout time.Duration
	Ports   []uint16
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
