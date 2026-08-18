package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// DefaultMaxTargets is the safety gate for lazy CIDR expansion.
const DefaultMaxTargets = 100_000

// ErrMaxTargets is returned when admitted or estimated targets exceed MaxTargets.
var ErrMaxTargets = errors.New("target expansion exceeds max-targets")

// TargetSource yields TargetSpec values without pre-resolving hostnames
// and without eagerly materializing CIDR members.
type TargetSource interface {
	Next(ctx context.Context) (TargetSpec, error)
}

// SourceOption configures NewTargetSource.
type SourceOption func(*sourceConfig)

type sourceConfig struct {
	targets    []string
	files      []string
	stdin      io.Reader
	useStdin   bool
	excludes   []string
	excludeF   []string
	maxTargets uint64
	strict     bool
}

// WithTargets adds argv / -t inputs.
func WithTargets(targets ...string) SourceOption {
	return func(c *sourceConfig) { c.targets = append(c.targets, targets...) }
}

// WithFile adds a -l/--list path.
func WithFile(path string) SourceOption {
	return func(c *sourceConfig) { c.files = append(c.files, path) }
}

// WithStdin reads targets from r (typically os.Stdin).
func WithStdin(r io.Reader) SourceOption {
	return func(c *sourceConfig) {
		c.stdin = r
		c.useStdin = true
	}
}

// WithExclude adds an IP or CIDR exclusion.
func WithExclude(raw string) SourceOption {
	return func(c *sourceConfig) { c.excludes = append(c.excludes, raw) }
}

// WithExcludeFile adds exclusions from a file (same syntax as target files).
func WithExcludeFile(path string) SourceOption {
	return func(c *sourceConfig) { c.excludeF = append(c.excludeF, path) }
}

// WithMaxTargets sets the safety gate. Zero means DefaultMaxTargets.
func WithMaxTargets(n uint64) SourceOption {
	return func(c *sourceConfig) { c.maxTargets = n }
}

// WithStrictInput makes malformed file lines fatal instead of skipped.
func WithStrictInput(strict bool) SourceOption {
	return func(c *sourceConfig) { c.strict = strict }
}

// NewTargetSource builds a streaming source. It does not resolve hostnames.
func NewTargetSource(opts ...SourceOption) (TargetSource, error) {
	cfg := sourceConfig{maxTargets: DefaultMaxTargets}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.maxTargets == 0 {
		cfg.maxTargets = DefaultMaxTargets
	}

	ex, err := compileExcludes(cfg)
	if err != nil {
		return nil, err
	}

	inner := &concatSource{}
	for _, t := range cfg.targets {
		inner.raw = append(inner.raw, rawItem{text: t, source: SourceArgv})
	}
	inner.files = append(inner.files, cfg.files...)
	if cfg.useStdin {
		r := cfg.stdin
		if r == nil {
			r = os.Stdin
		}
		inner.stdin = r
	}
	if len(inner.raw) == 0 && len(inner.files) == 0 && inner.stdin == nil {
		return nil, fmt.Errorf("%w: no targets specified", ErrInvalidTarget)
	}

	var src TargetSource = inner
	src = &parseExpandSource{inner: src, max: cfg.maxTargets, strict: cfg.strict}
	if ex != nil {
		src = &excludeSource{inner: src, ex: ex}
	}
	src = &dedupSource{inner: src}
	src = &limitSource{inner: src, max: cfg.maxTargets}
	return src, nil
}

type rawItem struct {
	text   string
	source string
	file   string
	line   int
}

type parseExpandSource struct {
	inner  TargetSource
	max    uint64
	strict bool
	expand *cidrExpand
}

func (s *parseExpandSource) Next(ctx context.Context) (TargetSpec, error) {
	for {
		if err := ctx.Err(); err != nil {
			return TargetSpec{}, err
		}
		if s.expand != nil {
			spec, err := s.expand.Next(ctx)
			if err == io.EOF {
				s.expand = nil
				continue
			}
			return spec, err
		}
		raw, err := s.inner.Next(ctx)
		if err != nil {
			return TargetSpec{}, err
		}
		spec, perr := parseTarget(raw.Input, raw.Source)
		spec.File = raw.File
		spec.Line = raw.Line
		if perr != nil {
			if !s.strict && raw.File != "" {
				continue
			}
			if raw.File != "" && raw.Line > 0 {
				return TargetSpec{}, fmt.Errorf("%s:%d: %w", raw.File, raw.Line, perr)
			}
			return TargetSpec{}, perr
		}
		if spec.Kind != TargetCIDR {
			return spec, nil
		}
		exp, err := newCIDRExpand(spec, s.max)
		if err != nil {
			return TargetSpec{}, err
		}
		s.expand = exp
	}
}

type cidrExpand struct {
	net *net.IPNet
	ip  net.IP
	src TargetSpec
	v4  bool
}

func newCIDRExpand(spec TargetSpec, max uint64) (*cidrExpand, error) {
	_, n, err := net.ParseCIDR(spec.Input)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidTarget, spec.Input)
	}
	count, err := cidrHostCount(n)
	if err != nil {
		return nil, err
	}
	if count > max {
		return nil, fmt.Errorf("%w: %s expands to %d addresses (max-targets %d); raise --max-targets intentionally", ErrMaxTargets, spec.Input, count, max)
	}
	ip := n.IP.Mask(n.Mask)
	v4 := ip.To4() != nil
	if v4 {
		ip = append(net.IP(nil), ip.To4()...)
	} else {
		ip = append(net.IP(nil), ip.To16()...)
	}
	return &cidrExpand{net: n, ip: ip, src: spec, v4: v4}, nil
}

func cidrHostCount(n *net.IPNet) (uint64, error) {
	ones, bits := n.Mask.Size()
	if ones < 0 {
		return 0, fmt.Errorf("%w: invalid mask", ErrInvalidTarget)
	}
	host := bits - ones
	if host >= 64 {
		return 0, fmt.Errorf("%w: %s is too large to expand (/%d)", ErrMaxTargets, n.String(), ones)
	}
	return 1 << uint(host), nil
}

func (c *cidrExpand) Next(ctx context.Context) (TargetSpec, error) {
	if err := ctx.Err(); err != nil {
		return TargetSpec{}, err
	}
	if c.ip == nil {
		return TargetSpec{}, io.EOF
	}
	cur := append(net.IP(nil), c.ip...)
	if !c.net.Contains(cur) {
		c.ip = nil
		return TargetSpec{}, io.EOF
	}
	incIP(c.ip)
	kind := TargetIPv6
	if c.v4 {
		kind = TargetIPv4
	}
	src := SourceCIDR
	if c.src.File != "" {
		src = c.src.File
	} else if c.src.Source != "" {
		src = c.src.Source
	}
	return TargetSpec{
		Input:  cur.String(),
		Source: src,
		Kind:   kind,
		File:   c.src.File,
		Line:   c.src.Line,
	}, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

type excludeSet struct {
	ips   map[string]struct{}
	cidrs []*net.IPNet
}

func compileExcludes(cfg sourceConfig) (*excludeSet, error) {
	ex := &excludeSet{ips: map[string]struct{}{}}
	add := func(raw, where string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return nil
		}
		if ip := net.ParseIP(raw); ip != nil {
			ex.ips[ip.String()] = struct{}{}
			return nil
		}
		if _, n, err := net.ParseCIDR(raw); err == nil {
			ex.cidrs = append(ex.cidrs, n)
			return nil
		}
		if where != "" {
			return fmt.Errorf("%w: exclude %s %q", ErrInvalidTarget, where, raw)
		}
		return fmt.Errorf("%w: exclude %q", ErrInvalidTarget, raw)
	}
	for _, e := range cfg.excludes {
		if err := add(e, ""); err != nil {
			return nil, err
		}
	}
	for _, path := range cfg.excludeF {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		line := 0
		for sc.Scan() {
			line++
			text := trimBOMSpace(sc.Text())
			if err := add(text, fmt.Sprintf("%s:%d", path, line)); err != nil {
				_ = f.Close()
				return nil, err
			}
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	if len(ex.ips) == 0 && len(ex.cidrs) == 0 {
		return nil, nil
	}
	return ex, nil
}

func (e *excludeSet) hit(spec TargetSpec) bool {
	if spec.Kind == TargetHostname {
		return false
	}
	ip := net.ParseIP(spec.Input)
	if ip == nil {
		return false
	}
	if _, ok := e.ips[ip.String()]; ok {
		return true
	}
	for _, n := range e.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type excludeSource struct {
	inner TargetSource
	ex    *excludeSet
}

func (s *excludeSource) Next(ctx context.Context) (TargetSpec, error) {
	for {
		spec, err := s.inner.Next(ctx)
		if err != nil {
			return spec, err
		}
		if s.ex.hit(spec) {
			continue
		}
		return spec, nil
	}
}

type dedupSource struct {
	inner TargetSource
	seen  map[string]struct{}
}

func (s *dedupSource) Next(ctx context.Context) (TargetSpec, error) {
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	for {
		spec, err := s.inner.Next(ctx)
		if err != nil {
			return spec, err
		}
		key := string(spec.Kind) + "\x00" + spec.Input
		if spec.Kind == TargetIPv4 || spec.Kind == TargetIPv6 {
			if ip := net.ParseIP(spec.Input); ip != nil {
				key = "ip\x00" + ip.String()
			}
		}
		if _, ok := s.seen[key]; ok {
			continue
		}
		s.seen[key] = struct{}{}
		return spec, nil
	}
}

type limitSource struct {
	inner TargetSource
	max   uint64
	n     uint64
}

func (s *limitSource) Next(ctx context.Context) (TargetSpec, error) {
	spec, err := s.inner.Next(ctx)
	if err != nil {
		return spec, err
	}
	s.n++
	if s.n > s.max {
		return TargetSpec{}, fmt.Errorf("%w: admitted %d (max-targets %d)", ErrMaxTargets, s.n, s.max)
	}
	return spec, nil
}

// CollectAll drains src. Intended for tests, not large CIDRs.
func CollectAll(ctx context.Context, src TargetSource) ([]TargetSpec, error) {
	var out []TargetSpec
	for {
		spec, err := src.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, spec)
	}
}

func trimBOMSpace(s string) string {
	return strings.TrimSpace(strings.TrimPrefix(s, "\ufeff"))
}
