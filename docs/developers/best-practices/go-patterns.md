---
title: "Go Patterns"
description: "Go coding patterns and idioms for Prime Radiant development."
template: "TEMPLATE.guide"
version: "0.1.0"
last_updated: "2026-01-14"
author: "Project Team"
tags: ["go", "patterns", "idioms", "coding"]
categories: ["development", "best-practices"]
difficulty: "intermediate"
prerequisites: []
related_docs:
  - "README.md"
  - "error-handling.md"
dependencies: []
llm_context: "high"
search_keywords: ["go", "patterns", "idioms", "golang", "coding patterns"]
---

# Go Patterns

## Purpose

This document covers Go coding patterns and idioms used in ping++. Following these patterns ensures consistency and leverages Go's strengths.

## Naming Conventions

### Packages

Use short, lowercase names:

```go
// Good
package vulnerability
package ingest
package transform

// Bad
package vulnerabilityHandler
package IngestService
```

### Variables and Functions

Use camelCase, with exported items starting uppercase:

```go
// Exported (public)
func NormalizeSeverity(score float64) string { ... }
type Vulnerability struct { ... }

// Unexported (private)
func parseRawData(data []byte) (map[string]any, error) { ... }
var defaultTimeout = 30 * time.Second
```

### Interfaces

Use `-er` suffix for single-method interfaces:

```go
// Good
type Reader interface {
    Read(p []byte) (n int, err error)
}

type VulnerabilityStore interface {
    Get(ctx context.Context, id string) (*Vulnerability, error)
    Save(ctx context.Context, v *Vulnerability) error
}

// Name describes behavior
type Normalizer interface {
    Normalize(source SourceData) (*Vulnerability, error)
}
```

### Constants

Use PascalCase for exported, camelCase for unexported:

```go
const (
    // Exported
    MaxBatchSize    = 1000
    DefaultTimeout  = 30 * time.Second
    
    // Unexported
    defaultRetries  = 3
    internalVersion = "1.0.0"
)
```

## Struct Patterns

### Constructor Functions

Use `New` prefix for constructors:

```go
type Handler struct {
    store  VulnerabilityStore
    logger *slog.Logger
    config Config
}

func NewHandler(store VulnerabilityStore, logger *slog.Logger, config Config) *Handler {
    return &Handler{
        store:  store,
        logger: logger,
        config: config,
    }
}

// With functional options
func NewHandler(store VulnerabilityStore, opts ...Option) *Handler {
    h := &Handler{
        store:   store,
        logger:  slog.Default(),
        timeout: 30 * time.Second,
    }
    for _, opt := range opts {
        opt(h)
    }
    return h
}
```

### Functional Options

Use for optional configuration:

```go
type Option func(*Handler)

func WithLogger(logger *slog.Logger) Option {
    return func(h *Handler) {
        h.logger = logger
    }
}

func WithTimeout(d time.Duration) Option {
    return func(h *Handler) {
        h.timeout = d
    }
}

// Usage
handler := NewHandler(store,
    WithLogger(customLogger),
    WithTimeout(60 * time.Second),
)
```

### Method Receivers

Use pointer receivers for consistency and mutation:

```go
// Pointer receiver - preferred for structs with state
func (h *Handler) Process(ctx context.Context, v *Vulnerability) error {
    h.logger.Info("processing vulnerability", "id", v.ID)
    return h.store.Save(ctx, v)
}

// Value receiver - for small, immutable types
func (id VulnerabilityID) String() string {
    return string(id)
}
```

## Interface Patterns

### Accept Interfaces, Return Structs

```go
// Good: Function accepts interface
func ProcessVulnerability(store VulnerabilityStore, v *Vulnerability) error {
    return store.Save(context.Background(), v)
}

// Good: Factory returns concrete type
func NewMemoryStore() *MemoryStore {
    return &MemoryStore{data: make(map[string]*Vulnerability)}
}

// Bad: Factory returns interface (hides implementation)
func NewStore() VulnerabilityStore {
    return &MemoryStore{...}
}
```

### Small Interfaces

Prefer small, focused interfaces:

```go
// Good: Small, focused interfaces
type Reader interface {
    Get(ctx context.Context, id string) (*Vulnerability, error)
}

type Writer interface {
    Save(ctx context.Context, v *Vulnerability) error
}

type ReadWriter interface {
    Reader
    Writer
}

// Bad: Large interface
type VulnerabilityService interface {
    Get(id string) (*Vulnerability, error)
    Save(v *Vulnerability) error
    Delete(id string) error
    List() ([]*Vulnerability, error)
    Search(query string) ([]*Vulnerability, error)
    Normalize(data []byte) (*Vulnerability, error)
    // ... many more methods
}
```

## Context Usage

### Always Pass Context First

```go
// Good
func (h *Handler) Process(ctx context.Context, v *Vulnerability) error {
    return h.store.Save(ctx, v)
}

// Bad
func (h *Handler) Process(v *Vulnerability, ctx context.Context) error {
    return h.store.Save(ctx, v)
}
```

### Use Context for Cancellation

```go
func (h *Handler) ProcessBatch(ctx context.Context, items []*Vulnerability) error {
    for _, item := range items {
        // Check for cancellation
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        if err := h.processOne(ctx, item); err != nil {
            return err
        }
    }
    return nil
}
```

### Context Values Sparingly

```go
// Define typed key to avoid collisions
type contextKey string

const (
    correlationIDKey contextKey = "correlation_id"
)

// Set value
ctx = context.WithValue(ctx, correlationIDKey, "abc123")

// Get value with type assertion
if id, ok := ctx.Value(correlationIDKey).(string); ok {
    // use id
}
```

## Concurrency Patterns

### Use sync.WaitGroup for Goroutines

```go
func processInParallel(items []*Vulnerability) error {
    var wg sync.WaitGroup
    errChan := make(chan error, len(items))

    for _, item := range items {
        wg.Add(1)
        go func(v *Vulnerability) {
            defer wg.Done()
            if err := process(v); err != nil {
                errChan <- err
            }
        }(item)
    }

    wg.Wait()
    close(errChan)

    // Return first error
    for err := range errChan {
        return err
    }
    return nil
}
```

### Use errgroup for Error Handling

```go
import "golang.org/x/sync/errgroup"

func processInParallel(ctx context.Context, items []*Vulnerability) error {
    g, ctx := errgroup.WithContext(ctx)

    for _, item := range items {
        item := item // Capture loop variable
        g.Go(func() error {
            return process(ctx, item)
        })
    }

    return g.Wait() // Returns first error
}
```

### Channel Patterns

```go
// Generator pattern
func generateIDs(ctx context.Context, count int) <-chan string {
    out := make(chan string)
    go func() {
        defer close(out)
        for i := 0; i < count; i++ {
            select {
            case <-ctx.Done():
                return
            case out <- fmt.Sprintf("PR-2026-%06d", i):
            }
        }
    }()
    return out
}

// Pipeline pattern
func normalize(in <-chan SourceData) <-chan *Vulnerability {
    out := make(chan *Vulnerability)
    go func() {
        defer close(out)
        for data := range in {
            if v, err := normalizeOne(data); err == nil {
                out <- v
            }
        }
    }()
    return out
}
```

## Testing Patterns

### Table-Driven Tests

```go
func TestNormalizeSeverity(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected float64
    }{
        {"critical", "critical", 9.5},
        {"high", "high", 8.0},
        {"medium", "medium", 5.0},
        {"low", "low", 2.0},
        {"none", "none", 0.0},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := normalizeSeverity(tt.input)
            if result != tt.expected {
                t.Errorf("normalizeSeverity(%q) = %v, want %v",
                    tt.input, result, tt.expected)
            }
        })
    }
}
```

### Test Helpers

```go
// Helper function in test file
func newTestVulnerability(t *testing.T, id string) *Vulnerability {
    t.Helper() // Marks this as a helper
    return &Vulnerability{
        ID:    id,
        Title: "Test Vulnerability",
        Severity: Severity{
            NormalizedScore: 8.0,
            NormalizedLevel: "high",
        },
    }
}

func TestHandler(t *testing.T) {
    v := newTestVulnerability(t, "PR-2026-000001")
    // test using v
}
```

## JSON Patterns

### Struct Tags

```go
type Vulnerability struct {
    ID          string   `json:"id"`
    Title       string   `json:"title"`
    Description string   `json:"description,omitempty"`
    Score       float64  `json:"score"`
    Tags        []string `json:"tags,omitempty"`
    internal    string   // Not exported, not serialized
}
```

### Custom Marshaling

```go
type Timestamp time.Time

func (t Timestamp) MarshalJSON() ([]byte, error) {
    return []byte(fmt.Sprintf(`"%s"`, time.Time(t).Format(time.RFC3339))), nil
}

func (t *Timestamp) UnmarshalJSON(data []byte) error {
    var s string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    parsed, err := time.Parse(time.RFC3339, s)
    if err != nil {
        return err
    }
    *t = Timestamp(parsed)
    return nil
}
```

## Related Documentation

- [Best Practices Overview](README.md)
- [Error Handling](error-handling.md)
- [Logging Standards](logging.md)
