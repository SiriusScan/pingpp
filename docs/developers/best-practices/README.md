---
title: "Best Practices Overview"
description: "Overview of coding and development best practices for the Prime Radiant system."
template: "TEMPLATE.documentation-standard"
version: "0.1.0"
last_updated: "2026-01-14"
author: "Project Team"
tags: ["best-practices", "coding", "standards", "overview"]
categories: ["development", "best-practices"]
difficulty: "intermediate"
prerequisites: []
related_docs:
  - "go-patterns.md"
  - "error-handling.md"
  - "logging.md"
dependencies: []
llm_context: "high"
search_keywords: ["best practices", "coding standards", "patterns", "guidelines"]
---

# Best Practices Overview

## Purpose

This section documents coding and development best practices for the Prime Radiant system. Following these practices ensures consistency, maintainability, and reliability across all components.

## Best Practice Categories

### Code Quality

| Practice | Document | Priority |
|----------|----------|----------|
| Go patterns and idioms | [go-patterns.md](go-patterns.md) | High |
| Error handling | [error-handling.md](error-handling.md) | High |
| Logging standards | [logging.md](logging.md) | High |

### Development Process

| Practice | Reference |
|----------|-----------|
| Lambda conventions | [Lambda Conventions](../guides/lambda-conventions.md) |
| Testing strategies | [Testing Lambdas](../guides/testing-lambdas.md) |
| Schema contributions | [Schema Contributions](../guides/schema-contributions.md) |

## Core Principles

### 1. Clarity Over Cleverness

Write code that is easy to understand:

```go
// Good: Clear and explicit
func getUserByID(id string) (*User, error) {
    if id == "" {
        return nil, ErrInvalidID
    }
    return db.FindUser(id)
}

// Bad: Clever but confusing
func getU(i string) (*User, error) {
    return i != "" ? db.FindUser(i) : nil, ErrInvalidID
}
```

### 2. Fail Fast

Validate early and return errors immediately:

```go
func processVulnerability(v *Vulnerability) error {
    // Validate first
    if v == nil {
        return errors.New("vulnerability is nil")
    }
    if v.ID == "" {
        return errors.New("vulnerability ID is required")
    }
    
    // Then process
    return doProcessing(v)
}
```

### 3. Single Responsibility

Each function/package should do one thing well:

```go
// Good: Focused functions
func validateVulnerability(v *Vulnerability) error { ... }
func normalizeVulnerability(v *Vulnerability) (*Canonical, error) { ... }
func storeVulnerability(v *Canonical) error { ... }

// Bad: Function doing too much
func handleVulnerability(v *Vulnerability) error {
    // validates, normalizes, stores, logs, notifies, etc.
}
```

### 4. Explicit Dependencies

Pass dependencies explicitly rather than using globals:

```go
// Good: Explicit dependencies
type Handler struct {
    store  VulnerabilityStore
    logger *slog.Logger
}

func NewHandler(store VulnerabilityStore, logger *slog.Logger) *Handler {
    return &Handler{store: store, logger: logger}
}

// Bad: Global dependencies
var globalStore VulnerabilityStore

func Handle(v *Vulnerability) error {
    return globalStore.Save(v) // Hidden dependency
}
```

### 5. Test-Driven Development

Write tests before or alongside implementation:

```go
// Write the test first
func TestNormalizeSeverity_High_Returns8(t *testing.T) {
    result := normalizeSeverity("high")
    if result != 8.0 {
        t.Errorf("expected 8.0, got %f", result)
    }
}

// Then implement to pass the test
func normalizeSeverity(level string) float64 {
    switch level {
    case "high":
        return 8.0
    // ...
    }
}
```

## Code Review Checklist

When reviewing code, check for:

### Correctness
- [ ] Code does what it claims to do
- [ ] Edge cases are handled
- [ ] Error paths are tested

### Readability
- [ ] Clear variable and function names
- [ ] Appropriate comments for complex logic
- [ ] Consistent formatting

### Best Practices
- [ ] Follows Go idioms
- [ ] Proper error handling with context
- [ ] Structured logging
- [ ] No hardcoded values

### Testing
- [ ] Unit tests for business logic
- [ ] Table-driven tests where appropriate
- [ ] Error cases are tested

### Documentation
- [ ] Public functions are documented
- [ ] README is updated if needed
- [ ] Complex algorithms are explained

## Anti-Patterns to Avoid

### 1. Empty Error Handling

```go
// Bad: Ignoring errors
result, _ := doSomething()

// Good: Handle or propagate errors
result, err := doSomething()
if err != nil {
    return fmt.Errorf("doing something: %w", err)
}
```

### 2. Naked Returns in Long Functions

```go
// Bad: Naked return in long function
func process() (result string, err error) {
    // 50 lines of code...
    return // What is being returned?
}

// Good: Explicit returns
func process() (string, error) {
    // ...
    return result, nil
}
```

### 3. Panic in Libraries

```go
// Bad: Panic in library code
func ParseID(s string) ID {
    if !isValid(s) {
        panic("invalid ID") // Crashes the caller
    }
}

// Good: Return error
func ParseID(s string) (ID, error) {
    if !isValid(s) {
        return ID{}, ErrInvalidID
    }
}
```

### 4. Stringly-Typed Code

```go
// Bad: Magic strings
if status == "completed" { ... }

// Good: Use constants or enums
const StatusCompleted = "completed"
if status == StatusCompleted { ... }

// Better: Use typed constants
type Status string
const StatusCompleted Status = "completed"
```

## Quick Reference

| Topic | Key Points |
|-------|------------|
| Naming | Use clear, descriptive names; follow Go conventions |
| Errors | Always handle errors; add context when wrapping |
| Logging | Use structured logging; include correlation IDs |
| Testing | Write tests; aim for 80%+ coverage on business logic |
| Comments | Explain why, not what; document public APIs |

## Related Documentation

- [Go Patterns](go-patterns.md)
- [Error Handling](error-handling.md)
- [Logging Standards](logging.md)
- [Lambda Conventions](../guides/lambda-conventions.md)
