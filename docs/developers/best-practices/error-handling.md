---
title: "Error Handling"
description: "Error handling guidelines and patterns for Prime Radiant Go code."
template: "TEMPLATE.guide"
version: "0.1.0"
last_updated: "2026-01-14"
author: "Project Team"
tags: ["error-handling", "errors", "go", "best-practices"]
categories: ["development", "best-practices"]
difficulty: "intermediate"
prerequisites: []
related_docs:
  - "README.md"
  - "go-patterns.md"
  - "logging.md"
dependencies: []
llm_context: "high"
search_keywords: ["error handling", "errors", "go errors", "error wrapping"]
---

# Error Handling

## Purpose

This guide covers error handling patterns for Prime Radiant Go code. Proper error handling is critical for debugging, observability, and system reliability.

## Core Principles

### 1. Always Handle Errors

Never ignore errors:

```go
// Bad: Ignoring error
result, _ := doSomething()

// Good: Handle the error
result, err := doSomething()
if err != nil {
    return fmt.Errorf("doing something: %w", err)
}
```

### 2. Add Context When Wrapping

Use `fmt.Errorf` with `%w` to wrap errors with context:

```go
func processVulnerability(id string) error {
    v, err := store.Get(id)
    if err != nil {
        return fmt.Errorf("getting vulnerability %s: %w", id, err)
    }

    if err := normalize(v); err != nil {
        return fmt.Errorf("normalizing vulnerability %s: %w", id, err)
    }

    return nil
}
```

This produces error messages like:
```
normalizing vulnerability PR-2026-000001: invalid severity value: unknown
```

### 3. Handle Errors at the Right Level

Handle errors where you can do something meaningful:

```go
// Low-level: Just return the error
func fetchFromDB(id string) (*Record, error) {
    row := db.QueryRow("SELECT * FROM vulnerabilities WHERE id = ?", id)
    // ...
    if err != nil {
        return nil, err // Let caller decide what to do
    }
}

// Mid-level: Add context, maybe retry
func GetVulnerability(id string) (*Vulnerability, error) {
    record, err := fetchFromDB(id)
    if err != nil {
        return nil, fmt.Errorf("fetching vulnerability %s: %w", id, err)
    }
    return toVulnerability(record), nil
}

// Top-level: Log and respond to user
func HandleRequest(w http.ResponseWriter, r *http.Request) {
    v, err := GetVulnerability(r.URL.Query().Get("id"))
    if err != nil {
        slog.Error("failed to get vulnerability", "error", err)
        http.Error(w, "Internal error", 500)
        return
    }
    // ...
}
```

## Error Types

### Sentinel Errors

Define package-level errors for expected conditions:

```go
package vulnerability

import "errors"

var (
    ErrNotFound     = errors.New("vulnerability not found")
    ErrInvalidID    = errors.New("invalid vulnerability ID")
    ErrDuplicate    = errors.New("vulnerability already exists")
)
```

Check for sentinel errors:

```go
v, err := store.Get(id)
if errors.Is(err, vulnerability.ErrNotFound) {
    // Handle not found case
    return nil, nil
}
if err != nil {
    return nil, err
}
```

### Custom Error Types

For errors that need additional context:

```go
type ValidationError struct {
    Field   string
    Message string
    Value   any
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation error on field %q: %s", e.Field, e.Message)
}

// Usage
func validateSeverity(score float64) error {
    if score < 0 || score > 10 {
        return &ValidationError{
            Field:   "severity.normalized_score",
            Message: "must be between 0 and 10",
            Value:   score,
        }
    }
    return nil
}

// Checking for type
var validationErr *ValidationError
if errors.As(err, &validationErr) {
    // Handle validation error specifically
    log.Printf("Invalid field: %s", validationErr.Field)
}
```

### Error Wrapping with Type

Wrap errors while preserving type information:

```go
type SourceError struct {
    Source string
    Err    error
}

func (e *SourceError) Error() string {
    return fmt.Sprintf("source %s: %v", e.Source, e.Err)
}

func (e *SourceError) Unwrap() error {
    return e.Err
}

// Usage
err := &SourceError{Source: "nessus", Err: ErrInvalidFormat}

// Both work:
errors.Is(err, ErrInvalidFormat)  // true
var srcErr *SourceError
errors.As(err, &srcErr)           // true
```

## Lambda Error Handling

### HTTP-like Responses

For Lambda functions returning HTTP responses:

```go
type Response struct {
    StatusCode int               `json:"statusCode"`
    Headers    map[string]string `json:"headers"`
    Body       string            `json:"body"`
}

func Handler(ctx context.Context, req Request) (Response, error) {
    v, err := processRequest(req)
    if err != nil {
        return handleError(err)
    }
    return successResponse(v)
}

func handleError(err error) (Response, error) {
    // Map errors to HTTP status codes
    var validationErr *ValidationError
    if errors.As(err, &validationErr) {
        return errorResponse(400, "validation_error", validationErr.Message)
    }

    if errors.Is(err, ErrNotFound) {
        return errorResponse(404, "not_found", "Vulnerability not found")
    }

    // Log unexpected errors
    slog.Error("unexpected error", "error", err)
    return errorResponse(500, "internal_error", "An internal error occurred")
}

func errorResponse(status int, code, message string) (Response, error) {
    body, _ := json.Marshal(map[string]string{
        "code":    code,
        "message": message,
    })
    return Response{
        StatusCode: status,
        Headers:    map[string]string{"Content-Type": "application/json"},
        Body:       string(body),
    }, nil
}
```

### Logging Errors

Log errors with context at the appropriate level:

```go
func Handler(ctx context.Context, req Request) (Response, error) {
    logger := slog.With(
        "request_id", ctx.Value("request_id"),
        "source_type", req.SourceType,
    )

    result, err := process(ctx, req)
    if err != nil {
        // Log with full context
        logger.Error("processing failed",
            "error", err,
            "source_id", req.SourceID,
        )

        // Return sanitized error to client
        return errorResponse(500, "processing_failed", "Failed to process request")
    }

    logger.Info("processing succeeded", "canonical_id", result.ID)
    return successResponse(result)
}
```

## Error Checking Patterns

### Multiple Returns

Check errors before using results:

```go
// Good: Check error immediately
data, err := fetch()
if err != nil {
    return err
}
process(data)

// Bad: Using result before checking error
data, err := fetch()
process(data) // data might be nil or invalid!
if err != nil {
    return err
}
```

### Early Returns

Use early returns to reduce nesting:

```go
// Good: Early returns
func process(v *Vulnerability) error {
    if v == nil {
        return errors.New("vulnerability is nil")
    }
    if v.ID == "" {
        return errors.New("vulnerability ID is required")
    }
    if v.Title == "" {
        return errors.New("vulnerability title is required")
    }

    // Main logic here
    return nil
}

// Bad: Deep nesting
func process(v *Vulnerability) error {
    if v != nil {
        if v.ID != "" {
            if v.Title != "" {
                // Main logic here
                return nil
            } else {
                return errors.New("vulnerability title is required")
            }
        } else {
            return errors.New("vulnerability ID is required")
        }
    } else {
        return errors.New("vulnerability is nil")
    }
}
```

### Defer for Cleanup

Use defer for cleanup even when errors occur:

```go
func processFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("opening file: %w", err)
    }
    defer f.Close() // Always closes, even if error below

    data, err := io.ReadAll(f)
    if err != nil {
        return fmt.Errorf("reading file: %w", err)
    }

    return process(data)
}
```

## Testing Errors

### Test Error Cases

Always test error paths:

```go
func TestGetVulnerability_NotFound(t *testing.T) {
    store := &MockStore{
        GetFunc: func(ctx context.Context, id string) (*Vulnerability, error) {
            return nil, ErrNotFound
        },
    }

    _, err := GetVulnerability(context.Background(), store, "nonexistent")

    if !errors.Is(err, ErrNotFound) {
        t.Errorf("expected ErrNotFound, got %v", err)
    }
}

func TestGetVulnerability_ValidationError(t *testing.T) {
    _, err := GetVulnerability(context.Background(), store, "")

    var validationErr *ValidationError
    if !errors.As(err, &validationErr) {
        t.Errorf("expected ValidationError, got %T", err)
    }
    if validationErr.Field != "id" {
        t.Errorf("expected field 'id', got %q", validationErr.Field)
    }
}
```

### Test Error Messages

Verify error messages when important:

```go
func TestValidateSeverity_OutOfRange(t *testing.T) {
    err := validateSeverity(15.0)

    if err == nil {
        t.Fatal("expected error, got nil")
    }
    if !strings.Contains(err.Error(), "between 0 and 10") {
        t.Errorf("error message should mention range, got: %s", err.Error())
    }
}
```

## Anti-Patterns

### Don't Panic in Libraries

```go
// Bad: Panics on invalid input
func MustParseID(s string) ID {
    id, err := ParseID(s)
    if err != nil {
        panic(err) // Crashes caller!
    }
    return id
}

// Good: Return error
func ParseID(s string) (ID, error) {
    if !validIDPattern.MatchString(s) {
        return ID{}, ErrInvalidID
    }
    return ID(s), nil
}

// OK: Panic in main/init for configuration errors
func main() {
    config, err := loadConfig()
    if err != nil {
        panic(fmt.Sprintf("failed to load config: %v", err))
    }
}
```

### Don't Swallow Errors

```go
// Bad: Error is logged but not propagated
func process(v *Vulnerability) {
    if err := store.Save(v); err != nil {
        log.Printf("failed to save: %v", err)
        // Caller has no idea this failed!
    }
}

// Good: Return the error
func process(v *Vulnerability) error {
    if err := store.Save(v); err != nil {
        return fmt.Errorf("saving vulnerability: %w", err)
    }
    return nil
}
```

## Related Documentation

- [Best Practices Overview](README.md)
- [Go Patterns](go-patterns.md)
- [Logging Standards](logging.md)
