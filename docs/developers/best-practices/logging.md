---
title: "Logging Standards"
description: "Structured logging guidelines and patterns for Prime Radiant services."
template: "TEMPLATE.guide"
version: "0.1.0"
last_updated: "2026-01-14"
author: "Project Team"
tags: ["logging", "observability", "slog", "best-practices"]
categories: ["development", "best-practices"]
difficulty: "intermediate"
prerequisites: []
related_docs:
  - "README.md"
  - "error-handling.md"
dependencies: []
llm_context: "high"
search_keywords: ["logging", "slog", "structured logging", "observability"]
---

# Logging Standards

## Purpose

This guide defines logging standards for Prime Radiant services. Consistent, structured logging is essential for debugging, monitoring, and incident response.

## Use slog

Prime Radiant uses Go's `log/slog` package (Go 1.21+) for structured logging:

```go
import "log/slog"

func main() {
    slog.Info("server starting", "port", 8080)
}
```

## Log Levels

### Level Guidelines

| Level | When to Use | Examples |
|-------|-------------|----------|
| `DEBUG` | Detailed debugging info | Request/response bodies, loop iterations |
| `INFO` | Normal operations | Request received, task completed |
| `WARN` | Unexpected but handled | Retry triggered, deprecated usage |
| `ERROR` | Errors requiring attention | Failed operations, unhandled errors |

### Examples

```go
// DEBUG: Detailed tracing (verbose, use sparingly)
slog.Debug("parsing source data",
    "source_type", sourceType,
    "data_size", len(data),
)

// INFO: Normal operations
slog.Info("vulnerability ingested",
    "canonical_id", v.ID,
    "source_type", source.Type,
    "source_id", source.ID,
)

// WARN: Unusual but handled situations
slog.Warn("retrying database connection",
    "attempt", attempt,
    "max_attempts", maxAttempts,
    "error", err,
)

// ERROR: Failures requiring attention
slog.Error("failed to process vulnerability",
    "source_id", source.ID,
    "error", err,
)
```

## Structured Logging

### Always Use Key-Value Pairs

```go
// Good: Structured key-value pairs
slog.Info("processing complete",
    "canonical_id", v.ID,
    "duration_ms", elapsed.Milliseconds(),
    "sources_count", len(v.Sources),
)

// Bad: Unstructured message
slog.Info(fmt.Sprintf("processed %s in %dms with %d sources",
    v.ID, elapsed.Milliseconds(), len(v.Sources)))
```

### Use Consistent Key Names

Standard keys across the codebase:

| Key | Description | Example |
|-----|-------------|---------|
| `canonical_id` | Prime Radiant vulnerability ID | `PR-2026-000001` |
| `source_type` | Source system type | `sirius`, `nessus` |
| `source_id` | Source system's ID | `SIRIUS-2026-001` |
| `request_id` | Request correlation ID | `abc123` |
| `duration_ms` | Operation duration | `150` |
| `error` | Error value | `err` |
| `count` | Generic count | `42` |

### Avoid These Key Names

- `msg` - Reserved by slog
- `time` - Reserved by slog
- `level` - Reserved by slog

## Logger Configuration

### Configure at Startup

```go
package main

import (
    "log/slog"
    "os"
)

func main() {
    // Configure based on environment
    level := parseLogLevel(os.Getenv("PR_LOG_LEVEL"))

    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: level,
    })

    slog.SetDefault(slog.New(handler))

    // Now all slog calls use this configuration
    slog.Info("server starting", "log_level", level.String())
}

func parseLogLevel(s string) slog.Level {
    switch strings.ToUpper(s) {
    case "DEBUG":
        return slog.LevelDebug
    case "WARN":
        return slog.LevelWarn
    case "ERROR":
        return slog.LevelError
    default:
        return slog.LevelInfo
    }
}
```

### JSON Output for Production

Use JSON handler for Lambda/production:

```go
handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
})
```

Output:
```json
{"time":"2026-01-14T10:30:00Z","level":"INFO","msg":"request processed","canonical_id":"PR-2026-000001","duration_ms":45}
```

### Text Output for Development

Use text handler for local development:

```go
handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
})
```

Output:
```
time=2026-01-14T10:30:00Z level=INFO msg="request processed" canonical_id=PR-2026-000001 duration_ms=45
```

## Context-Aware Logging

### Logger with Context

Add common fields to a logger:

```go
func HandleRequest(ctx context.Context, req Request) (Response, error) {
    // Create logger with request context
    logger := slog.With(
        "request_id", ctx.Value("request_id"),
        "source_type", req.SourceType,
    )

    logger.Info("request received")

    result, err := process(ctx, req)
    if err != nil {
        logger.Error("processing failed", "error", err)
        return errorResponse(err)
    }

    logger.Info("request completed",
        "canonical_id", result.ID,
        "duration_ms", time.Since(start).Milliseconds(),
    )

    return successResponse(result)
}
```

### Pass Logger Through

Pass logger to functions that need it:

```go
type Handler struct {
    logger *slog.Logger
    store  VulnerabilityStore
}

func (h *Handler) Process(ctx context.Context, v *Vulnerability) error {
    h.logger.Info("processing vulnerability", "id", v.ID)

    if err := h.normalize(ctx, v); err != nil {
        h.logger.Error("normalization failed", "id", v.ID, "error", err)
        return err
    }

    return nil
}
```

## Request Correlation

### Add Request IDs

Include a correlation ID in all logs for a request:

```go
func Handler(ctx context.Context, req Request) (Response, error) {
    requestID := generateRequestID()
    ctx = context.WithValue(ctx, "request_id", requestID)

    logger := slog.With("request_id", requestID)

    // All logs for this request include the request_id
    logger.Info("request started")
    // ...
    logger.Info("request completed")

    return response, nil
}
```

### Propagate Through Calls

```go
func processVulnerability(logger *slog.Logger, v *Vulnerability) error {
    // Logger already has request_id from caller
    logger.Debug("starting normalization")

    if err := normalize(v); err != nil {
        logger.Error("normalization failed", "error", err)
        return err
    }

    logger.Debug("normalization complete")
    return nil
}
```

## What to Log

### DO Log

```go
// Request entry/exit
slog.Info("request received", "endpoint", "/vulnerabilities", "method", "POST")
slog.Info("request completed", "status", 200, "duration_ms", 45)

// Business operations
slog.Info("vulnerability ingested", "canonical_id", v.ID, "status", "created")
slog.Info("batch processed", "total", 100, "succeeded", 98, "failed", 2)

// Errors with context
slog.Error("database query failed", "query", "get_vulnerability", "id", id, "error", err)

// State changes
slog.Info("cache invalidated", "key", cacheKey, "reason", "ttl_expired")

// Performance metrics
slog.Info("operation completed", "operation", "normalize", "duration_ms", 150)
```

### DON'T Log

```go
// Sensitive data
slog.Info("user authenticated", "password", password) // NEVER!
slog.Info("request received", "api_key", apiKey) // NEVER!

// High-volume debug in production
for _, item := range items {
    slog.Debug("processing item", "item", item) // Too noisy
}

// Duplicate information
slog.Error("error occurred", "error", err, "error_message", err.Error()) // Redundant

// Personally identifiable information (PII)
slog.Info("user action", "email", user.Email, "ssn", user.SSN) // NEVER!
```

## Error Logging

### Log Error Details

Include enough context to debug:

```go
func (h *Handler) Process(ctx context.Context, req Request) error {
    result, err := h.store.Get(ctx, req.ID)
    if err != nil {
        // Include: operation, identifiers, error
        h.logger.Error("failed to fetch vulnerability",
            "operation", "store.Get",
            "vulnerability_id", req.ID,
            "error", err,
        )
        return err
    }
    return nil
}
```

### Don't Log and Throw

Either log OR return the error, not both (unless at boundary):

```go
// Bad: Logs at every level
func level1(id string) error {
    err := level2(id)
    if err != nil {
        log.Error("level1 failed", "error", err) // Logged
        return err                                // Also returned
    }
}

func level2(id string) error {
    err := level3(id)
    if err != nil {
        log.Error("level2 failed", "error", err) // Logged again!
        return err
    }
}

// Good: Log at top level only
func Handler(req Request) (Response, error) {
    result, err := process(req)
    if err != nil {
        slog.Error("request failed", "error", err) // Log once
        return errorResponse(err)
    }
    return successResponse(result)
}

func process(req Request) (*Result, error) {
    // Add context, but don't log
    return nil, fmt.Errorf("processing %s: %w", req.ID, err)
}
```

## Testing with Logs

### Capture Logs in Tests

```go
func TestHandler_LogsRequestID(t *testing.T) {
    // Create buffer to capture logs
    var buf bytes.Buffer
    logger := slog.New(slog.NewJSONHandler(&buf, nil))

    handler := NewHandler(logger, mockStore)
    handler.Process(context.Background(), testRequest)

    // Verify log output
    output := buf.String()
    if !strings.Contains(output, "request_id") {
        t.Error("expected log to contain request_id")
    }
}
```

### Disable Logging in Tests

For quieter tests:

```go
func TestMain(m *testing.M) {
    // Suppress logs during tests
    slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
    os.Exit(m.Run())
}
```

## Lambda-Specific Guidelines

### Log Lambda Invocation

```go
func Handler(ctx context.Context, req Request) (Response, error) {
    start := time.Now()
    requestID := ctx.Value("request_id")

    slog.Info("lambda invocation started",
        "request_id", requestID,
        "function_name", os.Getenv("AWS_LAMBDA_FUNCTION_NAME"),
    )

    result, err := process(ctx, req)

    slog.Info("lambda invocation completed",
        "request_id", requestID,
        "duration_ms", time.Since(start).Milliseconds(),
        "success", err == nil,
    )

    if err != nil {
        return errorResponse(err)
    }
    return successResponse(result)
}
```

## Related Documentation

- [Best Practices Overview](README.md)
- [Error Handling](error-handling.md)
- [Go Patterns](go-patterns.md)
