# ping++ Project Plan

## Project Overview

**Project Name**: ping++
**Version**: 1.0.0
**Start Date**: 2026-02-02
**Target Completion**: TBD (estimate: 2-3 development cycles)

## Objectives

1. Build a modular Go network enumeration and OS fingerprinting tool
2. Follow ProjectDiscovery library-first patterns for reusability
3. Integrate seamlessly with Sirius app-scanner ecosystem
4. Enable developers to easily extend with new probe types

## Milestones

### Milestone 1: Project Setup and Foundation

**Status**: 🔄 In Progress

- [x] Create project folder from template
- [x] Complete PRD.txt with requirements
- [x] Create detailed task breakdown
- [ ] Initialize Go module
- [ ] Define core interfaces (Probe, Options, Result)
- [ ] Create Runner skeleton

### Milestone 2: Core Probes

**Status**: ⏱️ Pending

- [ ] Implement ICMP probe with TTL capture
- [ ] Implement TCP SYN probe
- [ ] Implement TTL-based OS detection
- [ ] Implement result aggregation

### Milestone 3: Advanced Probes

**Status**: ⏱️ Pending

- [ ] Implement ARP probe for Layer 2
- [ ] Implement SMB probe for Windows detection

### Milestone 4: Runner and Integration

**Status**: ⏱️ Pending

- [ ] Complete Runner with worker pool
- [ ] Implement OnResult callback system
- [ ] Create FingerprintStrategy adapter
- [ ] Verify go-api type compatibility

### Milestone 5: CLI and Polish

**Status**: ⏱️ Pending

- [ ] Implement CLI with goflags
- [ ] Add JSON output format
- [ ] Create library usage examples
- [ ] Write unit tests
- [ ] Set up CI/CD pipeline
- [ ] Complete documentation

## Task Organization

Tasks are tracked in `tasks/ping++-tasks.json`:

- **Phase 1**: Project Setup and Foundation (8 tasks)
- **Phase 2**: Core Probes (4 tasks)
- **Phase 3**: Advanced Probes (2 tasks)
- **Phase 4**: Runner and Integration (4 tasks)
- **Phase 5**: CLI and Polish (7 tasks)

**Total**: 25 tasks across 5 phases

## Progress Tracking

### Current Status

- **Completed**: Tasks 1.1, 1.2
- **In Progress**: Task 1.3
- **Pending**: All remaining tasks

### Task Dependencies

```
Phase 1 (Setup)
├── 1.1 Create project folder ✅
├── 1.2 Complete PRD ✅
├── 1.3 Create tasks file 🔄
├── 1.4 Initialize go.mod
│   ├── 1.5 Define Probe interface
│   ├── 1.6 Define Options struct
│   └── 1.7 Define Result types
│       └── 1.8 Create Runner skeleton
│
Phase 2 (Core Probes) [depends on 1]
├── 2.1 ICMP probe
├── 2.2 TCP probe
├── 2.3 TTL detection [depends on 2.1]
└── 2.4 Result aggregation [depends on 2.1, 2.2, 2.3]
│
Phase 3 (Advanced) [depends on 2]
├── 3.1 ARP probe [depends on 2.4]
└── 3.2 SMB probe [depends on 2.4]
│
Phase 4 (Integration) [depends on 2]
├── 4.1 Runner implementation [depends on 2.4]
├── 4.2 OnResult callback [depends on 4.1]
├── 4.3 FingerprintStrategy [depends on 4.1]
└── 4.4 go-api compatibility [depends on 4.3]
│
Phase 5 (Polish) [depends on 4]
├── 5.1 CLI implementation [depends on 4.2]
├── 5.2 JSON output [depends on 5.1]
├── 5.3 Examples [depends on 4.2]
├── 5.4 Unit tests [depends on 2.4, 4.2]
├── 5.5 CI/CD [depends on 5.4]
├── 5.6 Documentation [depends on 5.1]
└── 5.7 Cleanup [depends on 5.1-5.6]
```

## Architecture

### Directory Structure (Target)

```
ping++/
├── cmd/pingpp/main.go           # CLI entry point
├── pkg/
│   ├── runner/
│   │   ├── options.go           # Options struct
│   │   ├── runner.go            # Runner implementation
│   │   └── result.go            # Result types
│   └── probes/
│       ├── probe.go             # Probe interface
│       ├── icmp/icmp.go         # ICMP probe
│       ├── tcp/tcp.go           # TCP probe
│       ├── arp/arp.go           # ARP probe
│       └── smb/smb.go           # SMB probe
├── fingerprint/
│   ├── ttl.go                   # TTL-based detection
│   └── os.go                    # OS aggregation
├── integration/appscanner/
│   └── strategy.go              # FingerprintStrategy adapter
├── examples/simple/main.go      # Library usage example
├── go.mod
└── README.md
```

### Key Interfaces

```go
// Probe interface for all probe types
type Probe interface {
    Name() string
    Probe(ctx context.Context, target string) (ProbeResult, error)
}

// Options for Runner configuration
type Options struct {
    Targets    []string
    ProbeTypes []string
    Timeout    time.Duration
    OnResult   func(*Result)
    // ... more fields
}

// Result for each scanned host
type Result struct {
    IP       string
    IsAlive  bool
    OSFamily string
    TTL      int
    // ... more fields
}
```

## Dependencies

### Go Dependencies

- `github.com/prometheus-community/pro-bing` - ICMP
- `github.com/SiriusScan/go-api` - Sirius types
- `github.com/projectdiscovery/goflags` - CLI
- `github.com/projectdiscovery/gologger` - Logging

### Integration Points

- `app-scanner/internal/scan/strategies.go` - FingerprintStrategy interface
- `go-api/sirius/sirius.go` - Host, Port types

## Risks and Mitigation

| Risk                    | Impact | Probability | Mitigation                          |
| ----------------------- | ------ | ----------- | ----------------------------------- |
| Raw socket privileges   | Medium | High        | Support unprivileged fallback modes |
| ICMP blocked            | Medium | Medium      | Multiple probe types as fallback    |
| TTL false positives     | Low    | Medium      | Confidence scores, multiple probes  |
| go-api breaking changes | Medium | Low         | Use replace directive for local dev |

## Notes

- This project replaces the PlaceholderFingerprintStrategy in app-scanner
- Focus is on speed and accuracy for liveliness + OS detection only
- Not a replacement for full port scanning (Naabu) or vulnerability scanning (Nmap)
- Library-first design enables future integrations beyond Sirius

---

_This plan tracks the ping++ project development. Update milestones and tasks as work progresses._
