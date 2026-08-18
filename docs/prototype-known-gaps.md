# Ping++ prototype known gaps

This document freezes the prototype chassis and records the alignment contract
for the rebuild sequence. It is not a production-readiness claim.

## Freeze policy

Treat `cursor/ping-correctness-and-hygiene-d7fc` as a **prototype of the full
PRD**, not as a failed PR 0 and not as production code.

- **Do not reset to `master`.**
- **Do not remove protocol coverage** merely because collectors are incomplete.
- **Do not add more protocols** until classification, planner, fusion, and
  Engine composition are aligned.
- Keep breadth. Replace prototype assumptions with reliable mechanics.

Reviewed prototype commit: `bfef5cb`.  
R1 freeze work continues on this branch after later scan-correctness commits.

R1 itself is a freeze pass only: CI gate, test inventory, and this document.
No planner/fusion/Engine architecture changes belong in R1.

## Qualitative status

The shape of the system is mostly right:

```text
Asset / Endpoint
Observations
Claims
Collectors
Registry
Planner
Fingerprint rules
Artifacts
Profiles
TLS / HTTP / SSH / SMB
Broad protocol packages
Sirius adapter
```

The execution path is not yet that engine. Conceptually the code says
enumerate → classify → fingerprint → adapt → store evidence → budget, but the
live path is mostly enumerate → choose collectors by port → run once → return
observations. Selected callers then run fingerprinting manually.

| Area | Prototype status |
|---|---|
| Domain architecture | Strong foundation |
| Collector registration | Strong foundation |
| Evidence/claim concept | Good foundation, fusion bugged |
| TCP enumeration correctness | Improved |
| TLS | Good first implementation |
| SMB | Good first implementation |
| HTTP | Useful prototype, significant missing pieces |
| Service classification | Needs rebuild |
| Adaptive planner | Needs rebuild |
| Artifact replay | Designed, not wired |
| Protocol breadth | Many prototypes, insufficient validation |
| UDP | Essentially not wired |
| SNMP | Rebuild |
| Recog/Wappalyzer | Placeholder, rebuild/integrate properly |
| Fingerprint corpus | Useful start, confidence too aggressive |
| Performance/budgeting | Needs rebuild |
| Sirius compatibility | Needs refactor |
| Testing | Lots of unit scaffolding, insufficient semantic/integration coverage |
| Production readiness | Not yet |

## What must survive

Do not permit a broad rewrite of everything.

| Component | Direction |
|---|---|
| `pkg/model` Asset/Endpoint/Observation/Claim | KEEP + refine |
| `Collector` interface | KEEP + small extension |
| Registry/factory approach | KEEP |
| `pkg/transport` central dial abstraction | KEEP + expand |
| `pkg/artifact` content-addressed store | KEEP + wire into engine |
| Confidence tiers | KEEP |
| Native YAML fingerprint concept | KEEP + strengthen schema |
| TLS collector | KEEP + extend |
| SMB collector | KEEP + test heavily |
| Corrected TCP enumeration | KEEP |
| Separation of collectors from product fingerprints | KEEP ABSOLUTELY |
| Legacy output adapter | KEEP temporarily |

Sacred model rule:

> Protocol-specific data belongs in typed observation payloads, not global
> asset fields.

`Claim` already has the right broad concepts: subject, kind, vendor/product/
version, confidence, evidence, and correlation. Do not throw those away
because individual functions around them are wrong.

## What must be rebuilt

| Component | Required action |
|---|---|
| Planner | Rebuild implementation, preserve concept |
| Scheduler | Rebuild / actually integrate |
| Service classification | Rebuild |
| Evidence fusion | Rebuild carefully |
| UDP discovery/enumeration | Build properly |
| SNMP | Rebuild using a real protocol parser/library |
| Recog integration | Replace fake adapter with actual integration |
| Wappalyzer integration | Replace six-rule placeholder with actual corpus |
| Built-in fingerprint loading | Rebuild around `go:embed` |
| HTTP scheme/protocol detection | Rebuild around observed TLS, not ports |
| Budget accounting | Rebuild around network operations |
| Engine error/outcome handling | Rebuild |
| Adaptive enrichment | Implement |
| Protocol claim generation | Implement centrally |

## What should probably be deleted

- **`collect.tcpstack` from normal registration.** It connects and reports
  local/remote address and latency while admitting TTL/MSS/options need raw
  capture. That is not stack fingerprinting. Later reimplement with packet
  capture when available.
- **Fake local Wappalyzer.** `pkg/fingerprint/adapters/webtech.go` has six
  hand-written rules. Delete or keep only as a tiny test fixture once a real
  corpus is wired.
- **Fake Recog corpus path.** `fingerprints/recog/` is not actual Recog
  integration. Do not elaborate the compatibility layer; integrate Recog.
- **Runtime accuracy counters that require ground truth.**
  `metrics.Counters` tracks `ExactCorrect` / `StrongCorrect`. Normal scans
  cannot know correctness. Move that to benchmark/corpus tooling. Runtime
  metrics should report collectors executed, protocol matches, timeouts,
  bytes, unknown endpoints, claim tiers, and conflicts.

## Target architecture

Canonical end-to-end path:

```text
Target Resolver
      ↓
Discovery Manager
      ↓
Endpoint Enumerator
      ↓
Planner
      ↓
Protocol Classifiers / Collectors
      ↓
Observation Store
      ↓
Fingerprint Engine
      ↓
Claim Fusion
      ↓
Planner Re-evaluation
      ↓
Optional Enrichment
      ↓
Final Asset
```

The missing loop that makes ping++ special:

```text
collect → interpret → re-plan → collect again if useful
```

## Concrete gaps in this tree

File paths are the current chassis, not an invitation to rewrite them in R1.

### Engine does not own the scan

`engine.ScanTarget` stops at observations. Callers assemble claims:

- `examples/scan/main.go` calls `fingerprint.NewEngine()`, `LoadBuiltinPacks`,
  `Match`, `FuseOS`, then `AddClaim`.
- `integration/appscanner/strategy.go` does the same, then appends raw claims
  **and** `FuseOS` output, so weak original OS scores can survive.

After R3, `engine.ScanTarget` must mean the complete configured fingerprint
scan. Engine owns registry, fingerprint engine, artifacts, scheduler, planner,
profile, and metrics.

### Collector outcomes are unused

`ProbeOutcome` exists in `pkg/engine/profile.go`
(`success`, `no_match`, `refused`, `timeout`, `filtered`, `protocol_error`,
`internal_error`) but collectors still return `([]ObservationRecord, error)`.

`ScanTarget` ignores non-context collector errors:

```go
if err := e.runTask(...); err != nil && ctx.Err() != nil {
    return nil, err
}
```

NoMatch must not be Error. Timeout must not be InternalError. A valid negative
response is not an error. Parser invariant violations are InternalError.

Every protocol collector must answer “did the service speak this protocol?”,
not merely “did the socket return bytes?”

Known false-positive patterns:

- FTP emits an `ftp` observation from a generic banner
  (`pkg/protocol/ftp` → `textproto.CollectBanner`) without requiring a valid
  reply code.
- PostgreSQL treats any one-byte SSLRequest response as recognized
  (`pkg/protocol/postgres`); only `S` or `N` should match.

Protocol success must create endpoint-scoped `ClaimProtocol` centrally. Product
fingerprints enrich that layer; they must not substitute for it.

### Planner is one-shot and port-table driven

`Planner.PlanClassification` runs once. There is no
plan → execute → fingerprint → replan loop.

`serviceHints` duplicates `CollectorMetadata.DefaultPorts`. Registry metadata
already has default ports; the planner should derive priors from the registry.

`likelyCollectorsForPort` returns `nil` for non-TCP, so UDP collectors are
never scheduled even when metadata advertises UDP.

Unknown ports fall back to `collect.banner`, but production
`pkg/scan.NewRegistry` does not register a banner collector. Only engine tests
register a fake one.

### Scheduler and budgets are disconnected from reality

`Scheduler` exists with bounded concurrency. `ScanTarget` does not use it.
Enumeration and classification run sequentially.

Budgets count collector invocations. `enumerate.tcp` can make dozens of dials
and consume one probe. Transport helpers should report network operations;
collectors should not increment global counters by hand.

`discovery.tcp` and `enumerate.tcp` both iterate configured ports. Discovery
should use a small seed set, or be skipped when enumeration always runs.

### Fusion ignores subject and version identity

`fingerprint.Fuse` keys identity as `(kind, product/value, correlation_group)`.
`Subject` is ignored, so nginx on `:80` and nginx on `:443` can fuse.

Version identity is not separate. `nginx 1.22` and `nginx 1.24` can collapse
into one product/version claim instead of a product claim plus conflicted
version candidates.

`Claim.ContradictionIDs` is unused in any deterministic priority rule.
Protocol-native self-identification should beat generic heuristics.

OS composition: callers append raw claims and adjusted OS claims. Raw weak
Linux must not escape into final output separately.

### HTTP / TLS / artifacts

HTTP chooses HTTPS solely for ports 443 and 8443
(`pkg/protocol/http/collector.go`). Scheme must follow observed TLS, not port.

HTTP v2 still missing: effective URL, redirect chain, cross-host redirect
scope protection, body truncation flag, raw body artifact, favicon fetch and
hashes, script/link/form URLs. Default redirect policy: same hostname/IP may
follow; different host records `Location` and stops.

`pkg/artifact.Store` is implemented and unit-tested but not passed into
collectors. Engine must provide it. Observations should carry `ArtifactIDs`
so fingerprint replay can request body bytes without stuffing 256 KiB into
JSON.

### Fingerprint loading and schema

`LoadBuiltinPacks` uses `runtime.Caller` and swallows missing-directory
errors. Built-ins must be `go:embed`, validated at startup, with compiled
regexes and rejected unknown fields. External `--fingerprint-dir` errors must
surface.

Title-only application rules are frequently `strong` around 88–92. Recalibrate:
generic title keyword is hint/probable; native self-identification is
exact/strong.

### Recog / Wappalyzer placeholders

Adapter interfaces are useful. Internals are not real Recog or Wappalyzer.
HTTP observations do not retain HTML for body matching; `NativeWebTech` body
rules only see title + meta generator.

### UDP, DNS, SNMP

`enumerate.udp` is not implemented. Profile UDP ports exist
(`53, 123, 161, 500, 1900, 4500, 5353`) but are unused.

DNS collector (`pkg/protocol/dns`) does `LookupHost("example.com")` through
the target and treats any answer as DNS fingerprinting.

SNMP uses a hand-rolled parser that can mistake the community OCTET STRING
for `sysDescr`, and currently records the community in the observation.

### Target / address scanning

`ResolveTarget` returns all A/AAAA addresses. `ScanTarget` uses only
`target.Addresses[0]`. Hostname must be retained for Host/SNI on every
resulting asset.

IPv6 is model-compatible; TCP/TLS/HTTP/SSH/DNS must keep using
`net.JoinHostPort`. Do not block breadth on sophisticated IPv6 OS
fingerprinting.

### Sirius / config fragmentation

`integration/appscanner` knows too much: separate fingerprint engine
invocation, duplicated OS fusion, option-semantic drift versus
`runner.Options` / `engine.Options` / Profile / collector config.

Target: Sirius configures Engine → Scan → map canonical Asset to Sirius
schema. Preserve legacy options until Sirius moves to the richer API.

### Legacy runner

The new engine treats closed TCP as probable reachability. The legacy runner
does not (`pkg/runner/result_test.go` currently asserts closed TCP must not
override liveness). Make them consistent, then stop investing beyond
compatibility.

## Test inventory at freeze

Recorded by R1. This is ground truth for “lots of unit scaffolding,
insufficient semantic coverage.”

### Current `go test` packages with tests

| Package | What tests actually prove |
|---|---|
| `examples/scan` | Report keeps full payloads; seed expansion |
| `fingerprint` (legacy TTL) | TTL→OS heuristic tables |
| `integration/appscanner` | No hardcoded debug paths in source |
| `pkg/artifact` | Memory store content-addressing and size limit |
| `pkg/discovery/ports` | Port lists non-empty |
| `pkg/discovery/tcp` | Enumerate reports requested ports; curated defaults |
| `pkg/engine` | Registry, fake-pipeline enumeration, hostname pass-through, budget/rate limiter |
| `pkg/fingerprint` | Correlation-group non-inflation, independent-group combine, YAML nginx rule, pack positives, one lookalike, OS fusion generics |
| `pkg/fingerprint/adapters` | Six-rule Grafana title; native Recog SSH YAML |
| `pkg/metrics` | Precision counters given injected ground truth |
| `pkg/model` | Asset/endpoint/observation/claim invariants |
| `pkg/output` | Legacy Sirius mapping |
| `pkg/probes` | ProbeResult constructors |
| `pkg/probes/tcp` | Legacy TCP probe open/closed details, no TTL |
| `pkg/protocol/http` | GET observation against local server |
| `pkg/protocol/smb` | **Metadata only** |
| `pkg/protocol/ssh` | Banner against local listener |
| `pkg/protocol/textproto` | FTP banner + SMTP EHLO feature parse |
| `pkg/protocol/tls` | Local TLS cert capture |
| `pkg/runner` | Legacy options + liveness/open-port details |
| `pkg/scan` | Registry membership for SSH/SMB/HTTP/TLS and protocol IDs |

### Packages with collectors but no tests

`pkg/protocol/{amqp,dns,ftp,imap,ldap,memcached,mongodb,mqtt,mssql,mysql,pop3,postgres,rdp,redis,smtp,snmp,socks,telnet,vnc,tcpstack}`

`pkg/discovery/icmp`, `pkg/transport`, and most `pkg/probes/*` except TCP.

`pkg/scan` breadth tests check **registry membership**, not protocol
recognition or lookalike rejection.

### Required later (not R1)

Positive + negative protocol tests for every collector. Strong/exact
fingerprint fixtures. Docker-backed integration lab. Framing/corruption tests
for binary parsers. Planner tests with fake collectors. Subject-aware fusion
tests before corpus expansion.

## Refactor sequence

Work R1–R18 in order. Each PR must leave the end-to-end scanner working.
Do not defer integration until the end. Do not add protocols until R6/R7
classification actually composes.

| PR | Objective |
|---|---|
| R1 | Compile/test under PR CI; freeze feature additions; this document |
| R2 | Subject-aware fusion, version identity, OS composition |
| R3 | Engine owns fingerprinting, artifacts, and final claims |
| R4 | Iterative plan → execute → fingerprint → replan |
| R5 | Scheduler + network-operation budgets |
| R6 | Registry-derived priors; real `collect.banner` |
| R7 | Protocol claims + port-independent classification |
| R8 | UDP pipeline + DNS rebuild |
| R9 | SNMP rebuild |
| R10 | HTTP/TLS relationship, redirects, body artifacts, favicon hashes |
| R11 | Real Recog/Wappalyzer |
| R12 | Harden text protocols + pos/neg integration tests |
| R13 | Harden DB/middleware protocols + framing tests |
| R14 | Harden LDAP/RDP/SSH/SMB |
| R15 | Recalibrate fingerprint packs + fixture corpus |
| R16 | Sirius adapter / config unification |
| R17 | IPv6 / multi-address completion |
| R18 | Performance, unknown-corpus, benchmarks, release hardening |

## Standing rules for later PRs

- Ports are priorities, never identity.
- Product fingerprints remain outside collectors.
- Protocol success creates endpoint-scoped protocol claims.
- Claims from different endpoints never fuse unless an explicit asset-level
  promotion rule says they should.
- Fingerprint pack loading may never silently ignore malformed built-ins.
- Runtime built-in fingerprints must ship with the binary.
- Unknown is valid and should preserve useful raw evidence.
- Do not build complete protocol clients. Build the smallest
  standards-correct exchange that identifies the protocol and collects
  useful unauthenticated metadata.
- Receiving bytes is not a protocol match.

## R1 CI baseline

Commands that must pass on this freeze:

```text
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...   # v2.12.2
```

CI (`.github/workflows/ci.yml`) now runs build, vet, `go test -race`, and
pinned `golangci-lint` v2.12.2 via `golangci-lint-action@v8`. Workflows also
run on `cursor/**` pushes so the prototype branch gets a CI record even when
a GitHub PR has not been opened yet. The Origin forge cannot create pull
requests for this inbound GitHub-mirrored repository; open
`cursor/ping-correctness-and-hygiene-d7fc` → `master` on GitHub
(`SiriusScan/pingpp`) to get a reviewable PR.
