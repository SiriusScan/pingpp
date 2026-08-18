---
title: "Runner V2 contract"
description: "Frozen production execution layer for cmd/pingpp: CLI → runner → scan.Session → engine. Not a flag refresh on the legacy probe runner."
template: "TEMPLATE.documentation-standard"
version: "0.1.0"
last_updated: "2026-08-18"
author: "Project Team"
tags: ["runner", "cli", "scan", "engine", "contract"]
categories: ["architecture", "development"]
difficulty: "advanced"
prerequisites:
  - "docs/prototype-known-gaps.md"
related_docs:
  - "prototype-known-gaps.md"
  - "../programs/runner-v2/PROGRAM.md"
dependencies: []
llm_context: "high"
search_keywords:
  [
    "runner v2",
    "cmd/pingpp",
    "scan.Session",
    "scan.Config",
    "jsonl",
    "host concurrency",
  ]
---

# Runner V2 contract

**Status: FROZEN (C1).** Implementation follows this document. Do not start
`cmd/pingpp` until C2–C8 land. Do not invent flags, probe switches, or a
second engine.

This is a **new production execution layer**, not a refresh of
`pkg/runner`. Engine R1–R18 remain the scanning intelligence. Runner V2
multiplexes targets and operations around that engine.

Engine rebuild status lives in [prototype-known-gaps.md](prototype-known-gaps.md).
Program tracking lives in [programs/runner-v2/PROGRAM.md](../programs/runner-v2/PROGRAM.md).

---

## 1. Layering

```text
cmd/pingpp                 thin bootstrap / UI
    ↓
pkg/runner                 production multi-target execution
    ↓
pkg/scan.Session           prepared / reusable scanning runtime
    ↓
pkg/engine                 single-target adaptive engine
    ↓
registry / planner / collectors / fingerprinting / artifacts
```

**`cmd/pingpp` must not become another engine.**

| Layer | Owns | Must not own |
| --- | --- | --- |
| `cmd/pingpp` + `internal/cli` | flags, subcommands, signals, stdout/stderr wiring, exit codes | collectors, fingerprinting, hostname resolution, protocol switches |
| `pkg/runner` | target stream, host concurrency, per-target lifecycle, sinks, events, summary, fail-fast | probe selection, product/OS claims, flattening Asset into TTL/OS/open-ports |
| `pkg/scan` | canonical `Config`, prepared `Session`, registry wiring | CLI output flags, multi-target queues |
| `pkg/engine` | resolve → discover → enumerate → classify → fingerprint → re-plan → enrich → Asset | host-level concurrency across targets, CLI formatting |
| collectors | network facts / observations | product claims, peer scheduling |
| fingerprint | inference / fused claims | network I/O |
| `pkg/output` | versioned presentation DTOs | scanning |
| `pkg/artifact` | evidence bytes | identity |

Per-target scan remains:

```text
resolve → discover → enumerate TCP/UDP → classify → collect metadata
→ fingerprint → fuse claims → re-plan → enrich → finalize Asset
```

---

## 2. Current tree (facts this contract is written against)

HEAD at freeze: `963e48e` on `cursor/ping-correctness-and-hygiene-d7fc`.

Three execution stories exist today:

1. **README** still describes `cmd/pingpp` and the ICMP/TCP/SSH/HTTP/SMB probe
   model. That documented binary is **not** on this branch (`cmd/` is untracked
   leftover ignored by `.gitignore`'s `pingpp` pattern).
2. **`pkg/runner`** is the legacy architecture: hard-coded probe switch, flat
   `Result` (alive/OS/TTL/open ports), pre-resolution of hostnames, old OS
   aggregator. `integration/appscanner` still has `UseLegacyRunner`.
3. **`examples/scan`** is the closest new CLI: adaptive engine, profiles,
   registry, Asset output, hostname-preserving resolver. It is **not**
   production: one shared deadline across hosts, `-seed` apex/www expansion,
   URLs stripped to hostname, in-memory artifacts, stdout mixed with
   `enumerating …` on stderr only partly, no JSONL/schema version, no
   `cmd/pingpp`.

Additional freeze-time gaps that C2 must close before public Runner use:

- `engine.Options` treats `len(TCPPorts/UDPPorts) > 0` as override, so empty
  cannot mean “disable this transport.”
- `DisableICMP` in appscanner maps to `SkipDiscovery` (disables TCP discovery
  too).
- `ProfileDeep` uses curated `DefaultPorts`, not TCP 1–65535.
- `scan.Scan` constructs a new Engine (and reloads fingerprints) per call.
- One `Engine` holds planner, limiter, scheduler, fingerprints, artifacts,
  metrics, and a mutex; concurrent `ScanTarget` is not a proven contract.
- Scheduler `RatePerSecond` is task-oriented; one enumeration task can issue
  many network ops. Meter counts ops separately.
- `mergeScanState` merges budget counters, coarse reachability, and
  `Completed` only. It omits `Matched`, `RuledOut`, reachability reasons, and
  meter state from later addresses.
- Each address gets a fresh `ScanState`/Budget; totals merge afterward
  (per-address, not per user target).
- `ScanState` is an engine object with a mutex; it must not be the long-term
  JSON schema.
- Artifact store is in-memory (`artifact.MemoryStore`).
- `mqtt`, `amqp`, `vnc`, `socks` are registered but have no `RunResult`.
  Engine does not treat legacy `Run()` Completeness as protocol success.
- Appscanner new-engine path uses `context.WithTimeout(context.Background(), …)`
  instead of the caller context.
- `.gitignore` `pingpp` also ignores `cmd/pingpp/main.go`. Fix during C12.

---

## 3. Non-negotiable rules

1. `cmd/pingpp` is a thin bootstrap/UI layer.
2. Runner V2 does not import `pkg/probes/*` or the old `fingerprint/` aggregator.
3. Runner does not contain a protocol switch.
4. Runner does not perform product/OS fingerprinting.
5. Runner does not pre-resolve hostnames into IP-only work. Hostname must
   survive for HTTP Host and TLS SNI.
6. Runner does not flatten `Asset` into TTL/OS/open-ports as canonical result.
7. Runner does not interpret ports as services. Ports are priors, never identity.
8. Engine remains the owner of adaptive planning.
9. Fingerprint engine remains the owner of product/application/OS/device claims.
10. Runner owns **multi-target concurrency**, not collector selection.
11. Machine output has a versioned schema. It is not `json.Marshal(engine.ScanResult)`.
12. Logs/progress go to stderr; structured results go to stdout.
13. Unknown/unresponsive is a scan result, not automatically an execution failure.
14. Artifacts referenced by persistent output must themselves be persistent.
15. CLI and Sirius converge on one canonical `scan.Config` vocabulary.
16. No CLI flag promises a hard limit unless the engine actually enforces it.
17. Nothing in `cmd/pingpp` or `pkg/runner` V2 may import `pkg/probes/*` or
    the old `fingerprint/` package.
18. Do not copy generic `--retries` into Runner V2. Retries belong in
    transport/collector/discovery policy.
19. Do not expose `--max-bytes-per-host` or `--max-requests-per-endpoint`
    until `Budget.Remaining()` actually stops those resources.
20. Do not silently change `deep` to 65,535 TCP ports.

---

## 4. Package layout

Target tree (names may vary; separation is mandatory):

```text
cmd/pingpp/main.go              os.Exit(cli.Run(args, stdout, stderr))
internal/cli/                   scan, version, capabilities, collectors,
                                profiles, fingerprints, config, signals, exit
internal/legacyrunner/          quarantined old pkg/runner (or pkg/legacyrunner)
pkg/runner/                     Run, TargetSource, ResultSink, EventSink, Summary
pkg/scan/                       Config, Session, registry
pkg/output/                     document v1, text, json, jsonl, state snapshot
pkg/artifact/                   Store + FileStore
pkg/buildinfo/                  version, commit, corpus id
```

`examples/scan` may remain as a diagnostic example until C12, then either wrap
the production API or be deleted. It must not remain a second public CLI.

If external Go imports of today's `pkg/runner` matter, add a short-lived
compatibility package. Do not grow legacy `Result` with TLS/HTTP/Mongo/claims.

---

## 5. Canonical `scan.Config`

Public configuration today is split across `runner.Options`, `scan.ScanOptions`
(embeds `engine.Options`), `engine.Options`, `engine.Profile`, and
`engine.Budget`. That must collapse.

```go
type Config struct {
    Profile      ProfileConfig
    Discovery    DiscoveryConfig
    Ports        PortConfig
    Limits       LimitConfig
    Fingerprints FingerprintConfig
    Artifacts    ArtifactConfig
}
```

Compile path:

```text
scan.Config  →  engine.Options + Profile
```

`engine.Options` stays orchestration configuration, not the CLI/Sirius API.

### 5.1 Port tri-state

```go
type PortSelection struct {
    Override bool
    Ports    []uint16
}
```

| State | Meaning |
| --- | --- |
| `Override == false` | profile default |
| `Override == true`, non-empty `Ports` | custom list |
| `Override == true`, empty `Ports` | disable that transport's enumeration |

CLI: `--udp-ports none` must be representable. `len(slice) > 0` is forbidden
as the public override signal.

### 5.2 Discovery policy

`--no-icmp` and `--skip-discovery` are different:

| Flag | Behavior |
| --- | --- |
| `--no-icmp` | disable `discovery.icmp`; leave TCP discovery enabled |
| `--skip-discovery` | skip the discovery stage; still enumerate requested endpoints |

Profiles need a filtered/disabled-collector mechanism, not one Boolean.
Appscanner must stop mapping `DisableICMP → SkipDiscovery`.

### 5.3 Limits and timeouts

```text
run context
  └── per-target timeout          --target-timeout
      └── probe / HTTP timeouts   --probe-timeout / --http-timeout
```

Optional `--run-timeout` is a separate run-level deadline. Do **not** share
one overall timeout across all hosts (current `examples/scan` bug).

`--rate` = approximate **maximum network operations per second across the
entire run**, enforced near dial/read/write/packet, not merely collector
scheduling.

`--host-concurrency` = Runner max concurrent targets.
`--per-host-concurrency` = Engine max concurrent ops for one target.
Do not keep an ambiguous `--threads` except as a deprecated alias of
`--host-concurrency`.

Profile limits are **per user target input**, not per resolved address.
A 10-address hostname must not receive 10× `MaxNetworkOps` unless an
internal fairness split is documented. Optional per-address fairness is
internal.

SMB's self-dial path must be on the metered transport before we claim
exact budget/rate semantics.

---

## 6. Profiles

| Name | Ports | Effort |
| --- | --- | --- |
| `quick` | small endpoint set | small budget |
| `default` | curated broad inventory | default budget |
| `deep` | **same curated ports as default** | greater fingerprint/enrichment budget |
| `full` | TCP 1–65535 + selected UDP | dedicated performance acceptance before any default use |

`full` must not allocate a 65,535-literal in source if avoidable; generate
once. Do not enable `full` as a default anywhere until C16/C68 stress
tests pass (bounded memory, FDs, goroutines, cancellation, rate).

Users select profiles, not collectors. Collector selection stays dynamic.

---

## 7. Prepared `scan.Session`

```go
session, err := scan.NewSession(cfg)
defer session.Close()
result, err := session.Scan(ctx, target)
```

`Session` owns long-lived shared resources:

```text
registry
validated profiles
loaded built-in fingerprint corpus
external fingerprint packs
global artifact store
global network rate limiter
runtime metrics
build / corpus metadata
```

Each target owns isolated:

```text
Asset, ScanState, budget counters, meter,
planner progress, collector completion, protocol state
```

Fingerprint corpus must load **once** per process, not once per target.

Do not run `go eng.ScanTarget` concurrently on today's Engine until C7
proves the contract. Preferred split:

```text
Runtime   shared immutable corpus, registry, artifacts, global limiter
Engine    per-target planner / scheduler / scan state
```

Until C7, `Session.Scan` may be documented as non-concurrent.

`scan.Scan` one-shot helper may remain for single-target integrations, but
must be implemented on `Session`, not by reloading packs.

---

## 8. Runner API

```go
func (r *Runner) Run(ctx context.Context) (Summary, error)
```

Runner knows configuration, a `TargetSource`, a `ResultSink`, an optional
`EventSink`, host concurrency, max-targets, fail-fast. It does **not** know
JSON/Silent/Debug/Verbose.

```go
type ResultSink interface {
    WriteResult(context.Context, TargetResult) error
}
```

CLI wires text/json/jsonl/file/bundle sinks. Sirius wires an ingest sink.

`TargetResult` carries `TargetSpec`, `*engine.ScanResult` (internal),
timing, and typed `TargetError`. Public machine documents are built by
`pkg/output`, not by dumping `ScanResult`.

Unknown host / no response is a valid `TargetResult` with exit 0 for the
process (unless other targets failed operationally).

### 8.1 Error kinds

```text
input | resolution | timeout | cancelled | engine | output | internal
```

One target failure must not abort the rest unless `--fail-fast`.

### 8.2 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | run completed; network results may include unknown/down |
| 1 | operational failure / output failed / one or more target **executions** failed |
| 2 | invalid invocation / config / input contract |
| 130 | interrupted (first SIGINT path) |

---

## 9. Targets

### 9.1 Source

Streaming `TargetSource` (`Next(ctx) (TargetSpec, error)` or iterator).
Composable: argv, `-t`, `-l`/`--list`, stdin, CIDR expander, exclude,
dedup, max-targets.

Do **not** load every target into memory first. Do **not** expand CIDRs
eagerly. Do **not** resolve hostnames in Runner.

V1 accepted syntax: **IPv4, IPv6, hostname, CIDR**.

URL and `host:port`: **reject with a helpful error** in V1. Do not strip
`https://example.com:8443/admin` to `example.com` and pretend URL support.
Endpoint-hint Target fields are post-V2 (after C9 is stable).

`-seed` apex/www is **out of `pingpp scan`**. If needed later:
`pingpp discover-domain` with a real public-suffix list. `pingpp scan`
scans what the user supplied.

### 9.2 Safety

`--max-targets` with a guard. Estimated expansion over the limit → exit 2,
tell the user to raise `--max-targets`. IPv6 `/64` must be rejected or
bounded immediately, never expanded.

### 9.3 Files

One target per line; blanks ignored; `#` comments; UTF-8 BOM; large
scanner buffer; `file:line` in diagnostics. Default: warn + continue on
bad lines. `--strict-input` makes them fatal. Do not silently skip.

### 9.4 Exclusions

`--exclude`, `--exclude-file` applied before queue admission.

---

## 10. Output

### 10.1 Schema `pingpp.scan/v1`

Machine documents include `schema_version`, `run_id`, `tool` (version,
commit, `fingerprint_corpus_id`), target input/source, timestamps,
profile, **state snapshot** (no mutex), asset (addresses, hostnames,
endpoints, claims, observations), metrics, nullable error.

Do not serialize `ScanState`. Snapshot:

```text
reachability, budget counters, completed collectors,
matched protocols, ruled-out protocols
```

Fix multi-address merge (C2) before publishing state in JSON/verbose/stats.

### 10.2 Formats

| Format | Use |
| --- | --- |
| `text` | human; new model (reachability, identity claims, endpoints, unknown, conflicts). Not TTL-led. |
| `jsonl` | default machine format for batch; one complete target document per finished target |
| `json` | single array; may buffer |

`--verbose` / `--evidence`: claim evidence (rule IDs, observation IDs,
subject). No giant HTTP bodies in default verbose.
`--observations`: raw facts, separate advanced mode.

### 10.3 stdout / stderr

stdout = requested scan results only.
stderr = logs, progress, warnings, diagnostics.

`pingpp scan t --format jsonl | jq …` must always work.

### 10.4 Artifacts

| Mode | Behavior |
| --- | --- |
| `none` | `--no-artifacts` |
| `memory` | OK for ordinary text |
| `file` | `--artifact-dir`; required when JSON/JSONL references artifact IDs |
| `bundle` | `--bundle dir` → manifest.json, results.jsonl, artifacts/sha256/…, unmatched-banners.jsonl |

File store: content-addressed, atomic write+rename, dedup, 0600/0700 where
practical, bounded size, no path traversal.

Run bundle schema `pingpp.run/v1`. Replay (`pingpp replay`) is **V2.1**,
not a Runner V2 blocker. Bundle format must be replay-friendly now.

### 10.5 Provenance

`pkg/buildinfo`: version, commit, build date, Go version,
`fingerprint_corpus_id` (deterministic digest over embedded YAML, Recog
XML, Wappalyzer JSON). Every machine document includes it.
`pingpp version` / `pingpp version --json`.

`--stats` only after metrics mean ClaimProtocol, not “collector succeeded,”
and after empty-outcome-on-error is not counted as a match.

---

## 11. CLI surface

Canonical:

```text
pingpp scan
pingpp version
pingpp collectors
pingpp profiles
pingpp capabilities
pingpp fingerprints validate
```

Later: `pingpp replay`, `pingpp discover-domain`.

Optional shorthand: `pingpp -t 10.0.0.1` → `pingpp scan -t 10.0.0.1`.
Help promotes `pingpp scan`.

`main` is only:

```go
os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
```

### 11.1 `pingpp scan` flags (allowed)

Input: `-t/--target`, `-l/--list`, `--stdin`, `--exclude`, `--exclude-file`,
`--max-targets`, `--strict-input`.

Scan: `--profile` (`quick|default|deep|full`), `--tcp-ports`, `--udp-ports`
(`profile|none|full|list/ranges`), `--skip-discovery`, `--no-icmp`,
`--host-concurrency`, `--per-host-concurrency`, `--rate`,
`--target-timeout`, `--probe-timeout`, `--http-timeout`, `--run-timeout`,
`--max-network-ops`, `--max-probes`, `--fail-fast`.

Fingerprints: `--fingerprint-dir` (repeatable).

Artifacts: `--artifact-dir`, `--no-artifacts`, `--bundle`.

Output: `-o/--output`, `--format` (`text|json|jsonl`), `-v/--verbose`,
`--evidence`, `--observations`, `--stats` (after C2 metrics fix), `--quiet`,
`--no-color`, `--only-responsive` (presentation filter only; stream stays
complete).

Logging: `--log-level`, `--log-format`.

Config: `--config`, `--print-effective-config`.

Precedence: compiled defaults → profile → config file → CLI.
YAML `KnownFields(true)`. Unknown keys fail. Secrets (SNMP community, etc.)
must be typed and redacted from effective-config, manifests, and debug logs.

### 11.2 Flags not to expose yet / not to map

| Old / tempting | Rule |
| --- | --- |
| `-probes` | Reject/deprecate. No clean adaptive-engine equivalent. Do not disable every collector except X. |
| `-threads` | Deprecated alias of `--host-concurrency` only, with warning. |
| `-retries` | Do not map. |
| `-silent` / `-debug` | Map onto log/quiet, not runner Options mixed with scan config. |
| `-json` | Alias of `--format json` (or jsonl if documented). |
| `-timeout` | Map to `--target-timeout`, not a shared run deadline. |
| `-no-icmp` | Keep; must **not** skip TCP discovery. |
| `--max-bytes-per-host`, `--max-requests-per-endpoint` | Internal until enforced. |
| `-seed` | Not on `scan`. |
| `ShowAll` / hide offline | Do not filter in Runner. Optional `--only-responsive` is presentation. |

Collector introspection (`pingpp collectors`, `pingpp capabilities`) is
**registry-derived**. Do not hardcode protocol lists.

A collector is `production` in capabilities only if it implements
`ResultCollector`, has positive + negative lookalike fixtures, bounded
parse, and canonical `ClaimProtocol`. Otherwise `experimental` or
unregistered. MQTT/AMQP/VNC/SOCKS start experimental or get converted in C2.

---

## 12. Signals, cancellation, progress

First SIGINT/SIGTERM: stop admitting targets, cancel active scans, flush
sinks, finish valid JSONL already produced, summary on stderr, exit 130.
Second SIGINT: hard exit is acceptable.

Cancellation must flow: OS signal → CLI ctx → `Runner.Run` → per-target ctx
→ `Session.Scan` → Engine → Scheduler → Collector → transport.
No package may replace this with `context.Background()`.

Progress events: `run_started`, `target_accepted|started|resolved|completed|failed`,
`progress`, `warning`, `run_completed`. User-facing progress is coarse
(targets, responsive, endpoints, unknown). Not per-collector unless debug.

Collector panics must recover at `executeCollector` → `OutcomeInternalError`
with collector ID + endpoint. One malformed response must not crash a /16.

---

## 13. Implementation sequence (C1–C16)

Canonical numbering. Section “first five before `cmd/pingpp`” means C1, C2,
C3, C5 (`Session`), C8 (`TargetSource`). ProfileFull (C4) may ride with C3.
Do not start C12 until those exist.

| ID | Work | Gate |
| --- | --- | --- |
| **C1** | This contract | no flag work until merged |
| **C2** | Engine prerequisites (below) | `go test ./...`, `-race`, `go vet`; explicit regressions |
| **C3** | `pkg/scan` `Config` + tri-state ports + `--no-icmp` ≠ skip-discovery | listed config tests |
| **C4** | `ProfileFull` (TCP 1–65535 + selected UDP); `deep` stays curated | `quick ≠ default ≠ deep ≠ full` |
| **C5** | `scan.Session`; packs load once | instrumented 100-target load-once; race or explicit non-concurrent |
| **C6** | `artifact.FileStore` | put/get, dedup, atomic, max size, traversal, persist |
| **C7** | Global network limiter + host vs per-host concurrency | fake transports stay within rate; `-race` |
| **C8** | Streaming `TargetSource` | hostname not pre-resolved; lazy CIDR; IPv6 bound; exclude; file diagnostics |
| **C9** | Runner core: queue, workers, sinks, summary, fail-fast, cancel | concurrency cap; one bad target; no goroutine leaks |
| **C10** | `pkg/output` `pingpp.scan/v1` DTO | golden JSON fixtures |
| **C11** | text / json / jsonl sinks | no logs on stdout; JSONL one object per target |
| **C12** | `cmd/pingpp` + `internal/cli` (`scan`, `version`) | in-memory stdout/stderr tests; fix `.gitignore` |
| **C13** | signals, progress, logs, colors, exit codes | SIGINT 130; usage 2; unknown host 0 |
| **C14** | collectors / profiles / capabilities / fingerprints validate | help agrees with registry |
| **C15** | quarantine legacy runner; migrate appscanner; rewrite README primary path; deprecate `-probes` | new `cmd/pingpp` never calls old runner |
| **C16** | release hardening, benchmarks, README rewrite, `go install …/cmd/pingpp` | blockers in §15 |

### C2 engine prerequisites (must land before concurrent/public Runner)

- Multi-address `mergeScanState` includes Matched, RuledOut, reachability
  reasons, meter.
- Per-target (not per-address) budget semantics.
- Collector panic containment.
- Metrics: protocol-match = ClaimProtocol; do not count empty outcome+error
  as success; conflict dedup.
- MQTT/AMQP/VNC/SOCKS: `ResultCollector` + fixtures **or** unregister /
  mark experimental.
- ICMP-specific disable (not `SkipDiscovery`).
- SMB on metered transport before exact rate claims.

Replay, URL endpoint hints, `discover-domain`, and full Recog semantic
cleanup beyond current R-track debt are **not** C1–C15 blockers except
where listed in §15.

---

## 14. Example API (target shape)

```go
cfg := scan.DefaultConfig()
cfg.Profile.Name = engine.ProfileDefault
cfg.Limits.HostConcurrency = 50

session, err := scan.NewSession(cfg)
defer session.Close()

source, err := runner.NewTargetSource(
    runner.WithTargets(targets...),
    runner.WithFile("targets.txt"),
    runner.WithMaxTargets(100_000),
)

r, err := runner.New(runner.Options{
    Session: session,
    Targets: source,
    HostConcurrency: 50,
    Sink: sink,
})
summary, err := r.Run(ctx)
```

Absent on purpose: SSH/SMB/HTTP probes, OS aggregator, TTL logic, protocol
switches.

---

## 15. Release blockers (`cmd/pingpp` v2)

**Engine:** advertised protocols produce canonical outcomes; panic boundary;
multi-address state; per-target budgets; metrics; Recog notices/semantics as
already required by the R-track.

**Runner:** bounded queue; lazy CIDRs; max-targets; IPv6; hostname
preservation; cancellation; global network rate; typed errors; partial
results.

**Output:** stable schema; JSONL; stdout/stderr isolation; persistent
artifacts; build + corpus provenance.

**Ops:** signals; exit codes; config validation; benchmarks;
full-profile stress; `go install github.com/SiriusScan/ping++/cmd/pingpp@…`
works (module path as in `go.mod`); README matches behavior.

Human gates: production tag/release, scanning networks the operator did not
name, and publishing third-party fingerprint notices remain human-approved.

---

## 16. Validation

Repository-native:

```text
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...   # v2.12.2
```

C1 adds no behavioral tests. Later stages add the regressions named in
their rows. Do not claim a flag is enforced without a test that the engine
stops.

---

## 17. Standing freeze rules

- Do not reset this branch to `master`.
- Do not grow legacy `pkg/runner.Result`.
- Do not start C12 until C1, C2, C3, C5, and C8 are done.
- Unknown is valid. Receiving bytes is not a protocol match.
- Ports are priors. Product fingerprints stay outside collectors.
