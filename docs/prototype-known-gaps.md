# Ping++ prototype known gaps

This document is the living alignment contract for the rebuild sequence. It is
not a production-readiness claim. Update it after each R-stage so it describes
the **current** tree rather than the freeze-era snapshot.

## Freeze policy

Treat `cursor/ping-correctness-and-hygiene-d7fc` as a **prototype of the full
PRD**, not as a failed PR 0 and not as production code.

- **Do not reset to `master`.**
- **Do not remove protocol coverage** merely because collectors are incomplete.
- **Do not add more protocols** until classification, planner, fusion, and
  Engine composition are aligned.
- Keep breadth. Replace prototype assumptions with reliable mechanics.

Reviewed prototype commit: `bfef5cb`.  
Rebuild work continues on this branch.

## Qualitative status

Canonical path now implemented:

```text
resolve → discover → enumerate → plan → collect → fingerprint → re-plan → enrich → Asset
```

| Area | Current status |
|---|---|
| Domain architecture | In use (Asset / Observation / Claim) |
| Collector registration | Production registry; `collect.tcpstack` unregistered |
| Evidence / claims | Subject-aware fusion; endpoint-scoped protocol claims |
| TCP enumeration | Concurrent, metered `DialTCP` |
| TLS / HTTP | Scheme from observed TLS; redirects, body artifacts, favicon |
| Service classification | `ResultCollector` + `ProbeOutcome`; ports are priors only |
| Adaptive planner | `Next()` one collector per endpoint; fallback after NoMatch |
| Artifacts | Engine store; HTTP bodies / favicons persisted |
| UDP | Candidates even on silence; DNS/SNMP decide responsiveness |
| DNS | Speaks DNS to the endpoint via `miekg/dns` |
| SNMP | `gosnmp`; community never in JSON |
| Recog / Wappalyzer | XML / JSON corpora loaded; `NativeWebTech` is a test fixture |
| Fingerprint corpus | YAML packs load fail-closed; title-only scores still aggressive |
| Budgeting | `transport.Meter` counts dials **and** Read/Write bytes |
| Sirius compatibility | Engine → `ToSiriusHost`; still has a legacy runner fallback |
| Testing | Pos/neg protocol tests for hardened collectors |
| Production readiness | Not yet |

## What must survive

Do not permit a broad rewrite of everything.

| Component | Direction |
|---|---|
| `pkg/model` Asset/Endpoint/Observation/Claim | KEEP + refine |
| `Collector` / `ResultCollector` | KEEP |
| Registry/factory approach | KEEP |
| `pkg/transport` central dial abstraction | KEEP; all real I/O goes through it |
| `pkg/artifact` content-addressed store | KEEP; already wired into Engine |
| Confidence tiers | KEEP |
| Native YAML fingerprint concept | KEEP + recalibrate (R15) |
| TLS / HTTP / SSH / SMB collectors | KEEP |
| Corrected TCP enumeration | KEEP |
| Separation of collectors from product fingerprints | KEEP ABSOLUTELY |
| Legacy output adapter | KEEP temporarily |

Sacred model rule:

> Protocol-specific data belongs in typed observation payloads, not global
> asset fields.

## Rebuild progress

| Component | Status |
|---|---|
| Planner | Done (R4/R6/R7). Priors from registry metadata. After all port-associated collectors return NoMatch, `classificationSequence` continues into the general fallback (SSH on 443, Redis on 3306, HTTP on 22 remain discoverable). Exclusive protocol matches still stop irrelevant collectors. |
| Scheduler | Done (R5). `Scheduler.RunAll` with per-host concurrency. |
| Service classification | Done (R7). `ProbeOutcome` is identity; Completeness is not. |
| Evidence fusion | Done (R2). Subject + version identity; OS composition. |
| UDP enumeration | Done (R8). Profile UDP ports are candidates. ICMP port-unreachable may mark **closed**. Silence is **unknown**, not exclusion. Protocol collectors determine responsiveness. |
| DNS | Done (R8). Direct query to the endpoint; QR bit required. Uses metered `DialUDP`/`DialTCP`. |
| SNMP | Done (R9). `gosnmp`; dials counted via `transport.CountDial` + wrapped conn bytes. |
| Recog / Wappalyzer | Done (R11). Real XML/JSON loaders. |
| HTTP / TLS | Done (R10). Scheme from TLS match; same-host redirects; body artifacts; favicon hashes. HTTP dials through `transport.DialTCP`. |
| Banner collector | Done (R6). Registered as `collect.banner`; not exclusive. |
| Protocol claims | Done (R7). Engine writes endpoint-scoped `ClaimProtocol` on Success. |
| Budget accounting | Done (R5, repaired). `MaxNetworkOps` covers DialTCP/UDP, HTTP, DNS, SNMP, and ICMP. Connection Read/Write populate `BytesRead`/`BytesSent`. UDP wrappers remain `net.PacketConn` so DNS framing stays datagram. |
| Engine composition | Done (R3). Engine owns fingerprints, artifacts, final claims. |
| Built-in fingerprint `go:embed` | Remaining (R15). `LoadBuiltinPacks` fail-closes on parse errors but still uses `runtime.Caller` filesystem paths. |
| Title-only pack calibration | Remaining (R15). Generic title keywords still `strong` 88–92. |
| Sirius / ScanOptions | Remaining (R16). |
| Multi-address / IPv6 scan | Remaining (R17). `ResolveTarget` returns all A/AAAA; `ScanTarget` still uses `Addresses[0]`. Hostname is kept for SNI/Host. |
| Runtime metrics / unknown corpus | Remaining (R18). `ExactCorrect`/`StrongCorrect` still live in `pkg/metrics`. |

## What should still be deleted or moved

- **`collect.tcpstack` stays out of `pkg/scan.NewRegistry`.** Reimplement later with packet capture.
- **`NativeWebTech` is a test fixture only.** Do not register it in production.
- **Runtime accuracy counters that require ground truth** (`ExactCorrect` /
  `StrongCorrect`) still need to move to eval tooling (R18).

## Remaining gaps

### Fingerprint loading (R15)

`LoadBuiltinPacks` fail-closes on YAML/XML/JSON parse errors. Missing optional
directories are OK. Built-ins are not yet `go:embed`; `RepoFingerprintsRoot`
still uses `runtime.Caller`. Title-only application/device rules are too
confident.

### Sirius / config (R16)

`integration/appscanner` already scans via Engine when `UseEngine` is true, but
still carries a legacy runner path and does not expose one `ScanOptions` type.

### Target / address scanning (R17)

`ResolveTarget` returns all A/AAAA. `ScanTarget` uses only
`target.Addresses[0]`. Hostname is retained for Host/SNI on that one scan.
Transport helpers already use `net.JoinHostPort`.

### Metrics / unknowns (R18)

Runtime meters now describe real network activity. Claim-tier correctness
counters still require ground truth and do not belong on the scan path.
Unknown endpoints should dump unmatched banners for corpus work. Parser paths
must not panic.

### Legacy runner

The engine treats closed TCP as probable reachability. The legacy runner does
not. Stop investing beyond compatibility.

## Standing rules

- Ports are priors, never identity. After port-associated collectors miss,
  continue the general fallback sequence.
- Product fingerprints remain outside collectors.
- Protocol success creates endpoint-scoped protocol claims.
- Claims from different endpoints never fuse unless an explicit asset-level
  promotion rule says they should.
- Fingerprint pack loading may never silently ignore malformed built-ins.
- Runtime built-in fingerprints must ship with the binary.
- Unknown is valid and should preserve useful raw evidence.
- UDP silence is unknown. Do not require a generic datagram response before
  scheduling DNS/SNMP/etc.
- Network budgets must describe real activity (dials **and** payload bytes),
  not only calls that happened to go through `DialTCP`.
- Do not build complete protocol clients. Build the smallest
  standards-correct exchange that identifies the protocol and collects
  useful unauthenticated metadata.
- Receiving bytes is not a protocol match.

## Refactor sequence

Work R1–R18 in order. Each PR must leave the end-to-end scanner working.

| PR | Objective | Status |
|---|---|---|
| R1 | Compile/test under PR CI; freeze feature additions; this document | done |
| R2 | Subject-aware fusion, version identity, OS composition | done |
| R3 | Engine owns fingerprinting, artifacts, and final claims | done |
| R4 | Iterative plan → execute → fingerprint → replan | done |
| R5 | Scheduler + network-operation budgets (HTTP/DNS/SNMP/bytes included) | done |
| R6 | Registry-derived priors; real `collect.banner` | done |
| R7 | Protocol claims; port priors then general fallback | done |
| R8 | UDP pipeline + DNS rebuild; silence is unknown | done |
| R9 | SNMP rebuild | done |
| R10 | HTTP/TLS relationship, redirects, body artifacts, favicon hashes | done |
| R11 | Real Recog/Wappalyzer | done |
| R12 | Harden text protocols + pos/neg integration tests | done |
| R13 | Harden DB/middleware protocols + framing tests | done |
| R14 | Harden LDAP/RDP/SSH/SMB | done |
| R15 | Recalibrate fingerprint packs + fixture corpus | remaining |
| R16 | Sirius adapter / config unification | remaining |
| R17 | IPv6 / multi-address completion | remaining |
| R18 | Performance, unknown-corpus, benchmarks, release hardening | remaining |

## R1 CI baseline

Commands that must pass:

```text
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...   # v2.12.2
```

CI (`.github/workflows/ci.yml`) runs build, vet, `go test -race`, and pinned
`golangci-lint` v2.12.2. Open a GitHub PR from
`cursor/ping-correctness-and-hygiene-d7fc` into `master` on `SiriusScan/pingpp`
for review.
