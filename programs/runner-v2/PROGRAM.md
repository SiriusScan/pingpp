---
goal: "Ship production cmd/pingpp as a thin CLI over Runner V2 (multi-target execution), scan.Session (prepared runtime), and the existing adaptive engine — without recreating the legacy probe runner."
status: "active"
acceptance_criteria:
  - "docs/runner-v2.md is the frozen source of truth for layering, scan.Config, Session, target semantics, pingpp.scan/v1, artifacts, exit codes, and stdout/stderr."
  - "cmd/pingpp is only a bootstrap: os.Exit(cli.Run(args, stdout, stderr)). It never imports pkg/probes or the old fingerprint aggregator, never contains a protocol switch, and never pre-resolves hostnames."
  - "pkg/runner V2 multiplexes targets (streaming TargetSource, host concurrency, sinks, events, summary). pkg/scan.Session loads registry/fingerprints/artifacts/limiter once. pkg/engine remains the single-target adaptive owner."
  - "Machine output is versioned pingpp.scan/v1 (JSONL for batch). Persistent output references persistent artifacts. Unknown/unresponsive is a result, not exit 1."
  - "C2 engine prerequisites are closed before concurrent/public Runner use: multi-address state merge, per-target budgets, collector panic recovery, metrics=ClaimProtocol, ICMP≠skip-discovery, MQTT/AMQP/VNC/SOCKS formal or experimental."
  - "go test ./..., go test -race ./..., go vet ./..., golangci-lint run ./... (v2.12.2) pass on the branch. go install …/cmd/pingpp works. README matches the new model."
  - "New cmd/pingpp never invokes the quarantined legacy runner. -probes is rejected/deprecated, not mapped into collector disable lists."
human_gates:
  - "Human approval before tagging or publishing a production ping++ release."
  - "Human approval before scanning networks or hosts the operator did not name."
  - "Human approval before changing third-party fingerprint notices, Recog/Wappalyzer licensing text, or shipping corpora as a claimed production capability."
  - "Do not enable --profile full as a default anywhere until C16 full-scan stress evidence exists."
---

# Program: runner-v2

## Operating Contract

Outcome:

- Replace the three current execution stories (stale README `cmd/pingpp`,
  legacy `pkg/runner` probe switch, `examples/scan` prototype CLI) with one
  production layer: CLI → Runner V2 → `scan.Session` → engine.

Non-goals:

- Do not refresh flags on the old runner or grow `pkg/runner.Result` with
  TLS/HTTP/claims.
- Do not make `cmd/pingpp` an engine, protocol switch, or fingerprint owner.
- Do not pre-resolve hostnames in the runner.
- Do not implement `pingpp replay` or `pingpp discover-domain` in C1–C15
  (bundle format must be replay-friendly; `-seed` stays out of `scan`).
- Do not accept URL/`host:port` as silent hostname truncation. V1 rejects
  them; endpoint hints are post-V2.
- Do not silently turn `deep` into TCP 1–65535.
- Do not advertise `--max-bytes-per-host` / `--max-requests-per-endpoint` /
  exact SMB rate until the engine enforces them.
- Do not reset `cursor/ping-correctness-and-hygiene-d7fc` to `master`.

Selected stack and source:

- Existing ping++ Go 1.24 module `github.com/SiriusScan/ping++`.
- Engine R1–R18 on this branch remain the scanning intelligence
  (`docs/prototype-known-gaps.md`).
- Native validation: `go test ./...`, `go test -race ./...`, `go vet ./...`,
  `golangci-lint run ./...` (v2.12.2).
- No new language/scaffold. Production binary path is `cmd/pingpp`.

Owned paths (program-wide):

- `docs/runner-v2.md` (contract; exclusive during C1)
- `programs/runner-v2/`
- `cmd/pingpp/`, `internal/cli/`, `internal/legacyrunner/`
- `pkg/runner/`, `pkg/scan/`, `pkg/output/`, `pkg/artifact/`, `pkg/buildinfo/`
- Engine files only when a C-stage names them (C2)
- `README.md` at C15–C16, not before

Dependencies and order:

1. C1 freeze contract (this cycle).
2. C2 engine prerequisites.
3. C3 `scan.Config` then C4 `ProfileFull`.
4. C5 `Session`, C6 FileStore, C7 limiter/concurrency (C6 may parallel C5
   if owned paths stay disjoint: `pkg/artifact` vs `pkg/scan`).
5. C8 TargetSource then C9 Runner.
6. C10–C11 output, then C12 CLI, C13 UX, C14 introspection.
7. C15 legacy quarantine, C16 hardening.

Loop limits:

- One C-stage per bounded task unless the stage is docs-only.
- Stop a stage after two failed approaches; reframe or escalate
  Grok → Terra-high → Sol-high on concrete failure.
- Do not start C12 until C1, C2, C3, C5, and C8 are done.

Retry policy:

- Retryable: test flakes, lint, incomplete owned-path edits.
- Not retryable: expanding into URL hints, replay, or `cmd/pingpp` before
  the C12 gate; mapping `-probes` into collector allowlists.

## Stage 1: Freeze contract (C1)

Owned paths:

- `docs/runner-v2.md`
- `programs/runner-v2/PROGRAM.md`
- `docs/prototype-known-gaps.md` (pointer only)

Tasks:

- [x] Confirm the goal and acceptance criteria
- [x] Write frozen `docs/runner-v2.md`
- [x] Record dependencies, risks, and human gates
- [x] Merge/commit C1 on `cursor/ping-correctness-and-hygiene-d7fc`

## Stage 2: Engine prerequisites (C2)

Owned paths:

- `pkg/engine/`
- `pkg/metrics/`
- `pkg/protocol/{mqtt,amqp,vnc,socks}/` if converting or unregistering
- `pkg/protocol/smb/` if metering
- `integration/appscanner/` ICMP vs skip-discovery mapping

Tasks:

- [x] Multi-address `mergeScanState` (Matched, RuledOut, reachability, meter)
- [x] Per-target budget semantics
- [x] Collector panic → `OutcomeInternalError`
- [x] Metrics = ClaimProtocol; empty outcome+error is not a match
- [x] MQTT/AMQP/VNC/SOCKS: ResultCollector+fixtures or experimental/unregister
- [x] `--no-icmp` ≠ skip-discovery
- [x] `go test ./pkg/engine ./pkg/metrics ./pkg/protocol/...` (full `./...` still fails on leftover `cmd/pingpp`)

## Stage 3: Scan API (C3–C5)

Owned paths:

- `pkg/scan/`
- `pkg/engine/profile.go` (C4 full profile)

Tasks:

- [x] Canonical `scan.Config` + port tri-state
- [x] `ProfileFull`; deep stays curated
- [x] `scan.Session` loads corpus once

## Stage 4: Artifacts, limiter, targets, runner (C6–C9)

Owned paths:

- `pkg/artifact/` (C6)
- `pkg/transport/` + engine limiter (C7)
- `pkg/runner/` (C8–C9; quarantine legacy first or into `internal/legacyrunner`)

Tasks:

- [x] FileStore
- [x] Global network-op limiter (host concurrency stays Runner/C9)
- [x] Streaming TargetSource
- [x] Runner.Run

## Stage 5: Output and CLI (C10–C14)

Owned paths:

- `pkg/output/`, `pkg/buildinfo/`
- `cmd/pingpp/`, `internal/cli/`

Tasks:

- [x] `pingpp.scan/v1` + text/json/jsonl
- [x] `cmd/pingpp` scan + version
- [x] Signals, exit codes (input/config 2, run timeout 1, SIGINT 130, NXDOMAIN 0, `scan --help` 0)
- [ ] Introspection commands

## Stage 6: Legacy + release (C15–C16)

Owned paths:

- `internal/legacyrunner/` or `pkg/legacyrunner/`
- `integration/appscanner/`
- `README.md`

Tasks:

- [ ] Quarantine old runner; new CLI never calls it
- [ ] README rewrite
- [ ] Benchmarks and full-profile stress behind the human gate

## Current handoff

```yaml
goal_id: runner-v2
task_id: runner-v2.s6.t001
stage: "6 CLI UX / C13+"
cycle: 3
attempt: 1
assigned_role: grok
owned_paths:
  - cmd/pingpp/
  - internal/cli/
  - pkg/runner/
  - pkg/output/
  - pkg/buildinfo/
acceptance_criteria:
  - C9 ScanRun streams TargetSource through a bounded worker pool
  - cmd/pingpp scan + version exist; .gitignore no longer swallows cmd/pingpp
  - Session.Scan is concurrent via per-target Engine sharing fingerprints
next_action: C14 introspection commands; C15 README/legacy quarantine later. Core engine follow-ups remain HTTP pinned-IP redirects, per-host transport semaphore, and IPv6 filtered-vs-starved matrix.
```
