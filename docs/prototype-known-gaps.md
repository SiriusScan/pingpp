# Ping++ rebuild contract

Living status for `cursor/ping-correctness-and-hygiene-d7fc`. Update this file
**in the same commit as each R-stage** so it never describes a previous tree.

This is not a production-readiness claim and not a historical freeze snapshot.

## How to update

After each R-stage commit, edit that stage in place:

```text
R<n> <title>
Status: COMPLETE | PARTIAL | NOT STARTED
Commit: <short sha> <subject>
Acceptance tests:
- <TestName> — what it actually proves
Known debt:
- <remaining semantic hole, or "none">
```

Do not leave completed work described as missing. Do not mark COMPLETE while
listed known debt still violates the stage's acceptance bar.

## Freeze policy

- **Do not reset to `master`.**
- **Do not remove protocol coverage** merely because collectors are incomplete.
- **Do not add more protocols** until classification, planner, fusion, and
  Engine composition are aligned.
- Ports are priors, never identity.
- Product fingerprints stay outside collectors.
- Protocol-specific data belongs in typed observation payloads, not asset fields.
- Unknown is valid. Receiving bytes is not a protocol match.

Reviewed prototype commit: `bfef5cb`.

## Current head

`2beeda5` — meter all I/O, fall back after port priors, keep silent UDP.

Canonical path:

```text
resolve → discover → enumerate → plan → collect → fingerprint → re-plan → enrich → Asset
```

Next stage: **R15**.

---

## R1 Freeze / CI

Status: COMPLETE

Commit: `07d45cd` freeze chassis, CI gate, this document; `db41113` run CI on `cursor/**`

Acceptance tests:
- CI workflow `.github/workflows/ci.yml` — `go test -race`, `go vet`, golangci-lint v2.12.2
- `go test ./...` must pass on the branch

Known debt:
- none for the freeze bar

---

## R2 Subject-aware fusion

Status: COMPLETE

Commit: `c39c565` subject-aware claim fusion with version and OS composition

Acceptance tests:
- `TestFuseDoesNotMergeAcrossEndpoints` — nginx on `:80` and `:443` stay distinct
- `TestFuseKeepsConflictingVersionsSeparate` — `1.22` vs `1.24` do not collapse
- `TestFuseCombinesIndependentSignalsOnSameEndpoint` — independent groups combine
- `TestComposeDropsRawWeakLinuxAfterNormalization` — weak Linux does not leak
- `TestCorrelationGroupDoesNotInflate` — same HTTP response does not score-inflate

Known debt:
- none for the fusion bar

---

## R3 Engine owns fingerprinting

Status: COMPLETE

Commit: `73491a3` Engine owns fingerprinting, artifacts, and final claims

Acceptance tests:
- `TestEngineOwnsFingerprints` — `ScanTarget` attaches matcher claims
- `TestNoProductClaimsInCollectorOutput` — collectors do not emit product claims

Known debt:
- Sirius adapter still has a legacy runner path (R16)
- Built-in packs still load from filesystem via `runtime.Caller` (R15)

---

## R4 Adaptive planner

Status: COMPLETE

Commit: `b9ac12b` iterative planner loop; `fd633e4` plan from `ProbeOutcome`, not Completeness

Acceptance tests:
- `TestPlannerTLSSuccessReplansHTTP` — TLS Success schedules HTTP with `tls=1`
- `TestPlannerSSHSuccessStopsIrrelevantCollectors` — exclusive match stops spray
- `TestPlannerNoMatchIsNotRetried` — NoMatch rules the protocol out
- `TestPlannerTerminatesDeterministically` — idle after a finished scan
- `TestPlannerSchedulesEnrichmentForWeakHTTP` — weak product evidence enriches once

Known debt:
- none for the adaptive-planner bar. Port-prior fallback is R6/R7.

---

## R5 Metering / scheduler / budgets

Status: COMPLETE

Commit: `a244346` count network ops and enumerate TCP concurrently; `2beeda5` meter HTTP/DNS/SNMP and Read/Write bytes

Acceptance tests:
- `TestMeterCountsDialsAndRespectsBudget` — `MaxNetworkOps` stops extra dials
- `TestMeterCountsConnBytes` — connection Read/Write increment byte counters
- `TestWrapUDPKeepsPacketConn` — UDP wrappers stay datagram sockets (DNS framing)
- `TestHTTPCollectorUsesMeteredTransport` / `TestHTTPCollectorRespectsNetworkBudget`
- `TestDNSCollectorUsesMeteredTransport`
- `TestSNMPCollectorCountsDial`
- `TestEnumerateStopsAtNetworkBudget` / `TestNetworkBudgetStopsLaterCollectors`

Known debt:
- SNMP still self-dials inside `gosnmp.Connect`; the scan meter reserves the op with `CountDial` and wraps the resulting conn for bytes. The library socket is not `DialUDP`.
- ICMP discovery uses `CountDial`, not wrapped pinger I/O, so ICMP payload bytes are not counted.
- Legacy `pkg/probes/*` still dial on their own (not on the Engine path).
- Unregistered `collect.tcpstack` still uses `net.Dialer`.

---

## R6 Registry priors + banner

Status: COMPLETE

Commit: `49d9650` derive collector priors from registry metadata; `2beeda5` continue into general fallback after port priors miss

Acceptance tests:
- `TestPlannerPortPriorsNotIdentity` — open port 22 does not schedule HTTP as a prior
- `TestPlannerUnknownPortUsesBannerThenTLS` — unknown TCP starts banner → TLS
- `TestPlannerFallbackAfterPortPriorsNoMatch` — HTTP on 22 after SSH NoMatch
- `TestPlannerRedisOnMySQLPortAfterPriorNoMatch` — Redis on 3306 after MySQL NoMatch
- `TestBannerReadsBytesWithoutProtocolClaim` — banner is not exclusive
- `TestNewRegistryHasSSHAndSMB` — production registry includes `collect.banner`, excludes `collect.tcpstack`

Known debt:
- none for the prior/fallback bar

---

## R7 Protocol claims + classification

Status: COMPLETE

Commit: `903b24a` emit protocol claims from `ResultCollector` outcomes; `2beeda5` fallback sequence

Acceptance tests:
- `TestProtocolConfirmPromotesEndpointOpen` — Success, not Completeness, opens the endpoint
- `TestPlannerTLSSuccessReplansHTTP` — HTTP scheme follows TLS, not port 443
- `TestClassificationPassesHostnameTarget` — hostname survives into collectors for SNI/Host

Known debt:
- some remaining collectors are still legacy `Run()`-only; Engine does not treat their Completeness as a match

---

## R8 UDP pipeline + DNS

Status: COMPLETE

Commit: `41bd3ea` enumerate UDP and speak DNS to the target; `2beeda5` silence is unknown, still classified

Acceptance tests:
- `TestEnumerateUDPReportsResponsivePort` — a real UDP reply is responsive
- `TestEnumerateUDPSilenceIsUnknown` / `TestClassifyUDPSilenceIsUnknown` — timeout is unknown, still emitted
- `TestPlannerUnknownUDPStillSchedulesProtocolCollectors` — unknown UDP/53 schedules `collect.dns`
- `TestPlannerClosedUDPIsNotClassified` — ICMP port-unreachable / closed is excluded
- `TestDNSCollectorSpeaksDNSNotOSResolver` — query hits the endpoint, not `net.LookupHost`
- `TestDNSCollectorNoMatchOnGarbage` — echoed garbage is not DNS

Known debt:
- enumeration still sends a one-byte datagram to surface ICMP unreachable. That probe must not be required for scheduling (it is not). NTP/IKE/SSDP have no protocol collectors yet — do not add them until later.

---

## R9 SNMP

Status: COMPLETE

Commit: `da8308d` rebuild SNMP collection on gosnmp

Acceptance tests:
- `TestSNMPObservationOmitsCommunity` — community never appears in JSON
- `TestSNMPNoMatchOnGarbageUDP` — echoed garbage is not SNMP

Known debt:
- same metering note as R5: `gosnmp` owns the dial

---

## R10 HTTP / TLS / artifacts

Status: COMPLETE

Commit: `4557bd6` HTTP scheme, redirects, body artifacts, favicon hashes

Acceptance tests:
- `TestHTTPSameHostRedirectAndCrossHostStop` — same-host follows; cross-host records `Location` and stops
- `TestHTTPBodyArtifactAndTruncation` — truncated flag + artifact id
- `TestHTTPFaviconHashes` — SHA-256 (and MMH3) on favicon bytes
- `TestTLSCollectorCapturesCert` / `TestTLSCollectorNoMatchOnPlaintext`

Known debt:
- extra same-host URLs beyond favicon/robots are enrichment (`collect.http.enrich`), not the default GET

---

## R11 Recog / Wappalyzer

Status: COMPLETE

Commit: `d6dd7c3` load Recog XML and Wappalyzer JSON corpora

Acceptance tests:
- `TestNativeRecogXMLOpenSSH` — Recog XML pattern → OpenSSH
- `TestWappalyzerJSONNginx` — technologies.json Server header
- `TestHTTPApplicationPack` — Grafana/Jenkins/nginx/IIS/WordPress still claimed (scores not the bar here)

Known debt:
- `NativeWebTech` remains a test fixture only; do not register it
- `LoadBuiltinPacks` is fail-closed on parse errors but still filesystem-based (R15)
- title-only YAML rules are still `strong` 88–92 (R15)

---

## R12 Text protocols

Status: COMPLETE

Commit: `ef6bed4` harden protocol collectors with positive and negative outcomes

Acceptance tests:
- `TestFTPRejectsHTTPLookalike` / `TestSMTPSuccessOn220`
- `TestFTPBanner` / `TestSMTPEHLOFeatures`

Known debt:
- IMAP/POP3/Telnet share `textproto` helpers; not every text collector has its own file of tests

---

## R13 DB / middleware

Status: COMPLETE

Commit: `ef6bed4`

Acceptance tests:
- `TestPostgresMatchSN` / `TestPostgresRejectsHTTP`
- `TestMySQLHandshakeSuccess` / `TestMySQLRejectsShortGarbage`

Known debt:
- Redis/Mongo/Memcached/MSSQL hardening is in the collectors; dedicated pos/neg files are thinner than MySQL/Postgres

---

## R14 LDAP / RDP / SSH / SMB

Status: COMPLETE

Commit: `ef6bed4`

Acceptance tests:
- `TestLDAPSuccessOnBER` / `TestLDAPRejectsHTTPLookalike`
- `TestSSHCollectorBanner` / `TestSSHCollectorRejectsHTTPLookalike`

Known debt:
- RDP/SMB pos/neg coverage is thinner than SSH/LDAP

---

## R15 Fingerprint packs + embed

Status: NOT STARTED

Commit: —

Acceptance tests (required):
- built-ins load via `go:embed` (no `runtime.Caller` path in production `NewEngine`)
- malformed built-in YAML/XML/JSON fails closed
- title-only application/device rules are hint/probable, not strong 88–92
- server-header self-id (nginx, IIS) may remain strong/exact
- fixtures exist for strong/exact rules

Known debt:
- `LoadBuiltinPacks` uses `RepoFingerprintsRoot()` + `runtime.Caller`
- `fingerprints/http/applications.yaml` title rules are still `strong`
- `fingerprints/devices/appliances.yaml` title rules are still `strong`

---

## R16 Sirius adapter / ScanOptions

Status: NOT STARTED

Commit: —

Acceptance tests (required):
- one `ScanOptions` (or equivalent) wrapping engine options
- `integration/appscanner` is Engine → Scan → map Asset; no duplicate fingerprint/OS path

Known debt:
- `PingPlusPlusStrategy` still has `fingerprintLegacyRunner`
- `runner.Options` / `engine.Options` / Profile remain separate vocabularies

---

## R17 IPv6 / multi-address

Status: NOT STARTED

Commit: —

Acceptance tests (required):
- `ScanTarget` scans every resolved A/AAAA, not only `Addresses[0]`
- hostname is kept for SNI/Host on every resulting scan
- `net.JoinHostPort` on IPv6 literals (already true in `pkg/transport`)

Known debt:
- `ResolveTarget` returns all addresses; `ScanTarget` uses `target.Addresses[0]` only

---

## R18 Metrics, unknowns, hardening

Status: NOT STARTED

Commit: —

Acceptance tests (required):
- runtime counters: collectors executed, protocol matches, timeouts, bytes, unknown endpoints, claim tiers, conflicts
- `ExactCorrect` / `StrongCorrect` are not updated on the scan path
- unmatched banners can be dumped for corpus work
- parser paths do not panic

Known debt:
- `pkg/metrics.Counters` still has ground-truth `ExactCorrect` / `StrongCorrect`
- Engine records conflicts only

---

## Standing rules

- After port-associated collectors return NoMatch, continue the general fallback sequence.
- Exclusive protocol Success still stops irrelevant collectors.
- UDP silence is unknown. ICMP port-unreachable may mark closed.
- Network budgets must describe real activity (dials **and** payload bytes).
- Fingerprint pack loading may never silently ignore malformed built-ins.
- Runtime built-in fingerprints must ship with the binary.
- Do not build complete protocol clients.

## CI

```text
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...   # v2.12.2
```
