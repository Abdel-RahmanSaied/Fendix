# Changelog

All notable changes to Fendix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0-rc1] - 2026-04-30

Phase 13 — P3 External Release readiness, release-candidate. Validates the
new release pipeline (linux/arm64 binaries, multi-arch Docker, .deb/.rpm
packages, opt-in cosign keyless signing) end-to-end before tagging the
clean v0.6.0. Functional surface unchanged from `[Unreleased]` above —
all 6 Phase 13 work items (TASK-099..104) included. Operator items pending
for the v1.0 cut: `COSIGN_ENABLED=true` repo variable (signed artifacts +
commits) and `get.fendix.dev` DNS rollout (short-URL installer).

### Added

- **`--debug-bundle <path>` diagnostic tarball** (TASK-102). New flag on
  `fendix scan` writes a redacted `.tar.gz` at scan end intended for
  attaching to bug reports. Bundle contains six entries:
  `README.md` (top-level explainer), `config.json` (scan config with
  `auth.value` masked as `[REDACTED]` while preserving `auth.type` and
  `auth.header` for diagnosis), `environment.json` (fendix version, Go
  version, GOOS/GOARCH, resolved Python version, capture timestamp),
  `metadata.json` (the same `ScanMetadata` the JSON reporter receives),
  `findings.json` (post-sanitization findings), and `debug.log`
  (DEBUG-and-above slog stream captured via a tee handler installed for
  the duration of the scan, with auth values literal-replaced before
  serialization). When `--enable-active` is on, also includes
  `probes.jsonl` (one `ProbeRecord` per line, sorted by timestamp →
  endpoint → parameter for reproducibility across runs). New
  `internal/diagnostic` package (`bundle.go` + `redact.go`); new
  `internal/scanner/probe_audit_global.go` adds a process-level
  `ProbeAuditLog` with `ResetGlobalAuditLog` + `GlobalAuditRecords` so
  the orchestrator can read post-scan audit records (pre-fix the
  per-endpoint audit log was created freshly on each `CheckInjection`
  call and discarded after returning). Wired into the orchestrator at
  scan start (logagg + audit reset, slog tee install) and end (capture
  python version, probes, findings, metadata; write tarball before the
  fail-on check so non-zero exits still produce a bundle). 8 unit tests
  under `internal/diagnostic/` cover redaction, tarball shape,
  `--enable-active` probe inclusion, environment metadata, and
  unwritable-path error handling. New e2e regression
  `TestDebugBundle_WrittenAndRedacted` runs the binary against an
  httptest server with a real `--auth` value and asserts the bundle
  exists, contains all expected entries, and never leaks the auth
  credential anywhere — including the buffered slog stream. Closes the
  `--debug` exit criterion for Phase 13.
- **Linux `.deb` and `.rpm` packages** (TASK-100). Each release now ships
  Debian and RPM packages alongside the bare binaries: `fendix-vX.Y.Z-linux-amd64.deb`,
  `fendix-vX.Y.Z-linux-arm64.deb`, `fendix-vX.Y.Z-linux-amd64.rpm`,
  `fendix-vX.Y.Z-linux-arm64.rpm`, each with a matching `.sha256` sidecar
  (and `.sig` + `.crt` once `COSIGN_ENABLED=true` rolls out). Built with
  [nfpm](https://github.com/goreleaser/nfpm) from a single repo-root
  [`nfpm.yaml`](nfpm.yaml) covering both packagers. Dependencies declared
  on `python3` (required) and `semgrep` (recommended). Files install to
  `/usr/bin/fendix` plus docs under `/usr/share/doc/fendix/`. Install via
  `sudo dpkg -i fendix-*.deb && sudo apt-get install -f` on Debian/Ubuntu
  or `sudo dnf install ./fendix-*.rpm` on RHEL/Fedora — see new
  [`docs/install.md`](docs/install.md) for the canonical reference.
- **`docs/install.md` install reference** (TASK-100). Single-page guide
  covering every install path (Homebrew, install.sh, .deb, .rpm, Docker,
  manual binary, source), cosign verification one-liners for each asset
  type, the `get.fendix.dev` rollout status (operator-action: domain
  registration + GitHub Pages CNAME), and a troubleshooting section for
  the common install failures. Linked from the README's Documentation
  index. README install section gained `.deb` / `.rpm` quick-start
  blocks alongside the existing Homebrew and Docker entries.
- **Documentation pass for external evaluators** (TASK-101). Four new
  reference docs under `docs/`: [`walkthrough-juice-shop.md`](docs/walkthrough-juice-shop.md)
  takes a first-time user from `docker run` to opened HTML report in
  under 5 minutes against OWASP Juice Shop;
  [`semgrep-rules.md`](docs/semgrep-rules.md) is the rule-author guide
  covering Fendix's metadata expectations (`fendix_severity`, `category`,
  `confidence`), the Semgrep-result-to-Finding mapping, and worked
  examples for each bundled rule;
  [`triage-workflow.md`](docs/triage-workflow.md) is the operator guide
  for going from a fresh report to closed work items, covering the
  triage funnel, baseline diffs, suppression model + anti-patterns, and
  `jq` recipes for the JSON output. Plus a top-level "Documentation"
  index in [README.md](README.md) linking the walkthrough, CI integration
  page, triage workflow, JSON schema reference, Semgrep guide, per-check
  reference, ADRs, and security policy. Closes the docs-pass exit
  criterion for Phase 13.
- **Performance benchmark suite + published numbers** (TASK-104). Three new
  benchmarks in `go/internal/engine/scan_benchmark_test.go` measure
  end-to-end scan cost as a function of endpoint count: `BenchmarkScan_Throughput`
  (wall time + B/op + allocs/op), `BenchmarkScan_Goroutines` (peak goroutine
  count via a 2 ms ticker probe + atomic CAS), `BenchmarkScan_Memory` (allocation
  profile at scale). Each runs at sizes 10/100/500/1000 endpoints × 3 checks
  per endpoint × 32 workers against a local `httptest` server with a
  pool-friendly transport (`MaxIdleConnsPerHost: 64`) and silenced slog. New
  `make bench` Makefile target with `BENCHTIME ?= 5x` override. Reference
  numbers published in [README.md "Performance"](README.md#performance):
  Apple M1, Go 1.21 — 1000 endpoints in 31.7 ms / 24.7 MB / 166 peak goroutines.
- **`SECURITY.md` + active-scanner threat model** (TASK-103). New
  top-level [`SECURITY.md`](SECURITY.md) documents the vulnerability
  reporting channels (private GitHub Security Advisory + email),
  supported-versions policy, scope/out-of-scope for security reports,
  artifact-verification instructions (`cosign verify-blob` for binaries,
  `cosign verify` for the Docker image), disclosure timeline (72h ack,
  7d triage, 14d publication target), and an explicit policy for
  active-scanner misuse reports. New companion [`docs/threat-model.md`](docs/threat-model.md)
  is the reference for the active scanner's safety envelope: 7 threats
  (T1 destructive payload, T2 DoS, T3 auth/credential leakage, T4 safe-payload
  side effects, T5 cross-target contamination, T6 supply-chain compromise,
  T7 report XSS) each documented with scenario, Fendix-side mitigations,
  and operator-side residual risk; the explicit 5-property safety envelope
  any active probe must maintain (no write verbs without opt-in, no
  state-mutating payloads, no out-of-band callbacks, no cross-host
  crawl, all probes auditable); and an operator-responsibilities section
  delineating what Fendix owns vs. what the human running it owns.
- **Linux arm64 release binary** (TASK-099, partial). The release matrix now
  builds `fendix-vX.Y.Z-linux-arm64` alongside the existing
  `linux-amd64`/`darwin-amd64`/`darwin-arm64` artifacts. The Homebrew tap
  formula's `on_linux` block now branches on `Hardware::CPU.arm?` to download
  the arm64 build automatically; `scripts/install.sh` has matched arm64
  detection since v0.4.x. arm64 server users (Graviton, Ampere, Raspberry Pi
  4/5, ARM Linux laptops) can now `brew install fendix` or use
  `curl -fsSL …/install.sh | sh` and get a native binary.
- **Multi-arch Docker images** (TASK-099, partial). The Docker image at
  `ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z` is now a multi-arch manifest
  list covering both `linux/amd64` and `linux/arm64`. `docker pull` picks the
  right arch automatically per host. QEMU is wired into the release workflow
  so cross-arch builds run on the standard `ubuntu-latest` runner.
- **Cosign keyless signing — opt-in via repo variable** (TASK-099, partial).
  Both release binaries and the Docker image can be signed with cosign in
  keyless mode (Sigstore Fulcio + GitHub Actions OIDC — no static keys, no
  secrets to manage). Disabled by default; enable by setting the repo
  variable `COSIGN_ENABLED=true` (Settings → Secrets and variables →
  Actions → Variables tab). When enabled, every binary ships with `.sig` +
  `.crt` sidecar files; verify with:

  ```sh
  cosign verify-blob \
    --certificate fendix-vX.Y.Z-linux-amd64.crt \
    --signature   fendix-vX.Y.Z-linux-amd64.sig \
    --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    fendix-vX.Y.Z-linux-amd64
  ```

  Docker image verification:

  ```sh
  cosign verify ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z \
    --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
  ```

## [0.5.0] - 2026-04-30

Phase 12 — Quality & Ops. Polish that turns a working scanner into one
that fits production workflows: documented public JSON schema with
validation tests, schema-aware path-parameter substitution (templated
endpoints now actually get scanned), aggregated WARN log volume,
global scan budgets (`--max-requests`, `--max-duration`,
`--respect-robots`), apikey-query auth profile + e2e coverage of every
auth type, race-clean concurrency proof at 1000 endpoints + worker-pool
cancellation fuzzer, and a drop-in GitHub Actions workflow with SARIF
upload and PR summary comments.

### Added

- **Reference GitHub Actions workflow** (TASK-098). New
  `examples/github-actions/fendix-scan.yml` is a complete,
  drop-in CI workflow: scans on every PR and push to main,
  uploads SARIF to GitHub Code Scanning (inline annotations
  on the PR), persists the previous run's baseline via
  `actions/cache` (so PRs see only the diff), posts a PR
  summary comment via `actions/github-script@v7` with
  severity/source counts and the top 5 findings, and gates
  merges on `--fail-on HIGH` while still uploading SARIF and
  posting the comment when the gate fails. The comment
  payload reads the public JSON schema (`summary`, `sources`,
  `total`, `findings[].endpoint|line`) — same shape that
  `docs/schema.md` documents — so it stays correct as long as
  the schema is stable. `docs/ci-cd-integration.md` updated
  to point at the canonical example as its quick-start.

- **Concurrency review tests** (TASK-097). Two new tests in
  `internal/engine/` cover the worker pool's concurrency surface:
  - `TestWorkerPool_LargeConcurrentScan_RaceClean` — drives the pool with
    1000 endpoints × 3 checks × 32 workers against a single httptest
    server, asserts all 3000 invocations completed, server hit count
    matches, and no goroutines leaked. Runs under `-race` in CI as part
    of `go test ./...`, so any data race in the pool, scanner clients,
    or shared findings collection is caught on every PR.
  - `FuzzWorkerPool_CancelTiming` — native Go fuzzer that drives the
    pool with randomized (worker count, endpoint count, cancel-delay,
    busy-time) tuples and asserts no deadlock, no panic, and no
    goroutine leak under any cancel timing. Seed corpus exercises
    cancel-before-start, cancel-mid-flight, cancel-after-completion,
    zero-endpoints, zero-workers (clamped), and the tight cancel race.
    The seed corpus is exercised on every PR via `go test -race`.
    New `make fuzz FUZZTIME=30s` target runs deeper ad-hoc fuzzing
    (15s of `-race -fuzz` reaches 4400+ executions and 30+
    new-interesting inputs locally with no failures).

- **`--auth-type apikey-query`** (TASK-096). API-key authentication can
  now be delivered via URL query string instead of a request header — the
  common pattern for legacy or sensor-style APIs that prefer query
  placement (sometimes to avoid logging Authorization-class headers).
  CLI: `--auth-type apikey-query --auth-header api_key --auth my-key`
  produces `?api_key=my-key` on every outbound request and never sets a
  header. The param name comes from `--auth-header` (overloaded — same
  flag doubles as query-param name in this mode); defaults to `api_key`
  when unset. New constants `AuthTypeAPIKeyQuery` and
  `DefaultAPIKeyQueryParam` in `internal/models/auth.go`. New branch in
  `AuthContext.ApplyToRequest` mutates `req.URL.RawQuery` via
  `url.Values.Set` (idempotent on double-apply, preserves existing query
  params). Mirror branch in `injection.addAuth` for active-probe
  requests. Verified end-to-end: server-side wire-format assertion
  confirms the credential reaches the URL query and never a header.

- **End-to-end auth-profile coverage** (TASK-096). New
  `internal/e2e/auth_profiles_test.go` exercises every supported
  auth-type via the actual fendix CLI: bearer, apikey-header,
  apikey-query, basic, cookie. Each subtest spins up an httptest server
  that records every incoming request, asserts the expected wire
  format reaches it, and confirms the JSON report was written. This
  closes a Phase 12 visibility gap — the auth scanner had unit
  coverage since Phase 2 but no e2e proving the CLI flag-parsing,
  ScanConfig population, and per-scanner `ApplyToRequest` calls all
  worked as one integrated path.

- **Scan budget controls** (TASK-095). Three new flags shape how much
  work a scan does:
  - `--max-requests N` — soft-cap on total HTTP requests sent during the
    scan phase (discovery is exempt by design — a small cap shouldn't
    starve discovery before any check runs). Implemented as an
    `http.RoundTripper` wrapper in the new `internal/budget` package
    that increments an atomic counter on every outbound request and
    refuses further requests once the cap is hit. Cap-hit also fires a
    one-shot `context.CancelFunc` so the worker pool stops scheduling
    new jobs. Soft-stop semantics: in-flight requests finish, no new
    ones start; per-worker overshoot is bounded by `--workers`.
  - `--max-duration 5m` — wall-clock deadline. Wraps the run context
    with `context.WithTimeout`; deadline expiry triggers the same
    soft-stop path as the request cap. Accepts standard Go duration
    strings (e.g. `90s`, `2m30s`).
  - `--respect-robots` — when set, robots.txt `Disallow` paths are
    treated as a hard restriction across every discovery source (spec,
    sitemap, HTML crawl, brute-force). Brute-force pre-filters the
    wordlist so disallowed URLs never receive even a discovery probe.
    Default behaviour unchanged: Disallow paths are queued as endpoint
    hints, since they're often the highest-value targets for a
    security tool.
  Orchestrator emits a single `INFO budget summary` line at scan end
  with `requests_sent`, `requests_rejected`, `max_requests`, and
  `max_duration` whenever any cap is set. Unit tests cover the
  RoundTripper math under concurrent load (50-goroutine race test);
  e2e regressions verify the CLI integration: a 50-path scan with
  `--max-requests 20` is server-side capped, and `--respect-robots`
  with a `Disallow: /admin` rule prevents `/admin` from being touched.

- **Aggregated per-check WARN log volume** (TASK-094). New
  `internal/logagg` package caps WARN-level emissions at 3 per check key
  per scan (configurable via `SetCap`); subsequent events are downgraded
  to DEBUG and tallied. The orchestrator emits a single
  `INFO warning summary` line at scan end with per-key
  `warned=N suppressed=M` attrs (alphabetically sorted, deterministic).
  Eliminates terminal-flooding on partially-unreachable targets where
  every check fires the same transient error per endpoint. Real-world
  measure: a 10-endpoint scan against an unreachable target dropped from
  30 WARN lines (1 per check per endpoint) to 9 WARN lines + 1 summary
  (a 3× reduction). Goroutine-safe — worker pool calls into the
  aggregator from N goroutines concurrently. Integrated into the 18
  per-request WARN sites across auth, CORS, exposure, headers, injection
  (sqli/error/boolean/cmdi/crlf, baseline measurement, request build),
  and the Python engine spawner's malformed-JSON handler. Setup-time
  errors that fire at most once per scan (spec parsing failure, ignore
  file parsing, baseline save, python availability) keep their direct
  `slog.Warn` / `slog.Error` calls — capping wouldn't help and would
  hide important one-shot signals.

- **Path-parameter substitution for templated endpoints** (TASK-093).
  Discovered endpoints like `/users/{id}` previously produced HTTP
  requests to `/users/%7Bid%7D` because `http.NewRequest` URL-encodes
  the literal `{` and `}` characters. Every server returned 404 to that
  request, so every black-box check (headers, CORS, exposure, auth,
  rate-limit, injection) silently observed nothing on every templated
  endpoint of every OpenAPI spec. The crawler now substitutes a concrete
  sample value into the `FullURL` field at discovery time. The Path
  field is preserved as the template form so reports still show
  `GET /users/{id}` (not `GET /users/1`). Resolution order:
  `schema.example` → `schema.enum[0]` → type-driven default
  (integer/number → `1`, boolean → `true`, string + format=uuid → all-zero UUID,
  format=date → `2024-01-01`, format=date-time → `2024-01-01T00:00:00Z`,
  format=email → `user@example.com`) → parameter-name heuristic
  (`*Id`/`*_id`/`id` → `1`, `*uuid*`/`*guid*` → all-zero UUID,
  `count`/`page`/`limit`/`offset`/`index` → `1`, else `sample`) → `1`.
  Substitution applies to all five discovery sources (spec, JS, robots.txt,
  sitemap, HTML crawl); only the spec source has access to schema info,
  the rest fall through to the name heuristic. Verified against a real
  petstore3 spec scan: 4 templated paths (`/pet/{petId}`,
  `/pet/{petId}/uploadImage`, `/store/order/{orderId}`,
  `/user/{username}`) now produce non-zero black-box findings and zero
  `%7B` leakage in the report.

## [0.4.2] - 2026-04-29

Quality + UX patch. Two real-world bugs fixed (silent `fendix report` on
SARIF input; silent `os.Exit(2)` on any subcommand error) and the first
Phase 12 task lands (TASK-092 — output schema cleanup). No breaking
changes; safe upgrade for all v0.4.x users.

### Added

- **Documented JSON output schema** (TASK-092). New `docs/schema.md` +
  `docs/schema.json` (JSON Schema draft-07) act as the public, versioned
  contract for `fendix scan --format json` output. Stable for the v0.x
  line; additive changes only within minor releases. Schema-validation
  test walks every emitted report and enforces required fields, types,
  enums, the `SEC-NNN` id pattern, and the LOW-confidence severity cap.
- **Severity↔confidence consistency enforcement** (TASK-092). LOW
  confidence now caps severity at MEDIUM, MEDIUM caps at HIGH (derived
  from the scoring formula's implicit max). New
  `models.MaxSeverityForConfidence` + `EnforceSeverityConsistency`,
  wired as orchestrator step 5.6 between Deduplicate and Sort.
  Inconsistent findings get severity downgraded with an aggregated WARN
  summary; per-finding violations logged at DEBUG.

### Changed

- **`RenderJSON` always emits `findings: []`** (never `null`) so
  consumers can iterate without a null-check (TASK-092). Now part of
  the documented schema contract.
- **`[Unconfirmed by live scan]` evidence suffix tightened** (TASK-092).
  Only added when the whitebox finding normalises to a URL/path
  endpoint. File:line findings (e.g. a hardcoded secret in
  `src/config.py:14`) can't be confirmed by a live HTTP scan, so the
  suffix was misleading there. New `isURLEndpoint` helper gates both
  call sites in the correlator.

### Fixed

- **`fendix report --input` now rejects non-Fendix-JSONReport input.**
  Real-world bug: feeding a SARIF file to
  `fendix report --input results.sarif --format html` silently
  deserialized the SARIF document into a zero-value `JSONReport` and
  rendered an empty HTML page (0 findings, zero-time timestamp, blank
  version) — no error, no warning. New
  `reporters.ParseJSONReport(data)` helper detects SARIF (via `$schema`
  containing "sarif" OR top-level `runs` + `version` keys), random JSON
  (missing `metadata.version` and `metadata.mode`), and malformed JSON,
  and returns actionable error messages for each. SARIF-specific
  message hints at `fendix scan --format json` to produce a valid
  re-rendering input.
- **Subcommand errors now print to stderr** instead of vanishing into a
  silent `os.Exit(2)`. The root command had `SilenceErrors: true` to
  avoid double-printing structured logs from `fendix scan`, but
  `main()` never printed the error itself. Result: every
  command-level failure (bad `--format`, missing `--input`, parse
  errors, network errors) produced a bare exit 2 with no message.
  Now prints `Error: <msg>` to stderr before exiting.

## [0.4.1] - 2026-04-29

Build-infrastructure-only release. **No behavior changes vs v0.4.0** — all
detection logic, CLI flags, and report output are identical. v0.4.0 users
should upgrade to v0.4.1 only if they want to install via Homebrew or curl;
the v0.4.0 binary itself remains correct.

### Fixed

- **Distribution: anonymous install paths now actually work.** v0.4.0's
  release artifacts lived on a private repo, so every install path the
  README claimed (`brew tap`, curl-pipe, `github.com/.../releases/...`)
  returned 404 for any non-authenticated user. v0.4.1 routes all
  user-facing distribution through a public mirror at
  [`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix):
  `brew tap Abdel-RahmanSaied/fendix && brew install fendix` and
  `curl -fsSL https://raw.githubusercontent.com/Abdel-RahmanSaied/homebrew-fendix/main/install.sh | sh`
  both work end-to-end without auth.
- **CI on `main` is green for the first time since 2026-03-20.** Three
  long-standing pre-existing failures fixed: Python Test job was only
  installing `pytest` (now installs `requirements.txt` + `hypothesis`);
  TASK-085's `.env` test fixture was gitignored and never committed (now
  tracked via a fixtures-scoped negation rule); TASK-086's longer field
  name had left 4 files with stale gofmt alignment.

### Added

- **Docker image publishing** — `release.yml` now builds and pushes
  `ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z` and `:latest` on every `v*`
  tag (linux/amd64). Image visibility must be flipped to public via
  GHCR package settings on first push.
- **Public install mirror automation** — `release.yml` now has a `mirror`
  job that auto-creates a matching release on the public mirror with
  binaries+sha256s, and auto-regenerates `Formula/fendix.rb` in the
  mirror's main branch with fresh SHA256 sums on every `v*` tag.
  Idempotent (re-runs upload with `--clobber`).

### Changed

- **SARIF `tool.driver.informationUri`** now points at the public install
  mirror (`https://github.com/Abdel-RahmanSaied/homebrew-fendix`) so
  consumers reading SARIF reports don't 404 on a private repo URL.

## [0.4.0] - 2026-04-29

This release ships **Phase 11 — P1 Coverage Parity**: secrets, static analysis,
active scanning, deduplication, crawler discovery, real CVE lookups, and
correlator finalization. The goal was to close the gap with industry-baseline
detection (gitleaks / semgrep / ZAP) on the obvious checks. Folds the planned
v0.3.0 batch (TASK-085 + TASK-086) into v0.4.0 since v0.3.0 was never tagged.

### Added
- **Provider-specific secret patterns** — secrets analyzer now covers GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), Stripe live secret keys (`sk_live_`), Slack tokens (`xoxa-`/`xoxb-`/`xoxp-`/`xoxr-`/`xoxs-`), Google API keys (`AIza...`), Anthropic API keys (`sk-ant-`), OpenAI API keys (legacy `sk-`/`sk-proj-`/`sk-svcacct-`), npm registry tokens (`npm_`), and GCP service-account JSON files (matched on the canonical `"type": "service_account"` signature). Total pattern count: 7 → 15. (TASK-085)
- **`.env` file scanning** — `.env`, `.env.local`, `.env.production` etc. are now properly walked and scanned with a dedicated unquoted-`KEY=value` pattern. Previously the file walker missed dotfiles whose `Path.suffix` is empty, and the generic `HARDCODED_PASSWORD` regex only matched quoted values, so `.env` files passed through silently. (TASK-085)
- **Active scanner: body-param probing on POST/PUT/PATCH** — `requestBody.content."application/json".schema.properties` (OpenAPI 3) and `parameters[in:body].schema.properties` (Swagger 2) now flow into a new `Endpoint.BodyParams` field. Body-location probes serialize a JSON body where the target field carries the payload and sibling fields get a `"fendix"` placeholder, so server-side validation doesn't reject the request before reaching the vulnerable code. (TASK-086)
- **Active scanner: header-param probing** — `in: header` parameters now flow into `Endpoint.Headers` (with standard auth headers `Authorization`/`Cookie`/`X-Api-Key` filtered out) and get probed with header-location requests. Custom headers like `X-Trace-Id` and `X-Tenant-Id` are exactly the surface where header-value injection bugs hide. (TASK-086)
- **Error-based SQL injection detection** — sends a single `'"`-class payload and matches the response body against compiled regex patterns for MySQL, Postgres, MSSQL, Oracle, and SQLite error signatures. Confirmed matches surface as HIGH-severity HIGH-confidence findings. (TASK-086)
- **Boolean-based SQL injection detection** — sends a true/false payload pair (`' OR '1'='1` vs `' AND '1'='2`) and flags status-code flips or response-body length deltas > 5% as MEDIUM-confidence findings. (TASK-086)
- **SQLite + Oracle time-based SQLi payloads** — total time-based DB types: 3 → 5. SQLite uses `randomblob(99999999)` gated on a CASE expression; Oracle uses `DBMS_PIPE.RECEIVE_MESSAGE`. (TASK-086)
- **`--max-probes-per-endpoint` flag** (default 20) — the per-endpoint probe budget is now configurable. Replaces the previously hardcoded `MaxProbesPerEndpoint` constant; `0` falls back to the default. (TASK-086)
- **Static analyzer: pickle deserialization (`PY_PICKLE_LOAD`)** — `pickle.load()` / `pickle.loads()` flagged as CRITICAL HIGH-confidence (CWE-502). Also catches `cPickle` and `_pickle` aliases. (TASK-087)
- **Static analyzer: unsafe yaml.load (`PY_YAML_UNSAFE_LOAD`)** — `yaml.load()` without `Loader=SafeLoader`, `yaml.unsafe_load()`, and `yaml.load_all()` flagged as HIGH HIGH-confidence (CWE-502). `yaml.safe_load()` and explicit `Loader=yaml.SafeLoader` correctly skipped. (TASK-087)
- **Static analyzer: weak crypto for passwords (`PY_WEAK_CRYPTO_PASSWORD`)** — `hashlib.md5()` / `hashlib.sha1()` / `hashlib.new('md5'/'sha1', ...)` flagged HIGH MEDIUM-confidence (CWE-916) when the input subtree contains a password-like identifier (`password`, `passwd`, `passphrase`, `secret`, or whole-token `pw` / `pwd`). Substring-match for long tokens; whole-token snake_case-aware match for short abbreviations to avoid false positives like `pw` matching `power`. (TASK-087)
- **Static analyzer: open redirect (`PY_OPEN_REDIRECT`)** — `redirect()` / `HttpResponseRedirect()` called with `request.args/GET/POST/...` data flagged HIGH MEDIUM-confidence (CWE-601). (TASK-087)
- **Static analyzer: SSRF (`PY_SSRF`)** — `requests.get/post/put/delete/head/patch/options/request()` with a non-literal first arg flagged HIGH MEDIUM-confidence (CWE-918). Variables resolved through scope tracking — a constant URL assigned to a variable doesn't trigger. (TASK-087)
- **Static analyzer: auth-header trust (`PY_AUTH_HEADER_TRUST`)** — `if request.headers.get('X-Admin') == 'true':` and `if req.headers['X-Role']:` patterns flagged HIGH MEDIUM-confidence (CWE-290) under `auth_bypass` category. Recognizes both the global `request` and Flask-style `req` handler-arg name. (TASK-087)
- **Static analyzer: multi-step SQL injection** — `cursor.execute(name)` where `name` was assigned a BinOp/JoinedStr/Call earlier in the same function is now flagged via intra-function scope tracking. Closes the "Bobby Tables" string-concat gap from the 2026-04-28 evaluation. (TASK-087)
- **Findings deduplication via `AffectedEndpoints []string`** — N findings sharing the same (Title, Category, Severity) collapse into one finding whose `affected_endpoints` array lists every endpoint where the issue was detected. The grouped finding promotes to the highest confidence in the group, the strongest source signal (`correlated > blackbox > whitebox`), and the union of all references. Singleton findings keep `affected_endpoints` omitted so the JSON shape stays clean. Real-world re-test on `petstore3.swagger.io`: 160 findings → 10 (16× reduction; 9 deduped findings collapsed 159 occurrences across 21 endpoints). HTML reporter shows a "+N more" badge in the finding header and an "Affected endpoints (N)" list in the body; SARIF reporter emits one `Location` per affected endpoint per result (matches SARIF 2.1.0 §3.27.12 "this issue applies to all of them" semantics). (TASK-088)
- **Crawler: robots.txt discovery** — fetches `/robots.txt`, parses `Disallow:` and `Allow:` directives as endpoint hints, and follows `Sitemap:` directives to enqueue child sitemaps. Disallow paths are some of the highest-value targets — they're often the URLs operators don't want indexed, like admin or staging interfaces. (TASK-089)
- **Crawler: sitemap.xml discovery** — fetches `/sitemap.xml` (and any `Sitemap:` URLs from robots.txt), parses `<url><loc>` entries from `<urlset>` documents and `<sitemap><loc>` entries from `<sitemapindex>` documents (one level of recursion). Cross-host links filtered out. (TASK-089)
- **Crawler: HTML link parsing with recursive depth** — extracts `<a href>` and `<form action>` targets from HTML responses and follows them via BFS up to `--crawl-depth` levels deep. Same-host only (cross-host links dropped); a visited set prevents loops. New `--crawl-depth` flag (default `1` = home-page links only; `0` disables; `2+` follows links from those pages too). Non-HTTP schemes (`mailto:`, `tel:`, `javascript:`, `data:`, `ftp:`, `file:`, `sms:`) are filtered out so the scanner doesn't try to GET phantom endpoints. (TASK-089)
- **Crawler: `--wordlist` flag** — pass a path to override the built-in `CommonPaths` brute-force list. Plain text format, one path per line, `#` comments and blank lines ignored, leading `/` auto-added. (TASK-089)
- **Crawler: `--max-endpoints` budget** (default `500`) — caps total endpoint count after dedupe so a chatty sitemap or a deep HTML crawl can't produce a runaway scan. `0` removes the cap. (TASK-089)
- **Larger built-in `CommonPaths`** — wordlist expanded from ~50 to ~117 entries with admin/dashboard surfaces (`/admin/login`, `/console`, `/dashboard`), source-control leakage (`/.git/config`, `/.svn/entries`, `/.env`), DevOps tooling (`/grafana`, `/prometheus`, `/jenkins`, `/phpmyadmin`), debug endpoints (`/debug/vars`, `/debug/pprof`), and modern API conventions (`/api/v1/auth/login`, `/api/me`). (TASK-089)
- **Real CVE coverage via primary tools (pip-audit / npm audit / govulncheck)** — the deps analyzer now invokes pip-audit for `requirements.txt`, npm audit for `package.json` (when a lockfile is present), and govulncheck for `go.mod` as primary detection paths. The hardcoded 14-package known-vuln list is now a true offline fallback that fires only when the primary tool is missing or fails. **Real-world impact**: scan of `/tmp/fendix-test/badcode/requirements.txt` produced **6 deps findings** with the offline fallback alone, **97 deps findings (16× coverage)** with pip-audit installed. govulncheck against a Go fixture using `golang.org/x/net@v0.10.0` produces 4 HIGH findings (XSS, infinite parsing loop, non-linear and quadratic parsing) — only the actually-called vulns; vendored-but-uncalled noise is dropped. (TASK-090)
- **Go module support in deps analyzer** — `go.mod` files in `--code` are now scanned by govulncheck when installed. New `_check_go_modules` + `_run_govulncheck` methods; new module-level `_parse_govulncheck_json` parses govulncheck's pretty-printed multi-line JSON via `json.JSONDecoder.raw_decode` (the NDJSON assumption was wrong — caught during in-session live testing). Govulncheck `finding` messages with at least one `function` in their trace become "called" findings; vendored-but-uncalled vulns are skipped to avoid supply-chain noise. (TASK-090)
- **Correlator: path-suffix matching** — when one normalized path is a `/`-bounded suffix of the other, the correlator merges blackbox + whitebox findings even with base-path skew. Closes the petstore-style case where the spec describes `/pet/findByStatus` and the live server hosts it under `/api/v3/pet/findByStatus` — pre-fix, no exact path match meant no correlation; now they merge. (TASK-091)
- **Correlator: HTTP method-prefix stripping in endpoint normalization** — whitebox spec_parser emits endpoints as `"GET /pet/findByStatus"`. Pre-fix, the leading method dropped the value into the file-path branch and produced `"get /pet/findbystatus"`, blocking exact match against URL-derived blackbox endpoints. Method tokens (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/CONNECT/TRACE) are now stripped via regex before path parsing. (TASK-091)
- **Correlator: debug instrumentation** — every match attempt (and every miss) is logged at DEBUG level with the normalized endpoints, related categories, and match kind. Successful matches log at INFO with `match_kind=exact|suffix|fuzzy` so users can trace which predicate fired in real-world hybrid scans. (TASK-091)

### Fixed

- **Correlator: blackbox findings consumed at most once** — the previous index lookup didn't filter against the `bbCorrelated` set, so two different whitebox findings could both merge with the same blackbox, producing duplicate correlated findings. The new `findCorrelationMatch` honours a `taken` set across all three match passes. (TASK-091)
- Pattern boundaries on provider-specific tokens (`(?<![A-Za-z0-9])` anchors) prevent the OpenAI `sk-` regex from matching Anthropic's `sk-ant-` keys or matching inside concatenated base64 strings. (TASK-085)
- HTML crawler dropping `mailto:`, `tel:`, `javascript:`, `data:` scheme links surfaced as a real-world bug on `httpbin.org` where the home-page contact link was being followed and produced "unsupported protocol scheme" warnings on every check. (TASK-089)
- **pip-audit JSON key mismatch** — the integration was reading `data.get("vulnerabilities")`, but modern pip-audit (≥2.x) emits findings under `data["dependencies"]`. The result: pip-audit "ran" silently and emitted zero findings, with no fallback to the local list. Fixed by accepting both keys, treating any non-success exit code as a tool error that triggers fallback, and parsing the `aliases` field in references. (TASK-090)
- **e2e suite flakiness on macOS** — the brute-force phase opened 117 sequential connections per URL-based test, didn't drain the response body before close (preventing keep-alive reuse), and accumulated TIME_WAIT sockets that exhausted ephemeral ports under parallel-test load. Fixed by (a) draining response bodies in `fromBruteForce` before close, (b) raising `MaxIdleConnsPerHost` to 32 on the crawler's HTTP transport for connection reuse, and (c) routing every URL-based e2e test through a 1-path `tinyWordlist` so they don't pay 117 probes for tests that don't exercise brute-force. Suite now passes 7/7 sequential runs. (TASK-090)

## [0.2.0] - 2026-04-29

This release closes six P0 user-facing bugs surfaced by the 2026-04-28 real-world test pass.
After this release, every documented CLI flag does what its `--help` text claims.

### Fixed
- **`--save-baseline` was dead code at the CLI** — flag was declared but never read into `ScanConfig`, so no file was written. Now wired through `main.go` to the orchestrator's existing baseline path. (TASK-079)
- **`--code`-only scans refused to run** — orchestrator early-exited on "no endpoints discovered" before reaching the white-box branch. The guard now fires only when both endpoints AND `--code` are absent. (TASK-080)
- **Active scanner ignored spec-defined query parameters** — every probe targeted a hardcoded `id` param, missing real vulnerabilities on `host`/`url`/`username`/etc. The crawler now extracts `in: query` and `in: path` parameters from OpenAPI 2.0 and 3.x specs (path-level + operation-level layered correctly). (TASK-081)
- **`--spec` did not accept HTTP/HTTPS URLs** — `--spec http://host/openapi.json` silently fell back to brute-force. Specs are now fetched over HTTP with format auto-detection (URL suffix → `Content-Type` → first-byte sniff), 50 MB size cap, and 4xx/5xx surfaced as errors. (TASK-082)
- **`make test` failed from a clean checkout** — `cd python/ && pytest` broke `test_self_audit.py` (paths are repo-root relative). Makefile now runs pytest from repo root; the test was also hardened with cwd-agnostic `Path(__file__).resolve().parents[2]`. (TASK-084)

### Changed
- **SARIF: 1 rule per check type, not 1 rule per finding** — previously, 160 findings produced 160 unique rule IDs (`SEC-001..SEC-160`), so GitHub Code Scanning scattered the same vuln across N "rules". Rule IDs are now stable `fendix.<category>.<title-slug>`. Per-finding `SEC-NNN` IDs remain in JSON output as instance IDs but no longer appear in SARIF. **This is a breaking change for any consumer that pinned to v0.1 SARIF rule IDs in baselines or suppressions.** (TASK-083)

### Added
- **End-to-end test infrastructure** — `go/internal/e2e/` gated behind `//go:build e2e` and run via `make e2e`. Each fixed Phase 10 flag now has an e2e regression test that runs the built binary and asserts the externally-observable effect (`TestSaveBaseline_WritesFile`, `TestCodeOnlyScan_ProducesFindings`, `TestActiveProbe_UsesSpecParam`, `TestSpecURL_FetchedAndParsed`). This closes the bug class where unit tests pass but the CLI flag is unreachable.

## [0.1.0] - 2026-04-11

### Added
- **Hybrid scanning engine** — Go black-box scanner + Python white-box analyzer communicating via newline-delimited JSON IPC
- **Black-box checks:** security headers, CORS misconfiguration, authentication bypass (JWT malformed/expired/alg:none), sensitive data exposure, rate limiting detection, IDOR two-account check
- **Active injection probes** (opt-in via `--enable-active`): time-based SQL injection (MySQL, PostgreSQL, MSSQL), command injection (echo canary), CRLF header injection
- **White-box checks:** secrets detection (7 pattern types), Semgrep rules (auth, injection, secrets), OpenAPI spec parser (2.0 + 3.x), AST analyzer (Python + JavaScript), dependency CVE checker (PyPI + npm)
- **Correlator** — cross-references black-box and white-box findings; correlated findings get elevated confidence
- **Three output formats:** JSON (default), self-contained HTML, SARIF 2.1.0
- **CI/CD integration:** `--fail-on` exit codes, `--baseline` / `--save-baseline` diff mode, SARIF upload for GitHub Code Scanning
- **`.fendix-ignore`** suppression file — suppress by ID, endpoint, category with optional expiry dates
- **Auth profiles** — `~/.fendix/profiles/<name>.yaml` for reusable auth configurations
- **Credential masking** — auth values always displayed as `[REDACTED]` in all output
- **Distribution:** embedded Python engine via `go:embed`, multi-stage Dockerfile, curl-pipe installer, Homebrew formula
- **`fendix report`** command — re-render saved JSON findings to HTML/SARIF without re-scanning
- **Active probe safety:** legal disclaimer, per-endpoint rate limit (20 probes max), full audit log
- **Severity scoring model** — multiplicative formula: ImpactBase x ConfidenceMult x SourceMult
- **Worker pool** — concurrent HTTP scanning with configurable `--workers`, `--timeout`, `--delay`
