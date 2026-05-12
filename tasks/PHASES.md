# Fendix — Task Planning Master

> This directory is the **source of truth** for all project work.
> Update it after every work session. Never let it go stale.

---

## Project Phases Overview

| Phase | Name | Status | Goal |
|---|---|---|---|
| 0 | Foundation | ✅ Complete | Project skeleton, models, CI |
| 1 | Passive Scanner | ✅ Complete | Headers, CORS, exposure checks |
| 2 | Auth Scanner | ✅ Complete | JWT, auth bypass detection |
| 3 | Python Engine | ✅ Complete | Secrets, Semgrep, spec parser |
| 4 | Orchestration | ✅ Complete | Hybrid scan, correlator |
| 5 | Active Scanner | ✅ Complete | Injection probes (opt-in) |
| 6 | Reporting | ✅ Complete | HTML, SARIF, baseline diff |
| 7 | Distribution | ✅ Complete | Build, Docker, install script |
| 8 | Documentation | ✅ Complete | README, ADRs, contributing guide |
| 9 | Hardening | ✅ Complete | Perf, edge cases, security review |
| 10 | P0 — Flag wiring | ✅ Complete | Fix broken user-facing CLI flags found in real-world testing (v0.2) — shipped 2026-04-29 |
| 11 | P1 — Coverage parity | ✅ Complete | Reach industry-baseline detection coverage (secrets, static, active, deps, correlator) — shipped as v0.4.0 on 2026-04-29 (folds the planned v0.3 batch into v0.4) |
| 12 | P2 — Quality & ops | ✅ Complete (7/7 — TASK-092..098; v0.5.0 shipped 2026-04-29) | Schema cleanup, dedup, scan budgets, auth profiles, CI recipes (v0.5) |
| 13 | P3 — External release | ✅ Complete (v0.6.0 shipped 2026-04-30 — first stable signed release) | Reproducible builds, signed artifacts, docs pass, benchmarks (v1.0) |
| 14 | P4 — External wedge | 🔲 Not Started | Reposition, prove coverage, lower CI-onramp friction, ship GH App (v1.1) |
| 15 | P5 — Open & extensible | 🔲 Not Started | Open-source the engine, plugin system, reachability correlation (v1.2) |
| 16 | P6 — Architecture v2 | 🔲 Not Started | Drop Python boot tax: native-Go simple checks, optional shelled-out Semgrep (v2.0) |

Status values: 🔲 Not Started | 🔄 In Progress | ✅ Complete | ⏸ Blocked

Phases 10-13 grew out of the 2026-04-28 real-world test pass — see `tasks/MEMORY.md` "Last Session Summary" for the bug evidence that informed each task.

Phases 14-16 grew out of the 2026-04-30 strategic-advisor session — see `tasks/MEMORY.md` "Strategic Session 2026-04-30" for the analysis that informed each phase. Sequencing rationale: Phase 14 wedges a credible external-evaluation story (numbers + onramp + GH App) on top of v1.0; Phase 15 opens the source + extensibility surface (the high-leverage growth multiplier); Phase 16 retires Python embedding once plugin system + native-Go checks make it optional.

---

## Phase 0 — Foundation

**Goal:** A compilable, testable project skeleton with all shared models defined. Zero functionality, but everything compiles and tests run.

**Value:** Unblocks all parallel work. Establishes conventions early so all subsequent code is consistent.

**Target:** `fendix version` prints version string. `go test ./...` passes. `python -m pytest` passes.

**Exit criteria:**
- [ ] Repository initialized with correct structure
- [ ] `go.mod` with all dependencies
- [ ] `python/requirements.txt` complete
- [ ] `Finding` model defined in Go and validated against JSON schema
- [ ] `ScanConfig` model defined
- [ ] Severity scoring logic implemented and unit tested
- [ ] `fendix version` command works
- [ ] GitHub Actions CI running on push (build + test)
- [ ] `Makefile` with: `make build`, `make test`, `make lint`, `make clean`
- [ ] Pre-commit hooks: `gofmt`, `golint`, `ruff`, `black`
- [ ] `docs/adr/` directory with ADR-001 (Go+Python hybrid decision)

**Tasks:**
```
TASK-001  Initialize Go module and directory structure
TASK-002  Initialize Python package structure
TASK-003  Implement Finding model (Go) with JSON serialization
TASK-004  Implement ScanConfig model (Go)
TASK-005  Implement severity scoring (Go) with table-driven tests
TASK-006  Wire cobra CLI skeleton with version command
TASK-007  Write GitHub Actions workflow (build + test + lint)
TASK-008  Write Makefile
TASK-009  Write ADR-001: Go+Python hybrid architecture
TASK-010  Write ADR-002: Newline-delimited JSON IPC contract
```

---

## Phase 1 — Passive Scanner

**Goal:** A working black-box scanner that performs zero active probing. Safe to run against any target, any time.

**Value:** Immediately useful. A developer can point this at any API and get a real security report in under 30 seconds.

**Target:** `fendix scan --url https://api.example.com --format html --output report.html` produces a real HTML report with header and CORS findings.

**Exit criteria:**
- [ ] Endpoint crawler working (spec + JS + brute-force)
- [ ] Security headers check (7 headers, correct severity per header)
- [ ] CORS misconfiguration check (4 scenarios)
- [ ] Sensitive data exposure check (7 response patterns)
- [ ] Rate limit detection check
- [ ] JSON reporter producing valid output
- [ ] HTML reporter producing self-contained single-file report
- [ ] Worker pool for concurrent scanning
- [ ] `--delay` and `--timeout` flags respected
- [ ] All checks have unit tests with mock HTTP servers

**Tasks:**
```
TASK-011  Implement endpoint crawler (spec parser + JS + brute-force)
TASK-012  Implement headers check with mock server tests
TASK-013  Implement CORS check with 4 scenario tests
TASK-014  Implement exposure check with regex pattern tests
TASK-015  Implement rate limit detection
TASK-016  Implement worker pool concurrency model
TASK-017  Implement JSON reporter with scan metadata
TASK-018  Implement HTML reporter (self-contained, color-coded)
TASK-019  Wire all passive checks into orchestrator (Go-only path)
TASK-020  Integration test: scan mock server, assert finding counts
```

---

## Phase 2 — Auth Scanner

**Goal:** Detect authentication and authorization failures on live APIs.

**Value:** Auth issues are the #1 OWASP category. This phase alone makes Fendix worth using.

**Target:** `fendix scan --url https://api.example.com --auth "Bearer token"` detects missing auth, JWT bypass, and expired token acceptance.

**Exit criteria:**
- [ ] Auth context parsing from all sources (flag, env, config file)
- [ ] Unauthenticated access check (missing auth → 200 = CRITICAL)
- [ ] Malformed JWT check
- [ ] Expired JWT check (generate expired token, test acceptance)
- [ ] `alg:none` JWT confusion check
- [ ] Two-account IDOR check (optional, requires `--auth-user2`)
- [ ] Auth credentials masked in all report output
- [ ] `~/.fendix/profiles/` config file support

**Tasks:**
```
TASK-021  Implement AuthContext model and multi-source resolution
TASK-022  Implement unauthenticated access check
TASK-023  Implement JWT validation bypass checks (3 scenarios)
TASK-024  Implement IDOR two-account check
TASK-025  Implement credential masking in all reporters
TASK-026  Implement ~/.fendix/profiles/ config system
TASK-027  Tests: auth checks against mock JWT server
```

---

## Phase 3 — Python Engine

**Goal:** A standalone Python static analysis engine that reads a ScanRequest and streams Findings.

**Value:** Catches vulnerabilities before they ship — in code, not in production.

**Target:** `echo '{"mode":"whitebox","code_path":"./src","checks":["secrets","semgrep"]}' | python python/engine.py` streams valid Finding JSON.

**Exit criteria:**
- [ ] `engine.py` entrypoint reads stdin, streams findings, emits `{"done":true}`
- [ ] Secrets analyzer with all 7 pattern types
- [ ] OpenAPI 2.0 + 3.x spec parser with auth checks
- [ ] Semgrep runner with custom rule set (auth, injection, secrets rules)
- [ ] AST analyzer for Python and JavaScript
- [ ] Dependency CVE checker
- [ ] All analyzers independently unit tested
- [ ] Engine independently runnable (no Go required)
- [ ] Python engine startup < 2 seconds measured and tested

**Tasks:**
```
TASK-028  Implement engine.py entrypoint and IPC contract
TASK-029  Implement secrets analyzer with 7 pattern types + tests
TASK-030  Implement OpenAPI spec parser (2.0 + 3.x) + tests
TASK-031  Write Semgrep rules: auth.yaml (4 rules)
TASK-032  Write Semgrep rules: injection.yaml (3 rules)
TASK-033  Write Semgrep rules: secrets.yaml (2 rules)
TASK-034  Implement Semgrep runner + result mapping
TASK-035  Implement AST analyzer (Python + JS basic patterns)
TASK-036  Implement dependency CVE checker (PyPI + npm)
TASK-037  Performance test: engine startup and scan time benchmarks
```

---

## Phase 4 — Orchestration & Correlation

**Goal:** Go spawns Python, merges findings, cross-correlates black-box and white-box results into a unified report.

**Value:** The hybrid approach delivers higher confidence findings with fewer false positives — the core differentiator of Fendix.

**Target:** `fendix scan --url https://api.example.com --spec openapi.yaml --code ./src` produces correlated findings with `"source": "correlated"`.

**Exit criteria:**
- [ ] Orchestrator spawns Python engine as subprocess
- [ ] Stdin/stdout IPC working end-to-end
- [ ] Go collects streaming findings from Python
- [ ] Correlator merges matching black-box + white-box findings
- [ ] Correlated findings have elevated confidence
- [ ] Unconfirmed white-box findings marked MEDIUM confidence
- [ ] Sequential ID assignment (SEC-001, SEC-002...)
- [ ] `.fendix-ignore` suppression file working
- [ ] Baseline diff mode working (`--baseline`, `--save-baseline`)
- [ ] `--fail-on` exit code logic working (for CI/CD)

**Tasks:**
```
TASK-038  Implement subprocess spawner with stdin/stdout wiring
TASK-039  Implement streaming Finding reader (Go side)
TASK-040  Implement correlator with endpoint normalization
TASK-041  Implement sequential ID assignment
TASK-042  Implement .fendix-ignore suppression parser
TASK-043  Implement baseline diff comparison
TASK-044  Implement --fail-on exit code logic
TASK-045  End-to-end integration test: hybrid scan on fixture project
```

---

## Phase 5 — Active Scanner

**Goal:** Optional injection probing — SQL injection, command injection, header injection. Off by default, requires `--enable-active`.

**Value:** Confirms exploitability, not just code patterns. A confirmed SQLi finding is worth 10 unconfirmed ones.

**Target:** `fendix scan --url https://api.example.com --enable-active` detects time-based SQLi with HIGH confidence.

**Exit criteria:**
- [ ] `--enable-active` flag gates all active probes
- [ ] Time-based SQLi detection (MySQL, Postgres, MSSQL payloads)
- [ ] Baseline response time measurement (3-sample median)
- [ ] Safe CMDi detection (echo canary, no destructive payloads)
- [ ] CRLF header injection detection
- [ ] Max probe limit per endpoint enforced
- [ ] Full audit log of every probe sent
- [ ] Legal disclaimer printed when `--enable-active` used

**Tasks:**
```
TASK-046  Implement safe probe framework with audit logging
TASK-047  Implement time-based SQLi detection (3 DB types)
TASK-048  Implement CMDi canary detection
TASK-049  Implement CRLF header injection detection
TASK-050  Implement per-endpoint probe rate limiter
TASK-051  Tests: active probes against deliberately vulnerable mock server
```

---

## Phase 6 — Reporting

**Goal:** Complete reporting system — JSON, HTML, SARIF. Baseline diff. CI/CD ready.

**Value:** Reports are what users see. A great report turns findings into action. A bad report gets ignored.

**Target:** `fendix scan ... --format sarif --output results.sarif` produces GitHub-compatible SARIF that shows PR annotations.

**Exit criteria:**
- [ ] JSON report: full findings + scan metadata + summary
- [ ] HTML report: self-contained, sortable table, expandable rows, color-coded severity
- [ ] SARIF 2.1.0 report: validated against schema, GitHub Actions compatible
- [ ] `fendix report --input findings.json --format html` re-render command
- [ ] Report includes: timestamp, target, scan duration, finding counts by severity
- [ ] HTML report renders correctly in all major browsers

**Tasks:**
```
TASK-052  Finalize JSON reporter with full metadata schema
TASK-053  Finalize HTML reporter with sorting, expand/collapse, print CSS
TASK-054  Implement SARIF 2.1.0 reporter
TASK-055  Validate SARIF output against official schema
TASK-056  Implement fendix report re-render command
TASK-057  Add GitHub Actions example workflow to docs
```

---

## Phase 7 — Distribution

**Goal:** Users can install and run Fendix in under 2 minutes on any platform.

**Value:** The best tool nobody can install is worthless.

**Target:** `curl -fsSL https://get.fendix.dev | sh` works on macOS and Linux.

**Exit criteria:**
- [ ] `scripts/build.sh` produces single Go binary
- [ ] Go binary embeds Python engine files via `//go:embed`
- [ ] Python extracted to `~/.fendix/engine/` on first run
- [ ] Graceful fallback if Python not installed (skip white-box, clear message)
- [ ] `Dockerfile` builds and runs correctly
- [ ] GitHub Actions release workflow (tags → binaries for linux/amd64, darwin/amd64, darwin/arm64)
- [ ] Homebrew tap formula
- [ ] `scripts/install.sh` curl-pipe installer

**Tasks:**
```
TASK-058  Implement Go embed of Python engine
TASK-059  Implement Python extraction on first run
TASK-060  Implement Python availability check with graceful fallback
TASK-061  Write GitHub Actions release workflow with goreleaser
TASK-062  Write Dockerfile (multi-stage)
TASK-063  Write install.sh curl-pipe installer
TASK-064  Write Homebrew formula
```

---

## Phase 8 — Documentation

**Goal:** Any engineer can understand, use, and contribute to Fendix within 30 minutes.

**Value:** Documentation is the product's public face. Poor docs = low adoption, regardless of quality.

**Target:** README.md, full API docs, contributing guide, all ADRs written.

**Exit criteria:**
- [ ] README.md complete (see structure below)
- [ ] `docs/adr/` — all architectural decisions documented
- [ ] `docs/checks/` — one page per check explaining what it detects and how
- [ ] `CONTRIBUTING.md` — how to add a new check, development setup
- [ ] `CHANGELOG.md` — maintained from first release
- [ ] All Go exported symbols have godoc comments
- [ ] All Python public functions have docstrings

**README.md required sections:**
1. Hero section — what Fendix is, one-line pitch
2. Quick start — 3 commands to first result
3. Installation — all methods
4. Usage — one example per major use case
5. All CLI flags with defaults
6. Output formats with examples
7. CI/CD integration — GitHub Actions workflow
8. Architecture overview
9. How to add a check (contributor quickstart)
10. License + responsible use notice

**Tasks:**
```
TASK-065  Write README.md (all 10 sections)
TASK-066  Write CONTRIBUTING.md
TASK-067  Write docs/checks/ — one page per check (10 files)
TASK-068  Complete all ADRs (ADR-001 through ADR-00N)
TASK-069  Write CHANGELOG.md
TASK-070  Audit all godoc comments (Go)
TASK-071  Audit all docstrings (Python)
```

---

## Phase 9 — Hardening

**Goal:** Production-ready. Edge cases handled. Performance validated. Security of the tool itself reviewed.

**Value:** A security tool with security vulnerabilities is embarrassing and dangerous.

**Target:** All performance budgets met. No known edge case crashes. Security self-audit complete.

**Exit criteria:**
- [ ] Performance: 100 endpoints scanned in < 30 seconds (measured)
- [ ] Python engine startup < 2 seconds (measured)
- [ ] Fuzz testing on Finding JSON parser
- [ ] Fuzz testing on OpenAPI spec parser
- [ ] Self-audit: run Fendix against itself
- [ ] Handle malformed responses without panic
- [ ] Handle network timeouts without hanging
- [ ] Handle Python engine crash without crashing Go binary
- [ ] Memory usage profiled for large scans (1000+ endpoints)
- [ ] All error messages are actionable (tell user what to do, not just what failed)

**Tasks:**
```
TASK-072  Write performance benchmark suite
TASK-073  Fuzz test Finding JSON parser
TASK-074  Fuzz test OpenAPI spec parser
TASK-075  Self-audit: run Fendix against Fendix codebase
TASK-076  Resilience testing: malformed responses, timeouts, crashes
TASK-077  Memory profiling on large scan simulation
TASK-078  Audit all error messages for actionability
```

---

## Phase 10 — P0: Flag wiring & broken-feature fixes (v0.2)

**Goal:** Every documented CLI flag and feature actually does what the help text says. No silent failures.

**Value:** Unblocks external evaluation. The first thing reviewers try is the obvious flag (`--save-baseline` for CI gates, `--code` for SAST-only). When those fail silently, the tool loses credibility instantly.

**Target:** A user running `fendix scan --code ./repo --save-baseline base.json` produces a baseline file. Re-running with `--baseline base.json` shows zero new findings. SARIF output validates against the official schema and groups results by check, not by finding.

**Exit criteria:**

- [ ] `--save-baseline` writes a file containing all findings from the current run
- [ ] `--code`-only scans (no `--url`, no `--spec`) run the Python engine and produce findings
- [ ] Active injection probes use spec-defined query and path parameters (not just hardcoded `id`)
- [ ] `--spec http://host/spec.json` fetches the spec over HTTP
- [ ] SARIF output has 1 rule per check type, not 1 rule per finding
- [ ] `make test` passes from a clean checkout (no cwd-dependent test failures)
- [ ] Every CLI flag has an end-to-end test that runs the binary and asserts observable effect
- [ ] All v0.1 unit tests still pass

**Tasks:**
```
TASK-079  Wire --save-baseline flag into ScanConfig (main.go)
TASK-080  Allow --code-only scans (reorder no-endpoints early-exit in orchestrator.go:61)
TASK-081  Populate Endpoint.Params from spec parameters (path + query, OAS 2 + 3)
TASK-082  Accept HTTP/HTTPS URL as --spec input (auto-detect prefix and fetch)
TASK-083  Fix SARIF: shared rule registry, 1 rule per check type
TASK-084  Fix Makefile test-python target to run from repo root (cwd bug)
```

---

## Phase 11 — P1: Coverage parity (v0.3 + v0.4)

**Goal:** Reach industry-baseline detection coverage. Stop being "noticeably worse than gitleaks/semgrep/ZAP" on the obvious checks.

**Value:** External evaluators directly compare against gitleaks (secrets), semgrep (SAST), and ZAP (DAST). The current corpus is too small to hold up under that comparison. Closing these gaps is the difference between "interesting prototype" and "credible alternative."

**Target:** On a juice-shop instance, fendix detects ≥1 SQLi (login bypass), ≥1 reflected XSS, ≥1 IDOR, plus all gitleaks-default secret types in the source tree. Hybrid scans actually emit `correlated` findings.

**Exit criteria:**

- [ ] Secrets analyzer covers all major modern providers (GitHub, Stripe, Slack, Google, Anthropic, OpenAI, npm, GCP service-account JSON)
- [ ] `.env` files (unquoted `KEY=value` format) are correctly scanned
- [ ] Static SAST catches string-concat SQLi, pickle/yaml.load, weak crypto, open redirect, SSRF, auth-bypass anti-patterns
- [ ] Active scanner probes body params and headers, not just query string
- [ ] SQLi detection includes error-based and boolean-based, plus SQLite/Oracle DBs
- [ ] Findings deduplicated: same check across N endpoints aggregates into one finding with N affected endpoints
- [ ] Crawler discovery improved: parses robots.txt + sitemap.xml + HTML links, supports `--wordlist`, larger default wordlist
- [ ] Dependency CVE coverage is real (pip-audit + npm audit + govulncheck), not 10-package fallback
- [ ] Correlator produces `correlated` findings on hybrid scans against the vuln-server fixture

**Tasks:**
```
TASK-085  Expand secrets patterns (8+ new providers) and fix .env unquoted-value scanning
TASK-086  Active scanner: probe body params + headers; add error-based + boolean-based SQLi; add SQLite/Oracle DBs; add --max-probes-per-endpoint flag
TASK-087  Static analyzer: string-concat SQLi, pickle/yaml.load, md5/sha1-for-passwords, open redirect, SSRF, auth-header-trust patterns (AST-based)
TASK-088  Findings deduplication: AffectedEndpoints []Endpoint field, group identical findings, propagate to JSON/HTML/SARIF
TASK-089  Crawler upgrade: robots.txt + sitemap.xml + HTML link parsing, recursive depth, --wordlist, larger default list
TASK-090  CVE coverage: pip-audit primary path, npm audit, govulncheck for go.mod; hardcoded list as offline fallback
TASK-091  Correlator: instrument with debug logs, loosen matching predicate, add e2e test asserting >=1 correlated finding
```

---

## Phase 12 — P2: Quality, performance, ops (v0.5)

**Goal:** Polish that turns a working scanner into a tool that fits production workflows.

**Value:** Adoption blockers that don't appear in a single demo but show up in week-2 use: noisy logs, no scan budgets, broken auth profiles, undocumented JSON schema.

**Target:** A 1000-endpoint scan with `--max-duration 5m --max-requests 10000` finishes within budget, with logs aggregated to <50 lines. Auth profiles cover bearer/api-key/basic/cookie/refresh-on-401. Output JSON validates against a published schema.

**Exit criteria:**

- [x] Output JSON schema documented and validated in tests (TASK-092)
- [x] `[Unconfirmed by live scan]` evidence suffix only appears when correlation was actually attempted (TASK-092)
- [x] HIGH/MEDIUM/LOW severity↔confidence consistency rules enforced (TASK-092)
- [x] Path-parameter substitution: `/users/{id}` becomes `/users/1` (or schema-derived sample), not `/users/%7Bid%7D` (TASK-093)
- [x] Logging aggregated: max 3 WARN per check, rest at DEBUG (TASK-094)
- [x] Global scan budget: `--max-requests N`, `--max-duration 5m`, `--respect-robots` (TASK-095)
- [x] Auth profiles: bearer, api-key (header + query), basic, cookie, all e2e tested (TASK-096; refresh-on-401 deferred to BACKLOG-011)
- [x] `-race` passes on a 1000-endpoint scan in CI (TASK-097)
- [x] Example GitHub Actions workflow committed: scan → SARIF → upload → PR comment (TASK-098)
- [x] Worker-pool cancellation has a fuzz test (TASK-097)

**Tasks:**
```
TASK-092  ✅ Output schema cleanup: docs/schema.md, JSON-schema validation in tests, evidence-suffix logic, severity↔confidence consistency
TASK-093  ✅ Crawler placeholder substitution: schema-derived sample values for path params
TASK-094  ✅ Logging hygiene: aggregate per-check failures, cap WARN volume, downgrade rest to DEBUG
TASK-095  ✅ Scan budget controls: --max-requests, --max-duration, --respect-robots, soft-stop semantics
TASK-096  ✅ Auth profiles e2e: bearer + api-key (header/query) + basic + cookie under tests/e2e/ (refresh-on-401 deferred to BACKLOG-011)
TASK-097  ✅ Concurrency review: -race against 1000-endpoint scan in CI, fuzz worker-pool cancellation
TASK-098  ✅ CI integration recipe: examples/github-actions/fendix-scan.yml with SARIF upload and baseline-diff PR comment
```

---

## Phase 13 — P3: External release readiness (v1.0)

**Goal:** Trustworthy, signed, documented v1.0 that an external user can adopt without reading the source.

**Value:** "External evaluation" only succeeds when artifacts are signed, docs answer the obvious questions, and benchmarks back up the marketing claims.

**Target:** `brew install fendix` (or `curl -fsSL get.fendix.dev | sh`) installs a signed binary that passes cosign verification. README links to a juice-shop walkthrough, a CI integration page, and a published performance benchmark.

**Exit criteria:**

- [ ] Release pipeline builds linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 — all signed with cosign
- [ ] Homebrew formula auto-updates SHA256 per release (no `PLACEHOLDER_*`)
- [ ] Docker image published to ghcr.io, signed
- [x] `.deb` and `.rpm` packages produced via nfpm
- [x] One-line installer at `get.fendix.dev` works on macOS + Linux (live 2026-04-30)
- [x] Docs: 5-minute juice-shop walkthrough, CI integration (GH Actions + GitLab + CircleCI), Semgrep rule guide, triage workflow, JSON schema reference
- [x] `--debug` flag bundles a redacted diagnostic tarball
- [x] `SECURITY.md` with disclosure policy
- [x] Active-scanner safety threat model documented
- [x] Performance benchmarks published in README (scan time vs endpoint count, memory, goroutine count)

**Tasks:**
```
TASK-099  Reproducible release pipeline: linux/arm64 added, cosign signing, Homebrew auto-update, signed Docker image
TASK-100  Distribution artifacts: .deb + .rpm via nfpm, get.fendix.dev one-line installer
TASK-101  Documentation pass: 5-min walkthrough, CI integration page, Semgrep rule guide, triage workflow, JSON schema ref
TASK-102  --debug bundle: redacted config + OS + Python version + probe audit + slog-debug into a tarball
TASK-103  SECURITY.md + active-scanner threat model + signed commits/releases
TASK-104  Performance benchmark suite: scan time vs endpoint count, memory peak, goroutine count, published in README
```

---

## Phase 14 — P4: External wedge (v1.1)

**Goal:** Turn v1.0 from "credible engineering" into "credible external evaluation." Reposition around the actual wedge (DAST + SAST in one PR check, only fails on confirmed findings); ship the proof (vulnerable-app benchmark numbers); lower the CI onramp (`fendix init`); occupy the GitHub Marketplace channel.

**Value:** Engineering quality is already there. What's missing is the *story* (positioning), the *proof* (benchmark numbers), and the *channel* (GH Marketplace + zero-config init). Closing this gap is the difference between "interesting prototype" and "tool a startup defaults to."

**Target:** A first-time user runs `brew install fendix && cd repo && fendix init && git push`, and 90 seconds later their PR has a Fendix comment showing "✓ confirmed by both engines" findings. README hero leads with the wedge ("DAST + SAST as one PR check"); README has a benchmark table with juice-shop / vampi / crapi numbers vs ZAP-baseline + Semgrep CI.

**Exit criteria:**

- [ ] README hero repositioned: lead with "DAST + SAST as one PR check, fails only when both engines confirm" — not "hybrid" (TASK-110)
- [ ] Top-of-README "What Fendix sends to the network" telemetry statement (TASK-111)
- [ ] Vulnerable-app benchmark suite running in CI on every push: juice-shop + vampi + crapi; numbers published in README (`Fendix detects N of M known bugs in X seconds vs ZAP-baseline Y / Semgrep Z`) (TASK-106)
- [ ] `fendix init` writes a working `.github/workflows/fendix.yml` + `.fendix.yaml` based on detected stack (TASK-105)
- [ ] `.fendix.yaml` repo-committed policy file: severities, ignored rules, fail-on threshold, auth profile reference (TASK-109)
- [ ] `fendix demo` spins up a known-vulnerable target locally and produces a sample report in <60s (TASK-108)
- [ ] GitHub App on the Marketplace: one-click install, auto-comments on PRs, auto-uploads SARIF (TASK-107)
- [ ] PR-comment template rewritten to lead with "confirmed by both engines" framing for correlated findings (extension of TASK-098)

**Tasks:**
```
TASK-105  fendix init: zero-config workflow generator (detect stack, write .github/workflows/fendix.yml + .fendix.yaml + .fendix-ignore)
TASK-106  Vulnerable-app benchmark suite in CI (juice-shop + vampi + crapi); numbers published in README
TASK-107  GitHub App / Marketplace listing: one-click install, auto PR comment, SARIF upload
TASK-108  fendix demo command: spins up local vulnerable target, runs scan, opens report
TASK-109  .fendix.yaml repo-committed policy file (severities, suppressions, fail-on, auth profile)
TASK-110  README repositioning: lead with the wedge (DAST+SAST as one PR check, confirmed-by-both-engines)
TASK-111  Telemetry statement at top of README ("What Fendix sends to the network") + verification one-liner
```

---

## Phase 15 — P5: Open & extensible (v1.2)

**Goal:** Open-source the engine + ship the plugin system + build the reachability/dataflow correlation that becomes the long-term moat.

**Value:** Closed-source posture costs everything (no trust, no contributions, no audit story) and protects nothing right now (no SaaS, no enterprise contracts). Opening + extending unlocks community, hiring, and the only correlation feature competitors can't replicate quickly.

**Target:** `github.com/fendix/fendix` is public under MIT or Apache 2.0; community can contribute Semgrep rules + custom checks via `~/.fendix/plugins/`; a hybrid scan against juice-shop produces at least one finding tagged `correlated:reachable` (whitebox proves taint source→sink AND blackbox confirms exploitation).

**Exit criteria:**

- [ ] License decision documented in ADR; engine repo split + released under chosen license; commercial-features repo (if any) clearly delineated (TASK-112)
- [ ] Plugin system: `~/.fendix/plugins/<name>/plugin.yaml` + Go binary or Python script; plugins receive ScanContext via NDJSON, emit Findings via NDJSON (same contract as existing engine IPC); 3 reference plugins shipped (TASK-113)
- [ ] Reachability/dataflow correlation: whitebox AST records taint-source-to-sink chains; correlator escalates to a new `correlated:reachable` source when blackbox confirms exploitation at the same endpoint; new severity multiplier (TASK-114)
- [ ] CONTRIBUTING.md updated for plugin authors; `good first issue` labels seeded; first 5 community-contributed Semgrep rules merged
- [ ] Open-source launch post published (HN, r/devops, r/golang); juice-shop walkthrough pulled forward to README hero

**Tasks:**
```
TASK-112  Open-source the engine: license decision (MIT/Apache 2.0), repo split, public release, ADR documenting the strategic decision
TASK-113  Plugin system: NDJSON contract identical to engine IPC, ~/.fendix/plugins/ + .fendix/plugins/ discovery, 3 reference plugins (e.g. custom-secret-pattern, custom-semgrep-pack, custom-blackbox-check)
TASK-114  Reachability/dataflow correlation: whitebox taint chains, blackbox confirmation, new correlated:reachable source, severity escalation, walkthrough doc
```

---

## Phase 16 — P6: Architecture v2 (v2.0)

**Status note (2026-05-11):** TASK-115, TASK-116, TASK-118 pulled forward into **Phase 17b** (v0.9) per [docs/quarter_plan.md](../docs/quarter_plan.md). Only TASK-117 (AST analyzer migration via tree-sitter or Python plugin) remains in Phase 16 as the true v2.0 leftover — it's the hardest of the four, the AST analyzer doesn't degrade gracefully when removed, and shipping <500ms p50 cold start without it still wins the cold-start story. The original Phase 16 body below is retained verbatim for historical reference; the cold-start work is now Phase 17b.

**Goal:** Make Python optional. Drop the embedded-Python boot tax for the 80% of scans that don't need Semgrep depth. Move closer to "Trivy-fast cold start" (<500ms) for the common case.

**Value:** Python startup tax (~2s) aggregated across thousands of daily CI runs is real cost. Embedded extraction is a frequent bug source (permissions, partial extracts, version drift). Tested across 4 platforms per release. None of this is necessary for secrets/regex/OpenAPI-parsing checks — those are Go-native.

**Target:** `fendix scan --code ./repo` (without Semgrep installed) finishes in <500ms cold and produces secrets + OpenAPI + dep-CVE findings. Semgrep depth is reachable via shelled-out `semgrep ci` if the user installs it. Python is removed from the embedded distribution.

**Exit criteria:**

- [ ] Secrets analyzer ported to Go (~400 LOC, all current patterns including .env handling)
- [ ] OpenAPI 2.0/3.x spec parser ported to Go (existing Go crawler already does most of this — consolidate)
- [ ] Dependency CVE checker shells out to `pip-audit` / `npm audit` / `govulncheck` (already does — formalize as the only path; remove offline-fallback list once tools are guaranteed-installable)
- [ ] Semgrep + Bandit removed from embedded engine; shelled out to user-installed binaries; clear "install semgrep for deeper SAST" message when absent
- [ ] AST analyzer either ported to Go (using `tree-sitter`) or kept as Python plugin (depends on Phase 15 plugin system)
- [ ] Cold start benchmark: <500ms p50 for code-only scans without Semgrep
- [ ] Embedded Python distribution removed; binary size reduction documented

**Tasks:**
```
TASK-115  Port secrets analyzer to Go (all 15 patterns + .env handling)              [PULLED FORWARD → Phase 17b]
TASK-116  Make Semgrep optional: shell out to user-installed semgrep, remove from
          embedded distribution; clear absence-messaging                              [PULLED FORWARD → Phase 17b]
TASK-117  AST analyzer migration: tree-sitter in Go OR Python plugin (decide after
          Phase 15 plugin system stabilizes)                                          [DEFERRED — true v2.0 leftover]
TASK-118  Remove embedded Python distribution; binary-size + cold-start benchmark
          in README                                                                   [PULLED FORWARD → Phase 17b]
```

---

## Phase 17 — P7: Engine-first roadmap (v0.8 → v0.11)

**Period:** 2026-05-11 → ~5 months (4 releases, each its own honest time budget)
**Source document:** [docs/quarter_plan.md](../docs/quarter_plan.md)
**Supersedes for this period only:** Q1 of [docs/example_plan.md](../docs/example_plan.md) (Stripe + AI explanation work). Cloud work resumes after Phase 17d ships.

**Goal:** Widen the OSS engine moat across four directions — detection breadth, false-positive discipline, cold-start performance, plugin ecosystem — before turning on revenue. Each direction ships as its own minor release with measurable exit criteria. No artificial 3-month deadline; each workstream takes the time it needs.

**Value:** The engine is the funnel per [docs/example_plan.md](../docs/example_plan.md) §1.7. Investing one stretched quarter (~5 months) widening the moat before Stripe + AI ship means: (a) Q2 conversion happens against a stronger product, (b) Q0 launch traffic gets a v0.8+ with FP discipline rather than v0.7 with rough edges, (c) Phase 16 cold-start work lands before more checks are written against the embedded-Python path. Trade-off accepted: no paid revenue for ~5 months; original Q1 of [docs/example_plan.md](../docs/example_plan.md) ($10K-MRR-by-month-9 target) shifts right by one full quarter.

**Decision gates (each one can re-plan the rest):**

1. **End of week 2:** Q0 launch result. If <100 stars / <8 installs in 2 weeks, pause Phase 17a and re-evaluate — widening moat on an unused product is sunk cost.
2. **End of Phase 17a (v0.8 ships):** FP corpus quality. If <15 real FPs catalogued, expand the corpus or accept that Phase 17d's real-world pass is doing the heavy lifting.
3. **Before Phase 17b:** Capacity check. If Phase 17a took >7 weeks (vs. ~6 planned), 70% capacity assumption is wrong — consider skipping straight to Phase 17c and deferring Phase 16/17b to next year.
4. **End of Phase 17b (v0.9 ships):** Plugin breakage rate. If v0.9 broke >1–2 reference plugins, add a hotfix sprint before Phase 17c.
5. **Before Phase 17d:** Launch-data sufficiency. Phase 17d needs real user FPs. If <20 user-reported FPs by then, defer Phase 17d to next year — no signal to act on.

**Cross-repo coordination (canonical tickets live in those repos):**

- `fendix-backend`: per-release, re-parse new engine JSON fields in `backend/scanning/services.py::FendixEngine` and regenerate `openapi.json` via `make schema`. No new Django apps. No Stripe. No AI explanation. ~1 day per engine release × 4 releases.
- `fendix_frontend`: per-release, `npm run codegen` against the regenerated `openapi.json`; surface new `ScanFinding` fields (taint chains for new reachability patterns, suppression snippet for TASK-124) in the dashboard. No new pages. ~2 days per engine release × 4 releases.

**Cut order if external pressure forces a stop:**

1. Phase 17d entire — defer round-2 FP tuning to "do during cloud quarter as a side track."
2. TASK-131 (plugin CI smoke test) — keep docs + reference plugins, drop the automated regression guard.
3. TASK-130 (`fendix plugins` CLI) — docs + reference plugins are the deliverable; CLI is nice-to-have.
4. TASK-118 cold-start benchmark publish — ship Phase 17b without published numbers; add in v0.9.1.
5. TASK-120 + TASK-121 (XSS + cmd-injection reachability) — keep v0.7's three patterns; v0.8 ships with just deps + FP work.

**Never cut:** Phase 17a's FP reduction (TASK-123, TASK-124, TASK-125), TASK-126 (ADR-008), or Q0 launch ops.

---

### Phase 17a — v0.8: Detection quality + FP reduction

**Estimate:** ~25 solo days with 25% integration buffer, ~6 weeks at 70% capacity. Runs in parallel with Q0 operator launch ops.

**Exit criteria:**

- [ ] Native dep-CVE scanners shipped for Go (`govulncheck`), Python (`pip-audit`-equivalent), Node (`npm-audit`-equivalent), reading manifests directly without delegating to OSV/Trivy.
- [ ] Two new reachability patterns shipped: XSS-sink taint chains and command-injection-sink taint chains, behind the same TASK-114 correlator escalation logic.
- [ ] FP corpus catalogued in `tasks/FP_CORPUS.md` with ≥15 real false positives from running engine against 3+ OWASP-juice-shop-style targets.
- [ ] Correlator confidence math rebalanced against the FP corpus; measured FP-rate reduction documented in release notes.
- [ ] Every finding in the PR comment ships with a copy-paste `.fendix-ignore` snippet keyed on stable hash (one-click suppression).
- [ ] `reachable_code` severity multiplier audited and rebalanced per [docs/example_plan.md](../docs/example_plan.md) §3.5; EPSS/KEV multipliers explicitly deferred to cloud quarter.
- [x] ADR-008 (read-only AI / supersede BACKLOG-017) committed to [docs/adr/](../docs/adr/).
- [ ] v0.8.0 tagged + release.yml run succeeds.

**Tasks:**
```
TASK-119  Native dep-CVE scanners (govulncheck / pip-audit / npm-audit) in
          internal/scanner/deps/{govulncheck,pip,npm}/                                ~6 days
TASK-120  XSS-sink reachability pattern in engine/correlator.go                       ~2 days
TASK-121  Command-injection-sink reachability pattern in engine/correlator.go         ~2 days
TASK-122  FP corpus build — scripts/fp-corpus/ runner + tasks/FP_CORPUS.md            ~2 days
TASK-123  Correlator confidence math pass — tighten thresholds against TASK-122       ~3 days
TASK-124  One-click suppression snippet in PR comment (ghapp/handler.go)              ~3 days
TASK-125  Severity scoring refresh — rebalance reachable_code multiplier              ~2 days
TASK-126  ADR-008 written into docs/adr/                                              ~1 day
```

---

### Phase 17b — v0.9: Phase 16 cold-start pulled forward

**Estimate:** ~21 solo days with 25% buffer, ~5 weeks at 70% capacity. The invasive workstream — most likely to slip; test extensively before tagging.

**Exit criteria:**

- [ ] Secrets analyzer ported from `python/analyzers/secrets.py` to Go in `internal/scanner/secrets/`; all current patterns including `.env` handling preserved; behind the same NDJSON in-process plugin contract.
- [ ] Semgrep shelled-out, not embedded — detect `semgrep` in `$PATH`; if absent, scan continues + emits "install semgrep for X% more checks" notice.
- [ ] Embedded Python distribution removed from binary; binary-size reduction documented.
- [ ] Cold-start benchmark: <500ms p50 for code-only scans without Semgrep; numbers published in [docs/benchmarks.md](../docs/benchmarks.md).
- [ ] Plugin wire-contract compatibility verified — v0.7-era plugins still work against v0.9, OR breaking changes documented with 1-minor-version deprecation window.
- [ ] v0.9.0 tagged + release.yml run succeeds.

**Tasks:**
```
TASK-115  Port secrets analyzer to Go (pulled forward from Phase 16)                 ~6 days
TASK-116  Make Semgrep shelled-out, not embedded (pulled forward from Phase 16)      ~5 days
TASK-118  Drop embedded Python distribution + cold-start benchmark publish
          (pulled forward from Phase 16)                                              ~4 days
TASK-127  Plugin wire-contract compatibility audit                                    ~2 days
```

TASK-117 (AST analyzer migration) is **deliberately deferred** to true Phase 16 / v2.0 — see rationale at top of this Phase 17 entry and at the Phase 16 status note.

---

### Phase 17c — v0.10: Plugin ecosystem polish

**Estimate:** ~14 solo days with 25% buffer, ~4 weeks at 70% capacity.

**Sequencing rationale:** Phase 17b may shift the plugin NDJSON contract subtly; doing plugin docs/examples before v0.9 ships means rewriting them. After v0.9 the contract is stable and the documentation work is wasted-effort-free.

**Exit criteria:**

- [ ] [docs/plugins.md](../docs/plugins.md) rewritten for external authors — NDJSON wire contract with worked examples, plugin lifecycle, error handling, packaging, installation.
- [ ] At least 2 new reference plugins in non-Go languages (Python + Ruby or Node) under `examples/plugins/`; proves wire contract is language-agnostic.
- [ ] `fendix plugins list` / `fendix plugins install <git-url>` CLI subcommands shipped; local install only (no marketplace — that's Q3 of [docs/example_plan.md](../docs/example_plan.md)).
- [ ] CI smoke test: each reference plugin runs against a fixture in `make test`, asserts findings shape; guards wire-contract regressions.
- [ ] v0.10.0 tagged + release.yml run succeeds.

**Tasks:**
```
TASK-128  Plugin authoring docs — rewrite docs/plugins.md for external authors        ~3 days
TASK-129  2 new reference plugins in non-Go languages (Python + Ruby/Node)            ~3 days
TASK-130  fendix plugins list / install <git-url> CLI subcommands (new
          internal/pluginscmd/ package)                                               ~3 days
TASK-131  Plugin smoke test in CI — make test runs each reference plugin              ~2 days
```

---

### Phase 17d — v0.11: Real-world FP round 2 (post-launch data)

**Estimate:** ~19 solo days with 25% buffer, ~5 weeks at 70% capacity.

**Sequencing rationale:** This phase depends on real-world FP reports from launch traffic. Q0 launches in parallel with Phase 17a; by the time 17a–17c ship, you have ~4–6 months of real user feedback. The second pass of FP tuning is informed by *actual* user pain, not synthetic juice-shop fixtures.

**Exit criteria:**

- [ ] Every user-reported FP filed against v0.8–v0.10 is triaged in `tasks/FP_USER_TICKETS.md`; clustered by pattern; top 5–10 categories selected for fix.
- [ ] Targeted correlator fixes shipped for the top 5–10 FP categories.
- [ ] One more reachability pattern added, chosen from real ticket data (likely XXE, deserialization, or path-traversal — not predetermined).
- [ ] Suppression UX iterated based on how users actually use TASK-124's one-click snippets.
- [ ] Benchmark numbers refreshed in [docs/benchmarks.md](../docs/benchmarks.md) on v0.11.
- [ ] v0.11.0 tagged + release.yml run succeeds.

**Tasks:**
```
TASK-132  Real-world FP triage — catalog + cluster every FP filed against v0.8–v0.10  ~3 days
TASK-133  Targeted correlator fixes for top 5–10 FP categories                        ~5 days
TASK-134  One more reachability pattern, data-driven from TASK-132 results            ~4 days
TASK-135  Suppression UX iteration based on TASK-124 usage data                       ~2 days
TASK-136  Benchmark refresh on v0.11                                                  ~1 day
```

---

## Cross-cutting (apply during all of Phase 10-13)

1. **End-to-end tests over unit tests.** The `--save-baseline` bug had a passing unit test. Every CLI flag needs an e2e test that runs the binary and asserts the externally-observable effect. Add `tests/e2e/` with table-driven Go tests that shell out to the built binary.

2. **Vulnerable-app test corpus in CI.** Stand up juice-shop in a CI step and assert fendix finds a fixed list of known issues. Single best regression guard.

3. **Rule registry as a first-class concept.** Central registry (id, title, category, severity, CWE, fix-guidance) loaded at startup, referenced everywhere — makes SARIF correct, ignore rules cleaner, and "what does fendix detect" doc auto-generatable.

4. **Don't grow scope before fixing wiring.** Architecture is good. Resist new check types until Phase 10 is done — half-wired flags are worse than missing features.

---

## Backlog (Future Phases)

Items deferred from current scope. Revisit after Phase 13.

```
BACKLOG-001  Web dashboard (React + embedded Go server)
BACKLOG-002  gRPC mode for Python engine (replace subprocess IPC)
BACKLOG-003  Plugin system for custom checks
BACKLOG-004  GraphQL API scanning support
BACKLOG-005  gRPC API scanning support
BACKLOG-006  Authenticated crawling (OAuth flow support)
BACKLOG-007  Two-account IDOR automation
BACKLOG-008  Nuclei template compatibility layer
BACKLOG-009  VS Code extension
BACKLOG-010  SaaS hosted version
BACKLOG-011  Refresh-on-401: token-refresh RoundTripper that traps 401, POSTs refresh-token to a configured URL, retries the original request with the new access token; needs single-flight to coalesce concurrent refreshes. Out of scope for v0.5 (TASK-096 deferred this) — original FENDIX_CLAUDE_CODE.md spec doesn't require it; the Phase 12 mention was forward-looking. Revisit when a real-world target needs it.
BACKLOG-012  GraphQL API scanning: introspection-based discovery, alias-based query depth attacks, batched-query DoS, missing field-level auth. Closes a credibility gap with Burp/Nuclei. Promote to a phase task once the v1.x wedge is established.
BACKLOG-013  VS Code extension: surface findings inline in the editor pre-CI; cheaper to fix while writing. Needs the plugin/IPC contract (Phase 15) before this is clean.
BACKLOG-014  fendix server: web dashboard for trend reporting (severity over time, MTTR, regression alerts). Read-only over committed JSON reports — explicitly NOT multi-tenant SaaS, NOT a SOC2 dashboard. Trend-tracking only. Promote when ≥3 customers ask for it.
BACKLOG-015  SOURCE_DATE_EPOCH-reproducible builds: every release byte-identical from git. Pairs with cosign for an end-to-end audit story. Cheap once the cosign pipeline (TASK-099) is fully ramped.
BACKLOG-016  fendix-bench standalone benchmark CLI: lets users reproduce the README benchmark numbers locally and against their own targets. Strong proof-point for AppSec engineers evaluating the tool.
BACKLOG-017  Strategic distractions explicitly to NOT build (decision log): AI-driven triage / LLM fix suggestions [**partially superseded by ADR-008 (2026-05-11)**: read-only AI explanation + fix-as-text permitted in the cloud backend; auto-PR / auto-merge / LLM calls from the OSS engine remain permanently forbidden — see `docs/adr/ADR-008-readonly-ai.md`], compliance dashboards (SOC2/ISO 27001 mappings), container/infra scanning (Trivy/Aikido own this), CSPM / cloud config (Wiz/Aikido), mobile app scanning, Burp-style interactive proxy, multi-tenant SaaS with SSO/RBAC. See `tasks/MEMORY.md` "Strategic Session 2026-04-30" for the rationale on each.
```
