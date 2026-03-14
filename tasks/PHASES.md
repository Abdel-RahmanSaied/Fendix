# Fendix — Task Planning Master

> This directory is the **source of truth** for all project work.
> Update it after every work session. Never let it go stale.

---

## Project Phases Overview

| Phase | Name | Status | Goal |
|---|---|---|---|
| 0 | Foundation | 🔲 Not Started | Project skeleton, models, CI |
| 1 | Passive Scanner | 🔲 Not Started | Headers, CORS, exposure checks |
| 2 | Auth Scanner | 🔲 Not Started | JWT, auth bypass detection |
| 3 | Python Engine | 🔲 Not Started | Secrets, Semgrep, spec parser |
| 4 | Orchestration | 🔲 Not Started | Hybrid scan, correlator |
| 5 | Active Scanner | 🔲 Not Started | Injection probes (opt-in) |
| 6 | Reporting | 🔲 Not Started | HTML, SARIF, baseline diff |
| 7 | Distribution | 🔲 Not Started | Build, Docker, install script |
| 8 | Documentation | 🔲 Not Started | README, ADRs, contributing guide |
| 9 | Hardening | 🔲 Not Started | Perf, edge cases, security review |

Status values: 🔲 Not Started | 🔄 In Progress | ✅ Complete | ⏸ Blocked

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

## Backlog (Future Phases)

Items deferred from current scope. Revisit after Phase 9.

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
```
