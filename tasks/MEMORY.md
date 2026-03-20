# Fendix — Project Memory

> **Read this file first at the start of every new session.**
> This is the single source of truth for project state.
> Update the "Current State" and "Last Session" sections at the end of every session.

---

## Project Identity

| Field | Value |
|---|---|
| **Project name** | Fendix |
| **Type** | Hybrid API & code security scanner |
| **Tagline** | Find vulnerabilities before attackers do |
| **Repository** | github.com/yourusername/fendix |
| **Current version** | 0.0.0 (pre-release) |
| **License** | MIT |
| **Started** | [DATE] |

---

## What Fendix Is

Fendix is a developer-first security scanner with two engines that work together:

**Go layer (black-box):** Sends real HTTP requests to a live API and detects vulnerabilities by observing responses. Covers: missing auth, JWT bypass, CORS misconfiguration, security headers, sensitive data exposure, rate limiting, and injection attacks (active mode only).

**Python layer (white-box):** Analyzes source code and OpenAPI specs without making any network requests. Covers: hardcoded secrets, missing auth decorators, SQL injection patterns, dependency vulnerabilities, and any check expressible as a Semgrep rule.

**Hybrid mode:** Both engines run together. A correlator cross-references their findings — when both engines agree on a vulnerability, it becomes a `correlated` finding with HIGH confidence. This is the core differentiator.

---

## Architecture Decisions (final, do not re-debate)

| Decision | Choice | Reason |
|---|---|---|
| Black-box engine language | Go | Performance, concurrency, single binary distribution |
| White-box engine language | Python | Best security tooling ecosystem (Semgrep, Bandit, detect-secrets) |
| IPC between Go and Python | Newline-delimited JSON over stdin/stdout | Simple, debuggable, no infrastructure required |
| CLI framework (Go) | cobra | Industry standard, excellent help generation |
| HTTP client (Go) | go-resty/resty | Retry logic, timeout handling, clean API |
| Static analysis (Python) | Semgrep + custom rules | Most powerful, extensible rule system |
| Secrets detection (Python) | detect-secrets + custom regex | Two-layer: known patterns + domain-specific |
| Output formats | JSON, HTML (self-contained), SARIF 2.1.0 | JSON for machines, HTML for humans, SARIF for CI/CD |
| Active probes default | OFF (`--enable-active` required) | Safety — never damage target without explicit consent |
| Auth credentials in reports | Always masked as [REDACTED] | Security — reports are shareable |

**ADR documents:** `docs/adr/ADR-001` through `ADR-00N` in repository.

---

## Repository Structure

```
fendix/
├── go/                          # Go layer — CLI, HTTP scanner, orchestrator
│   ├── cmd/fendix/main.go       # Entrypoint
│   ├── internal/
│   │   ├── scanner/             # Individual check implementations
│   │   │   ├── crawler.go       # Endpoint discovery
│   │   │   ├── headers.go       # Security headers check
│   │   │   ├── cors.go          # CORS misconfiguration check
│   │   │   ├── auth.go          # Authentication checks
│   │   │   ├── injection.go     # Active injection probes (--enable-active)
│   │   │   ├── ratelimit.go     # Rate limiting detection
│   │   │   └── exposure.go      # Sensitive data in responses
│   │   ├── engine/
│   │   │   ├── orchestrator.go  # Main scan coordinator, spawns Python
│   │   │   └── correlator.go    # Cross-correlates black+white findings
│   │   ├── models/
│   │   │   ├── finding.go       # Finding, Severity, Confidence, Source types
│   │   │   ├── config.go        # ScanConfig, AuthContext
│   │   │   └── scoring.go       # Severity scoring logic
│   │   └── reporters/
│   │       ├── json.go          # JSON report renderer
│   │       ├── html.go          # Self-contained HTML report
│   │       └── sarif.go         # SARIF 2.1.0 renderer
│   ├── go.mod
│   └── go.sum
│
├── python/                      # Python layer — static analysis engine
│   ├── engine.py                # Entrypoint: reads stdin ScanRequest, streams Findings
│   ├── analyzers/
│   │   ├── spec_parser.py       # OpenAPI 2.0/3.x parser + auth checks
│   │   ├── secrets.py           # Hardcoded secrets detection (7 pattern types)
│   │   ├── semgrep_runner.py    # Semgrep integration + result mapping
│   │   ├── ast_analyzer.py      # Python/JS AST-based analysis
│   │   └── deps.py              # Dependency CVE checking
│   ├── rules/                   # Custom Semgrep YAML rules
│   │   ├── auth.yaml            # Missing auth decorator rules
│   │   ├── injection.yaml       # SQL/CMD injection pattern rules
│   │   └── secrets.yaml         # Hardcoded secret rules
│   ├── tests/
│   │   └── fixtures/            # Sample code for testing analyzers
│   └── requirements.txt
│
├── tasks/                       # Project planning (this directory)
│   ├── PHASES.md                # Master phase plan with all tasks
│   ├── CURRENT_SPRINT.md        # Active work items
│   └── DONE.md                  # Completed tasks log
│
├── docs/
│   ├── adr/                     # Architecture Decision Records
│   └── checks/                  # One page per check explaining detection logic
│
├── scripts/
│   ├── build.sh                 # Build Go binary + bundle Python engine
│   └── install.sh               # curl-pipe installer
│
├── .github/
│   └── workflows/
│       ├── ci.yml               # Build + test on every push
│       └── release.yml          # Tag → GitHub Release with binaries
│
├── Makefile                     # make build, test, lint, clean
├── Dockerfile                   # Multi-stage build
├── .fendix-ignore.example       # Suppression file template
├── MEMORY.md                    # This file
├── README.md                    # User-facing documentation
├── CONTRIBUTING.md              # Contributor guide
└── CHANGELOG.md                 # Release history
```

---

## Data Contract (IPC between Go and Python)

**Never change this without updating both sides.**

### ScanRequest (Go → Python stdin, single JSON line)
```json
{
  "mode": "whitebox",
  "spec": "./openapi.yaml",
  "code_path": "./src/",
  "language": "python",
  "checks": ["secrets", "auth", "injection", "semgrep", "deps"],
  "verbose": false
}
```

### Finding (Python → Go stdout, one JSON object per line)
```json
{
  "id": "SEC-001",
  "title": "Hardcoded API key detected",
  "severity": "CRITICAL",
  "source": "whitebox",
  "category": "secrets",
  "endpoint": "src/config.py:14",
  "evidence": "API_KEY = 'sk-live-abc...' [truncated]",
  "fix": "Move to environment variable. Rotate the exposed key immediately.",
  "references": ["CWE-798"],
  "confidence": "HIGH",
  "line": "src/config.py:14"
}
```

### Stream terminator (Python → Go stdout, final line)
```json
{"done": true, "total": 12}
```

**Severity values:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
**Confidence values:** `HIGH`, `MEDIUM`, `LOW`
**Source values:** `blackbox`, `whitebox`, `correlated`

---

## CLI Interface

```bash
# Commands
fendix scan      # Run a scan
fendix report    # Re-render saved findings
fendix verify    # Re-run single finding by ID
fendix version   # Print version

# Key scan flags
--url            # Target API base URL
--spec           # OpenAPI/Swagger spec path
--code           # Source code directory path
--auth           # Auth header e.g. "Bearer token123"
--auth-type      # bearer | apikey | basic | cookie
--auth-header    # Custom auth header name
--output         # Output file path
--format         # json | html | sarif (default: json)
--fail-on        # CRITICAL | HIGH | MEDIUM (exit 1 if found)
--baseline       # Previous findings JSON for diff
--save-baseline  # Save findings to path
--enable-active  # Enable injection probes (default: false)
--workers        # Concurrent HTTP workers (default: 10)
--timeout        # HTTP timeout seconds (default: 10)
--delay          # Ms between requests (default: 100)
--ignore         # Path to .fendix-ignore file
--verbose        # Print all requests and raw findings

# Exit codes
0  — scan complete, no findings at --fail-on threshold
1  — scan complete, findings found at threshold
2  — scan error
```

---

## Severity Scoring Model

```
Score = ImpactBase[category] × ConfidenceMult[confidence] × SourceMult[source]

CRITICAL  ≥ 9.0
HIGH      ≥ 7.0
MEDIUM    ≥ 4.0
LOW       ≥ 1.0
INFO      < 1.0

ImpactBase:
  auth_bypass    = 10.0
  injection      = 9.5
  secrets        = 9.0
  idor           = 8.5
  data_exposure  = 7.0
  cors           = 6.5
  headers        = 4.0
  info_disclosure= 2.0

ConfidenceMult:
  HIGH   = 1.0
  MEDIUM = 0.75
  LOW    = 0.5

SourceMult:
  correlated = 1.1
  blackbox   = 1.0
  whitebox   = 0.9
```

---

## Go Dependencies

```
github.com/spf13/cobra          v1.8.0   — CLI framework
github.com/go-resty/resty/v2    v2.11.0  — HTTP client
github.com/golang-jwt/jwt/v5    v5.2.0   — JWT generation for test tokens
github.com/fatih/color          v1.16.0  — Terminal color output
```

## Python Dependencies

```
semgrep>=1.45.0               — Static analysis engine
bandit>=1.7.5                 — Python security linter
pyyaml>=6.0                   — YAML parsing (OpenAPI specs)
openapi-spec-validator>=0.7.1 — OpenAPI validation
detect-secrets>=1.4.0         — Secrets detection
packaging>=23.0               — Dependency version comparison
```

---

## Engineering Standards (non-negotiable)

**Go:**
- `gofmt` + `golint` clean at all times
- All errors wrapped with context: `fmt.Errorf("doing X: %w", err)`
- Context propagation on all network calls
- Table-driven tests with `t.Run`
- Structured logging with `log/slog`
- No global mutable state
- Interfaces for all mockable dependencies

**Python:**
- Type hints on all function signatures
- Docstrings on all public classes and functions
- `ruff` + `black` formatting
- `pytest` with fixtures
- Context managers for all file I/O

**Git:**
- Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
- No broken builds ever — CI must pass before merge

**Safety:**
- Active probes NEVER run without `--enable-active`
- Auth credentials ALWAYS masked as `[REDACTED]` in output
- Python engine crash NEVER crashes Go binary

---

## Current Project State

**Phase:** 5 — Active Scanner ✅ Complete
**Overall progress:** Phases 0–5 complete (6/9 phases done)
**Last updated:** 2026-03-20

### Completed tasks
- TASK-001: Initialize Go module and directory structure
- TASK-002: Initialize Python package structure
- TASK-003: Implement Finding model (Go) with JSON serialization
- TASK-004: Implement ScanConfig model (Go)
- TASK-005: Implement severity scoring with table-driven tests
- TASK-006: Wire cobra CLI skeleton + version command
- TASK-007: GitHub Actions CI workflow
- TASK-008: Write Makefile
- TASK-009: ADR-001: Go+Python hybrid architecture
- TASK-010: ADR-002: Newline-delimited JSON IPC contract
- TASK-011: Implement endpoint crawler (spec parser + JS + brute-force)
- TASK-012: Implement headers check with mock server tests
- TASK-013: Implement CORS check with 4 scenario tests
- TASK-014: Implement exposure check with regex pattern tests
- TASK-015: Implement rate limit detection
- TASK-016: Implement worker pool concurrency model
- TASK-017: Implement JSON reporter with scan metadata
- TASK-018: Implement HTML reporter (self-contained, color-coded)
- TASK-019: Wire all passive checks into orchestrator (Go-only path)
- TASK-020: Integration test: scan mock server, assert finding counts
- TASK-021: Implement AuthContext model and multi-source resolution
- TASK-022: Implement unauthenticated access check
- TASK-023: Implement JWT validation bypass checks (3 scenarios)
- TASK-024: Implement IDOR two-account check
- TASK-025: Implement credential masking in all reporters
- TASK-026: Implement ~/.fendix/profiles/ config system
- TASK-027: Tests: auth checks against mock JWT server
- TASK-028: engine.py entrypoint with full IPC contract, error handling, all 5 checks, stderr logging
- TASK-029: Secrets analyzer — 7 pattern types (AWS key ID, AWS secret, private key PEM, generic API key, hardcoded password, JWT token, DB connection string)
- TASK-030: OpenAPI spec parser — 2.0 + 3.x, 4 auth checks (no global security, HTTP server/scheme, no-auth endpoint, basic auth scheme)
- TASK-031: Semgrep rules auth.yaml — 4 rules (Flask login_required, Django LoginRequiredMixin, FastAPI Depends, jwt.decode no-verify)
- TASK-032: Semgrep rules injection.yaml — 3 rules (SQL % formatting, subprocess shell=True, eval/exec)
- TASK-033: Semgrep rules secrets.yaml — 2 rules (hardcoded assignment, DB URL with credentials)
- TASK-034: Semgrep runner — subprocess integration, JSON output mapping, graceful fallback when semgrep not installed
- TASK-035: AST analyzer — Python stdlib ast module (os.system, eval/exec dynamic, subprocess shell=True, cursor.execute SQL injection) + JS heuristics (eval, innerHTML, document.write, SQL template literal)
- TASK-036: Dependency CVE checker — requirements.txt + package.json parsing, pip-audit primary with local known-vuln list fallback (10 PyPI vulns, 4 npm vulns), npm audit integration
- TASK-037: Performance benchmark — engine startup < 2s measured (3-run median), fixture scan timing tests
- TASK-038: Subprocess spawner — Go spawns Python engine, sends ScanRequest via stdin, reads findings from stdout, captures stderr diagnostics
- TASK-039: Streaming Finding reader — bufio.Scanner-based JSON line reader with malformed line skip, missing field validation, whitebox source default
- TASK-040: Correlator — endpoint normalization (URL→path, file:line→file), fuzzy endpoint matching (path segment overlap), category mapping (auth↔auth_bypass, secrets↔data_exposure), severity escalation, reference deduplication
- TASK-041: Sequential ID assignment — verified existing (SEC-001, SEC-002, ...) in orchestrator
- TASK-042: .fendix-ignore suppression parser — YAML format, suppress by ID/endpoint/category, glob patterns, expiry dates (until field)
- TASK-043: Baseline diff — compare by title+endpoint+category (ID-independent), supports JSONReport and raw Finding array formats, --save-baseline saves current findings
- TASK-044: --fail-on exit code logic — verified existing in orchestrator
- TASK-045: End-to-end integration test — hybrid scan with mock Python engine, ignore rules integration, baseline diff integration (3 new integration tests)
- TASK-046: Safe probe framework — ProbeAuditLog, ProbeRecord, PrintDisclaimer, --enable-active gate, CheckInjection wired into orchestrator
- TASK-047: Time-based SQLi detection — MySQL SLEEP, Postgres pg_sleep, MSSQL WAITFOR; 3-sample median baseline; baseline+4s threshold; confirmation probe for HIGH confidence
- TASK-048: CMDi canary detection — safe echo payload, canary reflection detection in response body, CRITICAL severity
- TASK-049: CRLF header injection — %0d%0a Set-Cookie injection, cookie reflection check, HIGH severity
- TASK-050: Per-endpoint probe rate limiter — MaxProbesPerEndpoint=20, enforced via audit log count before every probe
- TASK-051: Integration tests for active probes — vulnerable mock server (CMDi+CRLF), safe server, multi-param, auth propagation, context cancellation (22 new tests)

### In progress
*(none)*

### Blocked
*(none)*

---

## Last Session Summary

**Date:** 2026-03-20
**Session goal:** Complete Phase 5 — Active Scanner (all 6 tasks)
**Accomplished:**
- Safe probe framework: ProbeAuditLog with mutex-protected concurrent access, ProbeRecord capturing timestamp/endpoint/type/payload/param/method/status/duration/finding; NewProbeAuditLogWithWriter for testing; Record() writes structured [PROBE] log lines to stderr; Count() per-endpoint tracking
- Legal disclaimer: PrintDisclaimer() prints warning to stderr when --enable-active used
- --enable-active gate: CheckInjection returns nil immediately when EnableActive=false; orchestrator only adds CheckInjection to check list when EnableActive=true
- Time-based SQLi detection: probeSQLi() sends 3 DB-specific payloads (MySQL SLEEP, Postgres pg_sleep, MSSQL WAITFOR DELAY); measures 3-sample median baseline response time; threshold = baseline + 4 seconds; runs confirmation probe — HIGH confidence if both delayed, MEDIUM if single; breaks on first DB type match per parameter
- CMDi canary detection: probeCMDi() sends safe echo payload ("; echo fendix_canary_PROBE"); reads up to 1MB response body; checks for canary prefix in response; CRITICAL severity, HIGH confidence
- CRLF header injection: probeCRLF() injects %0d%0aSet-Cookie:%20fendix=injected as raw (not double-encoded) query value; checks resp.Cookies() for fendix=injected; HIGH severity
- Per-endpoint probe rate limiter: MaxProbesPerEndpoint=20 constant; checked via auditLog.Count() before every probe call; warning logged when limit reached
- Orchestrator wiring: CheckInjection added to check list when cfg.EnableActive is true; PrintDisclaimer called before scan starts
- URL encoding: buildProbeURL uses url.QueryEscape for param/payload (except CRLF which uses raw %0d%0a); addAuth helper propagates auth headers to probe requests
- Integration tests: vulnerable mock server (CMDi + CRLF detection), safe server (no false positives), multi-param (3 CMDi findings), auth propagation verification, context cancellation graceful handling
- Total: 201 Go + 130 Python = 331 tests passing

**Decisions made:**
- Probe payloads are URL-encoded via url.QueryEscape in query params (except CRLF which needs raw %0d%0a to test real injection)
- CRLF payload uses %20 instead of space to keep URL valid: %0d%0aSet-Cookie:%20fendix=injected
- MaxProbesPerEndpoint = 20 (prevents excessive probing of a single endpoint)
- When no params are known for an endpoint, defaults to testing "id" parameter
- SQLi confirmation: second probe sent only if first exceeds threshold; confidence escalated to HIGH only if both probes delayed
- SQLi breaks on first matching DB type per parameter (no need to test all 3 if MySQL SLEEP already confirmed)
- addAuth helper centralizes auth header logic for all probe types (bearer/apikey/basic/cookie)

**Files created/modified:**
- go/internal/scanner/injection.go — NEW: CheckInjection, CheckInjectionWithAudit, ProbeAuditLog, ProbeRecord, probeSQLi, probeCMDi, probeCRLF, buildProbeURL, addAuth, measureBaseline, PrintDisclaimer, sqliPayloads, medianDuration
- go/internal/scanner/injection_test.go — NEW: 22 tests (unit + integration: gate check, audit log, SQLi probes, CMDi canary, CRLF detection, URL building, auth propagation, concurrent access, vulnerable server, safe server, multi-param, context cancellation)
- go/internal/engine/orchestrator.go — MODIFIED: added CheckInjection + PrintDisclaimer when EnableActive=true

**Next session should start with:**
- TASK-052: Finalize JSON reporter with full metadata schema (Phase 6 — Reporting begins)

**Open questions:**
- None

---

## How to Resume Work

At the start of a new session:

1. Read this file (`MEMORY.md`) completely
2. Read `tasks/CURRENT_SPRINT.md` to see active tasks
3. Check `tasks/PHASES.md` for overall phase status
4. Run `make build && make test` to confirm current state compiles and passes
5. Pick up from "Next session should start with" above
6. At end of session: update "Last Session Summary" and "Current Project State" in this file

---

## Key Constraints (never violate)

1. `--enable-active` must be explicitly passed for any active probe
2. Every HTTP request respects `--delay` between calls
3. Auth credentials never appear in report output — always `[REDACTED]`
4. Python engine independently runnable without Go binary
5. All findings are deterministic — same input = same output
6. HTML report is a single self-contained file — no external dependencies
7. SARIF output must validate against SARIF 2.1.0 schema
8. Go binary must compile with `go build ./...` at all times
9. `python -m pytest` must pass at all times
10. `go test ./...` must pass at all times
