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

**Phase:** 4 — Orchestration & Correlation (next)
**Overall progress:** Phases 0–3 complete (3/9 phases done)
**Last updated:** 2026-03-16

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

### In progress
*(none)*

### Blocked
*(none)*

---

## Last Session Summary

**Date:** 2026-03-16
**Session goal:** Complete Phase 3 — Python Engine (all 10 tasks)
**Accomplished:**
- engine.py enhanced with full error handling: per-analyzer exception isolation (crash in one check → others continue), verbose logging to stderr (never stdout), all 5 check types dispatched (secrets, auth, semgrep, injection/ast, deps), invalid JSON input handled with exit code 2 (8 tests)
- Secrets analyzer: 7 pattern types (AWS Access Key ID AKIA..., AWS Secret Key, RSA/PEM private key header, generic API key/token, hardcoded password, JWT token 3-part, DB connection string with credentials), file walker skips .git/node_modules/vendor/__pycache__, 1MB file limit, evidence truncated, secrets values truncated for safe reporting (24 tests)
- OpenAPI spec parser: supports 2.0+3.x YAML+JSON; 4 auth checks: missing global security, HTTP/non-TLS server/scheme, per-endpoint no auth when global absent, explicit open endpoint (security:[]), HTTP Basic auth scheme; graceful error finding on parse failure (18 tests)
- Semgrep rules auth.yaml (4 rules): Flask @login_required, Django LoginRequiredMixin, FastAPI Depends(), jwt.decode with verify_signature:False
- Semgrep rules injection.yaml (3 rules): cursor.execute with % / f-string / join, subprocess shell=True / os.system, eval()/exec()
- Semgrep rules secrets.yaml (2 rules): hardcoded secret assignment, DB URL with embedded credentials
- Semgrep runner: subprocess integration with --json output, graceful fallback when semgrep not in PATH or times out, result-to-finding mapping (severity from metadata fendix_severity, confidence, category, CWE), evidence truncated to 200 chars (20 tests, all mocked)
- AST analyzer: Python stdlib ast module (os.system → CWE-78, eval/exec dynamic arg → CWE-95, subprocess shell=True → CWE-78, cursor.execute with BinOp/JoinedStr/Call → CWE-89); JS heuristics (eval, innerHTML=, document.write, SQL template literal); both skip minified JS lines >500 chars; safe forms not flagged (21 tests)
- Dependency CVE checker: parses requirements.txt (11-field known-vuln list for 10 PyPI packages) and package.json (4 npm packages); pip-audit primary / local list fallback for PyPI; npm audit primary / local list fallback for npm; pinned version comparison; unpinned → INFO finding; (32 tests)
- Performance benchmark: engine startup < 2s measured (3-run median), fixture scan timing for secrets/AST/combined scan (7 tests, all well under limits)
- Total: 202 Go + 130 Python = 332 tests passing

**Decisions made:**
- engine.py verbose logging goes to stderr only — stdout is reserved for clean Finding JSON and the done terminator
- Semgrep graceful degradation: if `semgrep` not in PATH, log warning to stderr and emit zero findings (never crash)
- AST analyzer: eval("literal") not flagged (safe); only dynamic eval() arguments trigger findings
- AST analyzer: cursor.execute("literal", (params,)) not flagged — only bare non-literal first arg
- DepsAnalyzer fallback: when pip-audit absent, compare pinned versions against local curated list; unpinned versions with known-vuln packages → INFO severity (not HIGH)
- SemgrepRunner._map_result returns None on malformed result (engine skips it); no crash
- pyyaml installed via pip install pyyaml --break-system-packages for python3.13 on this machine

**Files created/modified:**
- python/engine.py — enhanced: all 5 checks, per-analyzer error isolation, stderr logging, verbose to stderr
- python/analyzers/secrets.py — full implementation: 7 patterns, file walker, evidence truncation
- python/analyzers/spec_parser.py — full implementation: 2.0+3.x parser, 4 auth checks
- python/analyzers/semgrep_runner.py — full implementation: subprocess, JSON parsing, result mapping
- python/analyzers/ast_analyzer.py — full implementation: Python AST + JS heuristics
- python/analyzers/deps.py — full implementation: requirements.txt + package.json, pip-audit + local fallback
- python/rules/auth.yaml — NEW: 4 Semgrep auth rules
- python/rules/injection.yaml — NEW: 3 Semgrep injection rules
- python/rules/secrets.yaml — NEW: 2 Semgrep secrets rules
- python/tests/test_engine_contract.py — expanded from 2 to 8 tests
- python/tests/test_secrets.py — NEW: 24 tests
- python/tests/test_spec_parser.py — NEW: 18 tests
- python/tests/test_semgrep_runner.py — NEW: 20 tests
- python/tests/test_ast_analyzer.py — NEW: 21 tests
- python/tests/test_deps.py — NEW: 32 tests
- python/tests/test_performance.py — NEW: 7 benchmark tests
- python/tests/fixtures/secrets_target/ — NEW: config.py, server.js, clean.py (test data with intentional secrets)
- python/tests/fixtures/ast_target/ — NEW: dangerous.py, dangerous.js, clean.py (test data with intentional vulnerabilities)
- python/tests/fixtures/specs/ — NEW: 6 OpenAPI YAML fixtures (secure, no-global-auth, http-server, basic-auth, swagger2 variants)

**Next session should start with:**
- TASK-038: Implement subprocess spawner with stdin/stdout wiring (Phase 4 — Orchestration begins)

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
