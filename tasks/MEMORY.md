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

**Phase:** 2 — Auth Scanner
**Overall progress:** 100% (Phase 2 complete)
**Last updated:** 2026-03-15

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

### In progress
*(none)*

### Blocked
*(none)*

---

## Last Session Summary

**Date:** 2026-03-15
**Session goal:** Complete Phase 2 — Auth Scanner
**Accomplished:**
- AuthContext model with auth type constants (bearer, apikey, basic, cookie), auto-detection from credential value, and multi-source resolution (CLI flag → env var → config profile) (30 tests)
- Unauthenticated access check: sends request without auth, flags CRITICAL if endpoint returns 200 instead of 401/403 (3 tests)
- JWT validation bypass checks covering 3 scenarios: malformed JWT, expired JWT (HS256-signed with exp in past), alg:none algorithm confusion — all CRITICAL severity (8 tests)
- IDOR two-account check: sends same request with two different user credentials, detects identical responses as broken object-level authorization — HIGH severity (5 tests)
- Credential masking/sanitization: SanitizeFindings function replaces auth values in evidence/fix/title with [REDACTED], strips both full "Bearer <token>" and bare token forms (7 tests)
- Profile config system: ~/.fendix/profiles/<name>.yaml YAML files for saved auth credentials, ProfileLoader function integrates with ResolveAuth (8 tests)
- Comprehensive integration tests with realistic JWT-validating mock server: decodes JWT headers, verifies HS256 signatures, checks exp claims, rejects alg:none, tests partial-security scenarios (5 integration tests)
- Added --auth-user2 and --profile CLI flags, wired CheckAuth and CheckIDOR into orchestrator
- 202 Go tests + 2 Python tests = 204 total, all passing

**Decisions made:**
- Auth resolution priority: CLI --auth flag > FENDIX_AUTH env var > ~/.fendix/profiles/ config file
- Auth type auto-detection: "Bearer ..." → bearer, "Basic ..." → basic, key=value → cookie, else → bearer
- Redacted() always returns "[REDACTED]" (no partial reveal — security constraint)
- ApplyToRequest method on AuthContext encapsulates nil-safe header setting
- IDOR check compares response bodies byte-for-byte; empty responses do not trigger findings
- JWT bypass checks only run when isJWTAuth detects 3-part dot-separated token
- SanitizeFindings called in orchestrator before rendering (defense-in-depth)
- AuthUser2 field added to ScanConfig for IDOR two-account testing
- ResolveAuth accepts a profileLoader callback for extensible auth source chain
- JWT test tokens built with crypto/hmac + encoding/base64 (no external JWT library needed for test token generation)

**Files created/modified:**
- go/internal/models/auth.go — NEW: auth type constants, DetectAuthType, ResolveAuth, NormalizeAuth, Redacted, ApplyToRequest
- go/internal/models/auth_test.go — NEW: 30 tests (detect, normalize, resolve, redact, apply)
- go/internal/models/profiles.go — NEW: LoadProfile, LoadProfileFrom, ProfileLoader, ProfilesDir
- go/internal/models/profiles_test.go — NEW: 8 tests (valid, apikey, missing, empty, invalid, minimal, integration, override)
- go/internal/models/config.go — added AuthUser2 field to ScanConfig
- go/internal/scanner/auth.go — NEW: CheckAuth, unauthenticated check, JWT bypass checks (malformed, expired, alg:none)
- go/internal/scanner/auth_test.go — NEW: 14 tests (vulnerable/secure for each check type, non-JWT skip, full vulnerability scan)
- go/internal/scanner/auth_integration_test.go — NEW: 5 integration tests with realistic JWT-validating mock server
- go/internal/scanner/idor.go — NEW: CheckIDOR two-account check
- go/internal/scanner/idor_test.go — NEW: 5 tests (vulnerable, secure, no-user2, no-auth, empty-response)
- go/internal/reporters/sanitize.go — NEW: SanitizeFindings credential masking
- go/internal/reporters/sanitize_test.go — NEW: 7 tests (redact auth, bare token, nil, multiple, immutability, empty, title)
- go/internal/engine/orchestrator.go — wired CheckAuth, CheckIDOR, SanitizeFindings
- go/cmd/fendix/main.go — added --auth-user2, --profile flags, wired ResolveAuth + ProfileLoader

**Next session should start with:**
- TASK-028: Implement engine.py entrypoint and IPC contract (Phase 3 — Python Engine begins)

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
