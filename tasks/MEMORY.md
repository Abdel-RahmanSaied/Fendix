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
| **Current version** | 0.1.0 |
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

**Phase:** 11 — P1 Coverage Parity (v0.3 + v0.4) — 🔄 In Progress. TASK-085 + TASK-086 ✅ done (v0.3 batch complete); TASK-087 + TASK-088 ✅ done (v0.4 batch 2/5). Phase 10 ✅ Complete (v0.2.0 tagged + pushed 2026-04-29).
**Overall progress:** Phases 0-10 complete; Phase 11 4/7 tasks done; v0.1.0 + v0.2.0 released; v0.3.0 not yet cut (v0.3 batch ready to ship; v0.4 batch 2/5 tasks done)
**Last updated:** 2026-04-29

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
- TASK-052: Finalize JSON reporter — added Mode, EndpointsCount, ActiveProbes, ChecksRun to ScanMetadata; added SourceCounts (blackbox/whitebox/correlated) to JSONReport; orchestrator populates all new fields
- TASK-053: Finalize HTML reporter — JavaScript sorting by severity/endpoint/source; Expand All/Collapse All buttons; data-severity/data-source attributes for sort; finding ID + category displayed; enhanced print CSS (force body display, hide toolbar, readable colors)
- TASK-054: Implement SARIF 2.1.0 reporter — full SARIF 2.1.0 output with tool/driver/rules/results; severity→level mapping (CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note); physical locations for whitebox, logical locations for blackbox; CWE→MITRE URL mapping; rule properties with category/confidence/tags
- TASK-055: Validate SARIF output against official schema — comprehensive structural validation test covering all required SARIF 2.1.0 fields, level values, rule/result index consistency, invocation metadata
- TASK-056: Implement fendix report re-render command — reads JSONReport from file, re-renders to HTML/SARIF/JSON; --input/--format/--output flags; error handling for missing input and invalid JSON
- TASK-057: Add GitHub Actions example workflow to docs — docs/ci-cd-integration.md with SARIF upload, baseline diff, live API scan, active probing, exit code reference, suppression examples
- TASK-058: Go embed of Python engine — //go:embed all:engine directive in go/internal/embedded/; Makefile embed-engine target copies python/ into embed dir; HasEngine/ExtractEngine/EngineDir functions; .gitkeep placeholder for dev builds; .gitignore excludes build artifacts
- TASK-059: Python extraction on first run — EnsureEngine() resolves engine dir (explicit → embedded extraction → local fallback); version stamp for re-extraction on upgrade; dev builds skip re-extraction; NewOrchestrator accepts version param; 8 extraction unit tests
- TASK-060: Python availability check with graceful fallback — CheckPython() verifies python3 is available and captures version; orchestrator skips whitebox if Python missing with clear user message; PythonRequiredMessage() user-facing guidance
- TASK-061: GitHub Actions release workflow — .github/workflows/release.yml builds for linux/amd64, darwin/amd64, darwin/arm64; sha256 checksums; softprops/action-gh-release publishes; CI updated with embed-engine step
- TASK-062: Dockerfile (multi-stage) — go-builder stage with Alpine; python:3.11-slim runtime; embedded engine; non-root user; .dockerignore
- TASK-063: install.sh curl-pipe installer — platform detection (linux/darwin, amd64/arm64); GitHub Releases download; sha256 checksum verification; sudo fallback; scripts/build.sh for local builds
- TASK-064: Homebrew formula — Formula/fendix.rb with platform-specific URLs; python@3.11 dependency; caveats with quick start
- TASK-065: README.md — all 10 required sections (hero, quick start, installation, usage, CLI flags, output formats, CI/CD integration, architecture, how to add a check, license + responsible use); already complete from prior session
- TASK-066: CONTRIBUTING.md — development setup, how to add black-box/white-box/Semgrep checks, coding standards (Go + Python), IPC data contract, safety rules, PR process with checklist
- TASK-067: docs/checks/ — 11 check documentation pages (headers, cors, auth, exposure, ratelimit, injection, secrets, semgrep, spec-parser, ast-analyzer, deps); each page covers what it detects, how it works, example finding, references
- TASK-068: ADRs — 4 new ADRs (ADR-003 severity scoring, ADR-004 active probe safety, ADR-005 embedded engine distribution, ADR-006 report formats); total 6 ADRs covering all major architectural decisions
- TASK-069: CHANGELOG.md — initial changelog with all features for unreleased version; follows Keep a Changelog format
- TASK-070: Audit all godoc comments — verified all 92 exported Go symbols have godoc comments; 0 missing
- TASK-071: Audit all docstrings — found 1 missing docstring (emit_finding in engine.py); fixed; all 16 public Python symbols now documented
- TASK-072: Performance benchmark suite — Go benchmarks for readFindings (10/100/1000 findings), Correlate (20/100/500), normalizeEndpoint, CalculateSeverity, SeverityRank, RenderJSON/HTML/SARIF (10/100/1000 findings); all benchmarks with -benchmem
- TASK-073: Fuzz test Finding JSON parser — Go native fuzzing (FuzzReadFindings + FuzzNormalizeEndpoint); 14 seed corpus entries; 362k+ executions with no panics found; covers null bytes, unicode, truncated JSON, nested objects, extremely long lines
- TASK-074: Fuzz test OpenAPI spec parser — Python hypothesis-based property testing (8 tests); found and fixed 3 real bugs: _parse_file returning None on empty YAML, get_endpoints crashing on non-dict paths, _security_schemes crashing on non-dict components; 200 examples per test
- TASK-075: Self-audit — ran Python whitebox engine against own codebase; 17 findings, all from test fixtures (intentional test data); 0 production code vulnerabilities; automated self-audit test verifying no production secrets
- TASK-076: Resilience testing — 12 scanner resilience tests (garbage body, empty body, huge body, non-UTF8, HTTP 500, server timeout, context cancellation, connection refused, invalid URLs, slow-drip response); 15 engine resilience tests (14 malformed stream variants + correlator edge cases); all pass without panics
- TASK-077: Memory profiling — TestMemory_LargeFindingStream (2000 findings: 4.5MB, 2.3KB/finding); TestMemory_LargeCorrelation (1000 findings: 15MB including logging, under 20MB budget); TestMemory_ReporterLargeOutput (1000 ID assignments: 14KB); BenchmarkMemory_ReadFindings2000 + BenchmarkMemory_Correlate1000
- TASK-078: Audit error messages — improved 7 user-facing error messages with actionable guidance: endpoint discovery, ignore file parsing, baseline saving, report rendering, --fail-on validation, format validation, Python engine failure

### In progress

Phase 11 — P1 Coverage Parity (v0.3 + v0.4). Not yet started; tracked in `tasks/CURRENT_SPRINT.md`.

### Completed tasks — Phase 10 (P0 Flag Wiring, v0.2) ✅

- TASK-079: Wire `--save-baseline` flag into `ScanConfig` — added `flags.GetString("save-baseline")` and `SaveBaselinePath` field assignment in `go/cmd/fendix/main.go`. Verified end-to-end: real httpbin.org scan writes a 7-finding baseline JSON. E2e regression `TestSaveBaseline_WritesFile`.
- TASK-080: Allow `--code`-only scans — reordered the no-endpoints guard at `orchestrator.go:61` to fire only when both endpoints AND code path are empty. Empty-endpoint black-box pool runs as a no-op (returns []). E2e regression `TestCodeOnlyScan_ProducesFindings`.
- TASK-081: Populate `Endpoint.Params` from spec params — added `extractParamsList()` (filters `in: query` / `in: path`, skips `$ref` and headers) and `mergeParams()` helpers; `fromSpec` layers URL-template + path-level + operation-level params. Body params deferred to TASK-086 per plan. 3 unit tests + e2e `TestActiveProbe_UsesSpecParam` (records every probe at target, asserts at least one hit `?host=`).
- TASK-082: Accept HTTP/HTTPS URL as `--spec` — refactored to `loadSpec` / `fetchSpec` with `http://`/`https://` prefix detection; format selected by URL suffix → Content-Type → first-byte sniff. 50 MB size cap; 4xx/5xx surface as errors. 3 unit tests + e2e `TestSpecURL_FetchedAndParsed`.
- TASK-083: SARIF dedup by check type — dedup now keys on stable `ruleKeyFor(f) = "fendix.<category>.<title-slug>"`. Added `slug()` helper. `Result.RuleID` and `Rule.ID` use the stable key; per-finding `SEC-NNN` stays in JSON output, not SARIF. New unit test `TestRenderSARIF_RulesDedupedByCheckType` (4 findings of 2 check types → 2 rules + 4 results). All existing SARIF tests still pass.
- TASK-084: Makefile + self-audit cwd bug — Makefile `test-python` target now runs `pytest python/tests/` from repo root (not `cd python/ && pytest`). Plus hardened `test_self_audit.py` with `REPO_ROOT = Path(__file__).resolve().parents[2]` and `cwd=` in subprocess calls — defensive against future cwd shifts. Verified 140/140 from repo root, `python/`, and via `make test`.

### Cross-cutting work this session

- **e2e test infrastructure**: created `go/internal/e2e/e2e_test.go` gated behind `//go:build e2e` so normal `go test ./...` skips it. Added `make e2e` target which builds via `make build` first (so the embedded Python engine is bundled). 4 regression tests cover TASK-079/080/081/082; TASK-083/084 covered by unit tests.
- This addresses the cross-cutting recommendation in the plan: every CLI flag should have a test that runs the binary and asserts observable effect. The `--save-baseline` bug had a passing unit test but a broken CLI — only an e2e test catches that class of bug.

### Phase 10 release — ✅ shipped 2026-04-29

- [x] CHANGELOG `[0.2.0] - 2026-04-29` entry (TASK-079..084 + e2e infra; SARIF rule-ID change flagged as breaking)
- [x] `make e2e` wired into `.github/workflows/ci.yml` as a third job depending on `go` + `python`
- [x] Real-world re-test against same fixtures as 2026-04-28: all 6 bugs verified gone
- [x] Commit `2ca82ce` ("feat: v0.2.0 — fix P0 CLI flag wiring (TASK-079..084)") pushed to `origin/main`
- [x] Annotated tag `v0.2.0` (object `acd2f32`) pushed to `origin` — `release.yml` triggered for linux/amd64, darwin/amd64, darwin/arm64

### Completed tasks — Phase 11 (P1 Coverage Parity, v0.3 + v0.4)

- TASK-085: Expanded secret patterns 7 → 15. Added `GITHUB_TOKEN` (`gh[opusr]_` prefix + 36 alnum, CRITICAL), `STRIPE_LIVE_KEY` (`sk_live_` + 20+ alnum, CRITICAL), `SLACK_TOKEN` (`xox[abprs]-` + 10+, HIGH), `GOOGLE_API_KEY` (`AIza` + exactly 35, HIGH), `ANTHROPIC_API_KEY` (`sk-ant-` + 20+, CRITICAL), `OPENAI_API_KEY` (`sk-(?:proj-|svcacct-)?` + 32+ alnum, CRITICAL — anti-overlap with Anthropic verified), `NPM_TOKEN` (`npm_` + 36, HIGH), `GCP_SERVICE_ACCOUNT` (`"type": "service_account"`, CRITICAL). Plus `.env`-only `ENV_SECRET` pattern in new `_ENV_PATTERNS` list, gated by `_is_env_file()`. Fixed dotfile-walker bug — `.env` files had `Path.suffix=""` and were silently skipped; `_walk` now also yields env-files by name. New fixtures: `provider_tokens.py`, `gcp_service_account.json`, `.env`. 10 new test methods (8 provider + 1 ENV + 1 anti-overlap). All 150 Python tests pass; 4/4 e2e pass; Go race-clean.
- TASK-086: Active scanner expansion. **Endpoint model**: extended with `Headers []string` and `BodyParams []string` (in addition to existing `Params []string` for query/path). **Crawler**: new `extractHeaderParamsList()` filters out standard auth headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Apikey`, `Api-Key`, `Proxy-Authorization`); new `extractBodyParamNames()` reads OAS 3 `requestBody.content."application/json".schema.properties` and Swagger 2 `parameters[in:body].schema.properties`; both skip `$ref` schemas (deref out of scope). Path-level + operation-level merging matches the existing `Params` flow. **Injection**: introduced `ProbeLocation` enum (`LocQuery`/`LocHeader`/`LocBody`); new `buildProbeRequest()` constructs HTTP requests for each location (body uses `Content-Type: application/json` with sibling fields filled with `"fendix"` placeholder so server validation doesn't reject before reaching vulnerable code; header values strip CR/LF since net/http rejects malformed headers); new `targetsForEndpoint()` enumerates (param, location) pairs (body only on POST/PUT/PATCH; falls back to single `("id", query)` for fully-bare endpoints); new `methodAcceptsBody()` helper. **SQLi expansion**: time-based DBs 3 → 5 (added SQLite `randomblob(99999999)`, Oracle `DBMS_PIPE.RECEIVE_MESSAGE('a',5)`); new `probeSQLiErrorBased()` (single `'"`-class payload, regex match against 5 DB-specific error signatures from sqlmap/OWASP; HIGH severity HIGH confidence on match); new `probeSQLiBoolean()` (true/false payload pair `' OR '1'='1` vs `' AND '1'='2`, finding on status flip OR length-delta > 5%, MEDIUM confidence). **CMDi**: location-aware (works on query/header/body). **CRLF**: query-only by design (`net/http` strips CR/LF from headers; body values don't reach response-header construction). **Config + CLI**: new `cfg.MaxProbesPerEndpoint int` field + `--max-probes-per-endpoint` flag (default 20); new `effectiveMaxProbes(cfg)` helper (treats 0 as default for safe zero-values); old `MaxProbesPerEndpoint` constant kept as the default value to preserve back-compat with existing test code. **Tests**: 14 new unit tests across `crawler_test.go` + `injection_test.go` (header param extraction with auth-header filter, body param extraction OAS 3 + Swagger 2, $ref-schema skip, error-based detection + no-FP, boolean-based detection + no-flip, body-JSON serialization, CR/LF header stripping, body probing reaches target, header probing reaches target, max-probes override, max-probes default-on-zero, fallback id, body-only-for-body-methods); 2 new e2e regressions (`TestActiveProbe_BodyParam_FindsErrorBasedSQLi` POSTs to vulnerable JSON endpoint reflecting MySQL syntax error, `TestActiveProbe_HeaderParam_ProbesCustomHeader` confirms X-Trace-Id-bearing probes reach target). **Real-world re-test on `/tmp/fendix-test/vuln_server.py`**: scan now emits `SQL Injection (SQLite, error-based) @ GET /api/v1/users` (was completely missed pre-TASK-086) plus `SQL Injection (boolean-based) @ GET /api/v1/ping`. All builds green: Go race-clean across 5 packages; Python 150/150; 6/6 e2e (4 prior + 2 new).
- TASK-087: Static analyzer expansion (first v0.4 task). **6 new patterns** added to `python/analyzers/ast_analyzer.py`: `PY_PICKLE_LOAD` (pickle.load/loads + cPickle/_pickle aliases, CRITICAL HIGH, CWE-502), `PY_YAML_UNSAFE_LOAD` (yaml.load without `Loader=SafeLoader`, plus `yaml.unsafe_load`/`yaml.load_all`, HIGH HIGH, CWE-502; correctly skips `yaml.safe_load` and explicit `Loader=yaml.SafeLoader` via new `_is_safe_loader_expr` helper that handles both attribute and bare-name forms), `PY_WEAK_CRYPTO_PASSWORD` (hashlib.md5/sha1 + hashlib.new('md5'/'sha1', ...) when input subtree references a password-like identifier, HIGH MEDIUM, CWE-916, **category=secrets**), `PY_OPEN_REDIRECT` (redirect()/HttpResponseRedirect() called with `request.args/GET/POST/...` data via new `_references_request_input` helper, HIGH MEDIUM, CWE-601), `PY_SSRF` (requests.get/post/put/delete/head/patch/options/request with non-literal first arg; resolved-constant variables don't trigger via scope tracking, HIGH MEDIUM, CWE-918), `PY_AUTH_HEADER_TRUST` (`if request.headers.get(...)/['..']` patterns in `visit_If`, HIGH MEDIUM, CWE-290, **category=auth_bypass**). **Multi-step SQLi** closed via intra-function scope tracking: new `visit_FunctionDef`/`visit_AsyncFunctionDef` push/pop a `_scopes` stack of `dict[str, ast.AST]`; `visit_Assign` records single-target Name assignments; `_is_sql_injection` now resolves Name args by walking the scope chain — `sql = "..." + var; cursor.execute(sql)` is now flagged. **Helpers**: `_emit_finding` got a `category` parameter (default `injection` for back-compat). `_looks_like_password_id` uses substring match for long tokens (`password`/`passwd`/`passphrase`/`secret`) + whole-snake-case-token match for short abbreviations (`pw`/`pwd`) via `_TOKEN_SPLIT_RE`, avoiding false positives like `pw` matching `power`. `_REQUEST_NAMES` (`{"request", "req"}`) recognizes both global and Flask handler-arg forms. `_REQUEST_INPUT_ATTRS` covers Flask/Django/FastAPI body sources (`GET/POST/args/values/form/data/json/query_params/path_params/params/body/files`); `headers` deliberately excluded since it has its own dedicated trust check. **Fixtures**: extended `dangerous.py` with 13 new patterns (pickle, yaml.load, yaml.unsafe_load, MD5(password), SHA1(passwd), open redirect via assignment + inline, SSRF, auth via X-Admin + X-Role, multi-step SQLi via assignment, inline `+` SQLi, plus 5 safe negative-coverage cases). **Tests**: 16 new test methods across 7 new test classes (`TestPickleDeserialization`, `TestYamlUnsafeLoad`, `TestWeakCryptoForPasswords`, `TestOpenRedirect`, `TestSSRF`, `TestAuthHeaderTrust`, `TestSQLConcatViaAssignment`); each pattern gets at least one detect + one no-FP test; plus `pw`-abbrev detect, `power` no-FP, `req`-handler-arg detect, `request.session` no-FP, `yaml.safe_load` no-FP, `Loader=SafeLoader` no-FP, hashlib.new('md5', ...) detect. Test count 26 → 42 in test_ast_analyzer.py. **Real-world re-test on `/tmp/fendix-test/badcode/`**: scan went from 22 → 26 findings (+4 new — multi-step SQLi at handlers.py:16 was completely missed pre-fix; pickle.loads at handlers.py:50 missed; MD5(pw) at :38 missed because `pw` wasn't in pattern table; X-Admin trust at :61 missed because `req` wasn't recognized as request-arg). Python tests 150 → 174 (+24); Go race-clean across 5 packages; 6/6 e2e.
- TASK-088: Findings deduplication. **New field**: `AffectedEndpoints []string` on `models.Finding` (json:`affected_endpoints,omitempty`). **New file**: `go/internal/engine/dedup.go` — `Deduplicate(findings)` keys on `(Title, Category, Severity)`, picks highest confidence in group, promotes source via `correlated > blackbox > whitebox`, unions references; primary kept = first-seen finding (preserves Evidence/Fix/relative ordering); `AffectedEndpoints` only populated when group size > 1 (singleton stays clean). **Orchestrator wiring**: new step 5.5 between Correlate (5) and Sort (6) — runs after correlation so `correlated` findings dedup against each other too. **HTML reporter**: `+N more` badge in finding header (`{{if gt (len .AffectedEndpoints) 1}}`), "Affected endpoints (N)" list in body; new `sub` template func; new `.affected-list` CSS. **SARIF reporter**: each `AffectedEndpoint` becomes its own `SARIFLocation` under the result (per SARIF 2.1.0 §3.27.12 "this issue applies to all of them" semantics); the line/whitebox path unchanged. **Tests**: 8 unit tests in `dedup_test.go` (groups identical, singleton has nil AffectedEndpoints, different severity not merged, references unioned + sorted, picks highest confidence, source promotion across 3 cases, preserves order, empty/single defensive); 2 reporter tests (`TestRenderHTML_AffectedEndpointsList`, `TestRenderHTML_SingletonHasNoAffectedSection`, `TestRenderSARIF_AffectedEndpointsAsMultipleLocations`); 1 e2e regression (`TestDedup_GroupsSameFindingAcrossEndpoints` declares 3 endpoints with identical handler, asserts `affected_endpoints` appears in JSON output). **Real-world re-test on `petstore3.swagger.io`**: scan went from 160 findings → **10 findings (16× reduction)**. 9 deduped findings collapsed 159 occurrences across 21 endpoints — top 5 (CORS allows any origin, Missing CSP, Missing HSTS, Missing X-Content-Type-Options, Missing X-Frame-Options) each cover all 21 endpoints. Whitebox `/tmp/fendix-test/badcode/`: 26 → 22 (3 `.env` lines collapsed, 2 Stripe overlaps collapsed, 2 SQLi-on-different-lines collapsed). Go race-clean (5 packages); Python 174/174; 7/7 e2e (6 prior + 1 new).

### Pending tasks — Phase 11 (v0.4 batch — TASK-085 + TASK-086 already shipped to v0.3; TASK-087 + TASK-088 done)

- TASK-089: Crawler — robots.txt + sitemap.xml + HTML link parsing, recursive depth, `--wordlist` flag, larger default list
- TASK-090: Real CVE coverage — pip-audit + npm audit + govulncheck primary; hardcoded list as offline fallback
- TASK-091: Correlator — debug instrumentation, loosen matching predicate, e2e test asserting >=1 correlated finding

### Pending tasks (Phase 12 — P2 Quality & Ops, v0.5)

- TASK-092: Output schema cleanup — `docs/schema.md`, JSON-schema validation in tests, evidence-suffix logic, severity↔confidence consistency
- TASK-093: Crawler placeholder substitution — schema-derived sample values for path params
- TASK-094: Logging hygiene — aggregate per-check failures, cap WARN volume, downgrade rest to DEBUG
- TASK-095: Scan budget controls — `--max-requests`, `--max-duration`, `--respect-robots`
- TASK-096: Auth profiles e2e — bearer + api-key (header/query) + basic + cookie + refresh-on-401
- TASK-097: Concurrency review — `-race` against 1000-endpoint scan in CI, fuzz worker-pool cancellation
- TASK-098: CI integration recipe — `examples/github-actions/fendix-scan.yml` with SARIF upload + baseline-diff PR comment

### Pending tasks (Phase 13 — P3 External Release, v1.0)

- TASK-099: Reproducible release pipeline — linux/arm64, cosign signing, Homebrew auto-update, signed Docker
- TASK-100: Distribution artifacts — `.deb` + `.rpm` via nfpm, `get.fendix.dev` one-line installer
- TASK-101: Documentation pass — 5-min juice-shop walkthrough, CI integration page, Semgrep rule guide, triage workflow, JSON schema ref
- TASK-102: `--debug` bundle — redacted config + OS + Python version + probe audit + slog-debug into a tarball
- TASK-103: SECURITY.md + active-scanner threat model + signed commits/releases
- TASK-104: Performance benchmark suite — scan time vs endpoint count, memory peak, goroutine count, published in README

### Blocked

*(none)*

---

## Last Session Summary

**Date:** 2026-04-29 (late night — TASK-088: findings deduplication)
**Session goal:** Complete TASK-088 — collapse N findings of the same `(Title, Category, Severity)` into one finding with `AffectedEndpoints []string`. Surface the change end-to-end through the JSON, HTML, and SARIF reporters. This is the second task in the v0.4 batch (TASK-087..091).

**Accomplished:**

- **New `AffectedEndpoints []string` field** on `models.Finding` (`json:"affected_endpoints,omitempty"`). Singletons keep it nil so the JSON shape doesn't bloat for the common case. Documented intent in the struct's docstring so future contributors know it's a dedup output, not a contract field for engines to populate.
- **New `engine.Deduplicate(findings)`** in `go/internal/engine/dedup.go`. Groups by `dedupKey = severity|category|title` (Source intentionally omitted so the "missing CSP" case dedups across hybrid scans where the same vuln gets both blackbox + whitebox sources before correlation). Group merge rules:
  - Primary = first-seen finding in input order (preserves Evidence, Fix, ID position)
  - `AffectedEndpoints` = sorted, deduped union of all endpoints (only set when > 1)
  - References = sorted, deduped union of all references in the group
  - Confidence = highest (`HIGH > MEDIUM > LOW`) — a finding confirmed at HIGH on at least one endpoint stays HIGH
  - Source promotion via `mergeSource`: `correlated > blackbox > whitebox` (defensive — Correlator runs first, but mixed-source same-key groups can still occur)
  - Output ordering preserves first-occurrence position via `firstIdx` to keep downstream `SEC-NNN` ID assignment deterministic
- **Orchestrator wired** at new step 5.5 between Correlate (step 5) and Sort (step 6). Critical that dedup runs AFTER correlation so correlated findings dedup against each other; running before would produce wrong groupings on hybrid scans.
- **HTML reporter** now renders dedup'd findings with a `+N more` badge in the finding header (`<em>` styled in amber to match the evidence color) and an "Affected endpoints (N)" `<ul>` in the body. New `sub` template func. New `.affected-list` CSS rule. Singletons render unchanged — no empty section, no badge, no visual noise.
- **SARIF reporter** emits one `SARIFLocation` per `AffectedEndpoint` per result. Per SARIF 2.1.0 §3.27.12, multiple locations on a single result mean "this issue applies to all of them" — exactly the semantics we want. The whitebox/file:line path is unchanged (those rarely repeat). Refactored the location-building branch to use a single endpoint-list code path: when `AffectedEndpoints` is set, iterate it; otherwise fall back to a singleton `[Endpoint]`.
- **8 new unit tests** in `dedup_test.go`:
  - `TestDeduplicate_GroupsIdenticalFindings`: 4 endpoints same finding → 1 with 4 affected
  - `TestDeduplicate_SingletonHasNoAffectedEndpoints`: nil for size-1 groups
  - `TestDeduplicate_DifferentSeverityNotMerged`: same title+category but Medium vs High stay separate
  - `TestDeduplicate_ReferencesUnioned`: CWE-89 + OWASP-A03 + CWE-20 → sorted union of all three
  - `TestDeduplicate_PicksHighestConfidence`: M + H + L → H
  - `TestDeduplicate_SourcePromotion`: 3 sub-cases (correlated wins, blackbox-over-whitebox, all-same)
  - `TestDeduplicate_PreservesOrder`: A,B,A,C input → A,B,C output (A's position from first occurrence)
  - `TestDeduplicate_EmptyAndSingle`: defensive — no panic on nil/empty/singleton
- **3 new reporter tests**: `TestRenderHTML_AffectedEndpointsList` (verifies header badge "+2 more" + body list with all 3 endpoints), `TestRenderHTML_SingletonHasNoAffectedSection` (no "Affected endpoints" string for nil case), `TestRenderSARIF_AffectedEndpointsAsMultipleLocations` (exactly 3 SARIFLocation entries for 3 affected endpoints).
- **1 new e2e regression**: `TestDedup_GroupsSameFindingAcrossEndpoints` — declares 3 endpoints in OAS spec, all served by the same handler with weak headers, asserts `affected_endpoints` appears in the JSON output.
- **Real-world re-test on `petstore3.swagger.io`** (the original "21 endpoints, 160 findings" scenario from 2026-04-28): scan went from **160 findings → 10 findings (16× reduction)**. Top 5 collapsed findings each cover all 21 endpoints (CORS allows any origin, Missing CSP, Missing HSTS, Missing X-Content-Type-Options, Missing X-Frame-Options). 9 deduped findings collapsed 159 occurrences; 1 singleton finding remained.
- **Real-world re-test on `/tmp/fendix-test/badcode/`** (whitebox-only): 26 findings → 22 (4 collapsed: 3 `.env` lines into 1 finding with 3 affected, 2 Stripe occurrences into 1 with 2 affected, 2 SQLi findings on different lines into 1 with 2 affected). Confirms whitebox file:line endpoints dedup correctly too.

**Decisions made:**

- **Dedup key is `(Title, Category, Severity)`, not `(Title, Category)`.** Same-title findings at different severities are different findings — e.g. a HIGH SQL Injection vs a MEDIUM one (boolean-based, less confidence) shouldn't collapse. Severity in the key is the cheap fix.
- **Source NOT in dedup key.** This was deliberate: the same vuln found by both engines on the same endpoint should collapse, not stay as two separate entries. The Correlator already merges hybrid pairs before Dedup runs — but dedup must handle the residual case where Correlator's matching predicate misses (which it currently does — see TASK-091 backlog).
- **`AffectedEndpoints` includes the primary endpoint when set.** Considered "only OTHER endpoints" but rejected — consumers iterating "all places this finding applies" would have to do `affected if affected else [endpoint]` everywhere. Inclusive list is friendlier and the duplication is one string field.
- **`AffectedEndpoints` is `[]string`, not `[]Endpoint`.** The existing `Endpoint` field is already a string (`"GET /api/users"` for blackbox, `"file.py:42"` for whitebox), so a slice-of-strings matches the rest of the contract. Migrating to a richer struct would mean rewriting all reporters and the IPC contract — out of proportion for a v0.4 ergonomics fix.
- **Dedup runs AFTER correlation, BEFORE sort.** Pre-correlation dedup would lose hybrid pairs (a `secrets` finding at file:line and a `data_exposure` finding at endpoint would never see each other). Post-sort dedup would scramble the deterministic SEC-NNN assignment. Step 5.5 is the right slot.
- **Confidence merge is "highest wins", not "average" or "lowest wins".** A vuln confirmed at HIGH on one endpoint is a HIGH-confidence vuln overall, even if other endpoint instances are MEDIUM-confidence (e.g. boolean-based variant). Lowering the confidence would understate the user's risk.
- **Source promotion ladder is fixed (`correlated > blackbox > whitebox`)**, matching the existing `SourceMult` weights in the severity scoring model. Predictable ranking; no need for tunables.
- **No CHANGELOG fold or release tag this session.** The v0.3 batch (TASK-085+086) is still uncut from the prior session; v0.4 batch is now 2/5 done. Continuing to bank v0.4 progress and ship one batch later when more user-visible improvements have accumulated.

**Files modified:**

- `go/internal/models/finding.go` — added `AffectedEndpoints []string` with omitempty + docstring.
- `go/internal/engine/dedup.go` — NEW file. Public `Deduplicate(findings) []models.Finding`; internal `dedupKey`, `confidenceRank`, `mergeSource`, `stringSet`, `sortedKeys`. Comments explain motivation, merge rules, and why each helper exists.
- `go/internal/engine/dedup_test.go` — NEW file. 8 unit tests covering all behaviors.
- `go/internal/engine/orchestrator.go` — added step 5.5 (`findings = Deduplicate(findings)`) between correlate and sort.
- `go/internal/reporters/html.go` — added `+N more` badge in header, "Affected endpoints (N)" list in body, `.affected-list` CSS, `.finding-endpoint em` CSS for badge styling, `sub` template func.
- `go/internal/reporters/html_test.go` — added `TestRenderHTML_AffectedEndpointsList` + `TestRenderHTML_SingletonHasNoAffectedSection`.
- `go/internal/reporters/sarif.go` — refactored location-building to iterate over `AffectedEndpoints` (or fall back to singleton `Endpoint`), emitting one SARIFLocation per endpoint.
- `go/internal/reporters/sarif_test.go` — added `TestRenderSARIF_AffectedEndpointsAsMultipleLocations`.
- `go/internal/e2e/e2e_test.go` — added `TestDedup_GroupsSameFindingAcrossEndpoints`.
- `CHANGELOG.md` — `[Unreleased]` Added: TASK-088 entry with petstore evidence (160 → 10).
- `tasks/CURRENT_SPRINT.md` — TASK-088 marked ✅ with full implementation notes.
- `tasks/MEMORY.md` (this file) — Phase 11 progress (3/7 → 4/7 done); TASK-088 entry; new Last Session Summary; "Next session" pointer reset to TASK-089.

**Build state at session end:**

- `make build` ✓
- `make test` ✓ (Go race-clean across 5 packages; Python 174/174)
- `make e2e` ✓ (7/7 e2e regression tests — 6 prior + 1 new TASK-088 regression)

**Next session should start with:**

1. **(Carry-over from prior session) Verify v0.2.0 release succeeded** — browser-load `https://github.com/Abdel-RahmanSaied/Fendix/releases/tag/v0.2.0` and confirm linux/amd64, darwin/amd64, darwin/arm64 binaries with sha256 checksums.
2. **(Carry-over) Cut v0.3.0** — both v0.3 batch tasks (TASK-085 + TASK-086) are done. Steps still apply: fold `[Unreleased]` `→ [0.3.0] - <today>`, conventional commit `feat: v0.3.0 — coverage parity (TASK-085 + TASK-086)`, annotated tag, push.
3. **TASK-089 — Crawler upgrade.** Per `tasks/PHASES.md` Phase 11. Spec:
   - **robots.txt parser** — fetch `/robots.txt`, extract `Disallow:` and `Allow:` paths, queue them for scanning. Disallowed paths are often hidden admin endpoints — high-value discovery surface.
   - **sitemap.xml parser** — fetch `/sitemap.xml` (and any `Sitemap:` URLs from robots.txt), extract `<loc>` elements, queue them.
   - **HTML link parsing** — already partly there via `apiPathRe`; extend to parse `<a href="...">` and `<form action="...">` from HTML responses to discover endpoints linked from the home page or any visited URL.
   - **Recursive depth** — currently only the `--url` page gets HTML/JS scanning; add a `--crawl-depth` flag (default 2) so the crawler follows discovered URLs one or two hops out. Cap total endpoints at a budget (`--max-endpoints`, default 500?) to avoid runaway scans on large sites.
   - **`--wordlist` flag** — currently the brute-force list is the hardcoded 50-path `CommonPaths`. Add `--wordlist /path/to/wordlist.txt` to override. Optionally bundle SecLists' `common.txt` (or a curated subset) as the new default.
   - **e2e regression** — stand up a mock server that serves robots.txt with a `Disallow: /admin/secret` line, assert the scanner discovers and probes that path.
4. After TASK-089, evaluate whether to ship v0.4.0 with the now-3-task batch (TASK-087+088+089) or continue to TASK-090+091 first.

**Open questions:**

- **Should `--max-endpoints` be a separate task or rolled into TASK-089?** Strongly related — recursive depth without a budget is dangerous on large sites (the GitHub spec parsed to 1145 endpoints). Recommend rolling it in, since the natural shape is "crawl with budget".
- **Default crawl depth: 1, 2, or 3?** Depth 0 = just `--url`; 1 = follow links from base page (current behavior is partial); 2 = follow links from those pages too. Larger = more coverage but more risk of scanning unintended targets. Default of 2 seems right; user can lower with `--crawl-depth 0` for spec-only or single-page mode.
- **SecLists wordlist licensing?** SecLists is MIT, so embedding a subset is fine, but it's ~few-thousand entries and would inflate the binary by some unknown amount. Check size before committing to embed; alternatively fetch on first run (slower UX, more failure modes). Defer decision to implementation time.

---

## Earlier Session (2026-04-29 night — TASK-087: static analyzer expansion, first v0.4 task)

**Session goal:** Complete TASK-087 — extend `python/analyzers/ast_analyzer.py` with 6 new AST patterns (pickle, yaml.load, weak crypto for passwords, open redirect, SSRF, auth-header trust) plus closing the multi-step string-concat SQLi gap via intra-function scope tracking. This is the first task in the v0.4 batch (TASK-087..091).

**Accomplished:**

- **6 new AST pattern detectors** in `python/analyzers/ast_analyzer.py`:
  - `PY_PICKLE_LOAD` — `pickle.load()` / `pickle.loads()` (plus `cPickle` and `_pickle` aliases). Always dangerous on untrusted data; no "safe variant" exists. CRITICAL HIGH, CWE-502.
  - `PY_YAML_UNSAFE_LOAD` — `yaml.load()` without `Loader=SafeLoader`, plus `yaml.unsafe_load()`/`yaml.load_all()`. Correctly skips `yaml.safe_load()` and explicit `Loader=yaml.SafeLoader` via new `_is_safe_loader_expr` helper that handles both attribute (`yaml.SafeLoader`) and bare-name (`SafeLoader` after `from yaml import`) forms. HIGH HIGH, CWE-502.
  - `PY_WEAK_CRYPTO_PASSWORD` — `hashlib.md5/sha1` and `hashlib.new('md5'/'sha1', data)` when the input subtree references a password-like identifier. HIGH MEDIUM, CWE-916, **category=secrets** (not injection).
  - `PY_OPEN_REDIRECT` — `redirect()`/`HttpResponseRedirect()` called with `request.args/GET/POST/...` data. HIGH MEDIUM, CWE-601.
  - `PY_SSRF` — `requests.<method>()` with non-literal first arg. Resolved-constant variables don't trigger (scope-tracking lookup). HIGH MEDIUM, CWE-918.
  - `PY_AUTH_HEADER_TRUST` — `if request.headers.get('X-Admin')` / `if req.headers['X-Role']`. New `visit_If` hook. HIGH MEDIUM, CWE-290, **category=auth_bypass**.
- **Multi-step SQL injection** closed via intra-function scope tracking. The `_PythonSecurityVisitor` now maintains a `_scopes: list[dict[str, ast.AST]]` stack: `visit_FunctionDef`/`visit_AsyncFunctionDef` push/pop scopes, `visit_Assign` records single-target Name assignments, and `_is_sql_injection` resolves Name args via the scope chain. Pattern that was missed pre-fix: `sql = "SELECT * FROM users WHERE id = " + uid; cursor.execute(sql)` — assignment recorded, Name resolved at execute() site.
- **`_emit_finding` got a `category` parameter** (default `injection` for back-compat). Lets the new patterns route to `secrets` and `auth_bypass` categories so the severity-scoring impact bases apply correctly.
- **Identifier-matching helpers refined** to keep noise low:
  - `_looks_like_password_id` uses substring match for long tokens (`password`/`passwd`/`passphrase`/`secret`) + whole-snake-case-token match for short abbreviations (`pw`/`pwd`) via `_TOKEN_SPLIT_RE`. Avoids the obvious false positive of `pw` matching `power`/`pwn`/etc. but still catches `user_pw`, `pwd_hash`, `admin_password`.
  - `_REQUEST_NAMES = {"request", "req"}` recognizes both the Django/FastAPI global and the Flask handler-arg abbreviation. Used by both `_references_request_input` (open redirect) and `_is_request_header_trust` (auth-header).
  - `_REQUEST_INPUT_ATTRS` covers Flask/Django/FastAPI body sources (`GET/POST/args/values/form/data/json/query_params/path_params/params/body/files`); `headers` is deliberately excluded because it has its own dedicated trust check.
- **Fixture extended** (`python/tests/fixtures/ast_target/dangerous.py`): added 13 new dangerous-pattern functions (pickle, yaml.load, yaml.unsafe_load, MD5(password), SHA1(passwd), open redirect via assignment + inline, SSRF, auth via X-Admin + X-Role, multi-step SQLi via assignment, inline `+` SQLi) plus 5 safe negative-coverage cases (yaml.load with SafeLoader, yaml.safe_load, MD5 of non-password file checksum, redirect to constant path, requests.get with constant URL, request.session check).
- **16 new test methods** across 7 new test classes (`TestPickleDeserialization`, `TestYamlUnsafeLoad`, `TestWeakCryptoForPasswords`, `TestOpenRedirect`, `TestSSRF`, `TestAuthHeaderTrust`, `TestSQLConcatViaAssignment`). Each pattern: at least one detect + one no-FP test. Plus `pw`-abbrev detect, `power` no-FP, `req`-handler-arg detect. Test count 26 → 42 in test_ast_analyzer.py; full Python suite 150 → 174 (+24).
- **Real-world re-test on `/tmp/fendix-test/badcode/`**: scan went from 22 findings → 26 findings (+4 new):
  - CRITICAL multi-step SQLi @ handlers.py:16 — multi-step assignment now resolved through scope chain
  - CRITICAL pickle.loads @ handlers.py:50 — was completely missed pre-fix
  - HIGH MD5(pw) @ handlers.py:38 — was missed because `pw` wasn't in pattern table; now caught by whole-token snake_case match
  - HIGH X-Admin trust @ handlers.py:61 — was missed because the handler arg is named `req`; now caught via `_REQUEST_NAMES`
  - Open redirect at handlers.py:56-57 NOT flagged (correctly) — the badcode uses `f"Location: {target}"` not `redirect()`. Different attack pattern; not in TASK-087 scope.
- **Required engine cache flush** between rebuilds. The Go binary embeds Python and extracts to `~/.fendix/engine/` keyed by version stamp. Since the build version `v0.2.0-1-gaff18ef` is unchanged, the binary won't re-extract — needed `rm -rf ~/.fendix/engine` to pick up the new ast_analyzer.py code in real-world testing. Worth noting for any future iterative dev cycle. Production users get fresh extraction on version bumps so this only bites local dev.

**Decisions made:**

- **Substring vs whole-token password matching is hybrid, not uniform.** Long tokens like `password` are unambiguous as substrings; short tokens like `pw` aren't (`power`, `pwn`). Two separate constants (`_PASSWORD_SUBSTR_TOKENS`, `_PASSWORD_WORD_TOKENS`) make the distinction explicit. The whole-token check splits on `[^a-z0-9]+` which handles snake_case, kebab-case, dotted, and mixed identifiers — `user_pw_hash` and `admin-pwd-storage` both match.
- **`req` recognized as alternative to `request`.** Convention varies: Django and FastAPI use `request`; Flask is split (the global `request` vs handler-arg `req`). Both extracted into shared `_REQUEST_NAMES` constant for use by open-redirect and auth-header-trust detectors. Risk: any `req` variable named that way (e.g. for HTTP request data structures) could trigger false positives — judged acceptable because real-world Flask/aiohttp handlers use `req` extensively for the request object specifically.
- **Auth-header trust is MEDIUM confidence, not HIGH.** The `if request.headers.get(...)` pattern is sometimes legitimate (CORS preflight handling, content negotiation). The pattern's strong signal is the *security decision* shape — the if-statement + header read together — but distinguishing security decisions from non-security decisions requires data-flow that's out of scope. MEDIUM confidence captures this uncertainty.
- **Multi-step SQLi tracking is intra-function only.** Module-level globals or cross-function tracking would need a full data-flow analyzer; intra-function gets the most common pattern (the "Bobby Tables" case from the 2026-04-28 evaluation) without that complexity. Captured as a `_scopes` stack of `dict[str, ast.AST]` — module scope at the bottom, each function pushes/pops a scope on entry/exit. Re-assignment overwrites the prior value; this is correct (latest wins).
- **`yaml.unsafe_load` and `yaml.load_all` always flagged**, regardless of args. There's no safe form of either. `yaml.load()` is gated on `Loader=` because `Loader=yaml.SafeLoader` is the documented safe usage.
- **`hashlib.md5(file_data)` not flagged** — variable name has no password hint. MD5 for non-password use (file checksums, content-addressed storage) is fine, and flagging it would create false-positive noise. The narrow heuristic (require password-like identifier in arg subtree) keeps the signal high.
- **No version bump or release tag this session.** v0.4 batch is TASK-087..091; only TASK-087 done. Cutting v0.4 with one task would force v0.4.1 within days. v0.3.0 batch (TASK-085+086) is also still uncut from prior session. Both pending, but I'm focusing on code progress per "after each phase do the next" instruction.

**Files modified:**

- `python/analyzers/ast_analyzer.py` — added 6 new pattern detectors (`_is_pickle_load`, `_is_unsafe_yaml_load`, `_is_weak_password_hash`, `_is_open_redirect`, `_is_ssrf`); added `visit_FunctionDef`/`visit_AsyncFunctionDef`/`visit_Assign`/`visit_If`; added `_scopes` stack to visitor `__init__`; added `category` parameter to `_emit_finding`; extended `_is_sql_injection` to resolve Name args via scope chain. Module-level helpers added: `_SAFE_LOADER_NAMES`, `_is_safe_loader_expr`, `_PASSWORD_SUBSTR_TOKENS`, `_PASSWORD_WORD_TOKENS`, `_TOKEN_SPLIT_RE`, `_looks_like_password_id`, `_arg_subtree_looks_like_password`, `_REQUEST_INPUT_ATTRS`, `_REQUEST_NAMES`, `_references_request_input`, `_is_request_header_trust`.
- `python/tests/fixtures/ast_target/dangerous.py` — added 13 new dangerous pattern functions and 5 safe negative-coverage functions (replaced via Write rather than incremental edits since the rewrite was extensive).
- `python/tests/test_ast_analyzer.py` — added 7 new test classes (16 new test methods) covering all new detectors + edge cases.
- `CHANGELOG.md` — `[Unreleased]` Added section: 7 new bullets for TASK-087 (each new pattern + multi-step SQLi).
- `tasks/CURRENT_SPRINT.md` — TASK-087 marked ✅ with full implementation notes.
- `tasks/MEMORY.md` (this file) — Phase 11 progress (2/7 → 3/7 done); TASK-087 entry; new Last Session Summary; "Next session" pointer reset to TASK-088.

**Build state at session end:**

- `make build` ✓ (binary built with VERSION=v0.2.0-1-gaff18ef)
- `make test` ✓ (Go race-clean across 5 packages; Python 174/174 — was 150)
- `make e2e` ✓ (6/6 e2e regression tests, ~2s)

**Next session should start with:**

1. **(Carry-over from prior session) Verify v0.2.0 release succeeded** — browser-load `https://github.com/Abdel-RahmanSaied/Fendix/releases/tag/v0.2.0` and confirm linux/amd64, darwin/amd64, darwin/arm64 binaries with sha256 checksums.
2. **(Carry-over) Cut v0.3.0** — both v0.3 batch tasks (TASK-085 + TASK-086) are done. Steps still apply: fold `[Unreleased]` `→ [0.3.0] - <today>`, conventional commit `feat: v0.3.0 — coverage parity (TASK-085 + TASK-086)`, annotated tag, push.
3. **TASK-088 — Findings deduplication via `AffectedEndpoints []Endpoint`.** Per `tasks/PHASES.md` Phase 11. Pattern: "Missing CSP header × 21 endpoints" → 1 finding with 21 endpoints. Implementation:
   - Extend Go `models.Finding` with `AffectedEndpoints []Endpoint` (or just `[]string` of the existing `Endpoint` field shape — TBD).
   - In `orchestrator.go` after correlation, walk findings and group those with identical (Title, Category) signatures, merging endpoints.
   - Propagate to JSON reporter (single finding entry with array of endpoints), HTML reporter (single row, expandable list of endpoints), SARIF reporter (multiple `locations` per `result`).
   - Add unit tests: 21 identical findings on different endpoints → 1 dedup'd finding with 21 endpoints; different (Title, Category) → not merged.
4. After TASK-088, can either continue TASK-089 (crawler upgrade) or stop and ship v0.4.0.

**Open questions:**

- **Open redirect detection misses string-format patterns.** `f"Location: {request.args.get('next')}"` (the badcode pattern) builds a header value via f-string rather than calling `redirect()`. To catch: detect Response/HttpResponse construction with f-string body containing request data — would require new pattern. Defer; redirect()-call form is the dominant pattern in real Flask/Django code.
- **YAML `Loader=yaml.UnsafeLoader` not flagged.** Currently we accept any non-`SafeLoader` Loader as unsafe (which is correct for `Loader=yaml.Loader` and `Loader=yaml.UnsafeLoader`), but we don't differentiate "non-safe loader explicitly chosen" from "no Loader argument given". Both go into the same finding. Could split into two patterns if real users want finer-grained signal. Defer.
- **Engine cache invalidation during dev.** Anyone iterating on Python code locally needs to `rm -rf ~/.fendix/engine` between builds since the version stamp doesn't change. Two options: (a) document this in CONTRIBUTING.md; (b) make the version include a content hash in dev mode so rebuilds always re-extract; (c) add a `--reset-engine` CLI flag. Defer to a Phase 12 dev-experience task.

---

## Earlier Session (2026-04-29 late evening — TASK-086: active-scanner expansion)

**Session goal:** Complete TASK-086 — body-param + header probing, error-based + boolean-based SQLi, SQLite/Oracle DB payloads, `--max-probes-per-endpoint` flag. Together with the morning's TASK-085, both v0.3.0 tasks are now done.

**Accomplished:**

- **Endpoint model extended** (`go/internal/scanner/scanner.go`): added `Headers []string` (in: header params with auth-headers filtered) and `BodyParams []string` (JSON body field names). The pre-existing `Params []string` continues to hold query/path params.
- **Crawler header + body extraction** (`go/internal/scanner/crawler.go`): new `extractHeaderParamsList()` returns `in: header` names with standard auth headers filtered (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Apikey`, `Api-Key`, `Proxy-Authorization`); new `extractBodyParamNames()` reads OAS 3 `requestBody.content."application/json".schema.properties` and Swagger 2 `parameters[in:body].schema.properties`; both skip `$ref` schemas. Path-level + operation-level params merged the same way `Params` already was.
- **Probe location infrastructure** (`go/internal/scanner/injection.go`): introduced `ProbeLocation` enum (`LocQuery`/`LocHeader`/`LocBody`); new `buildProbeRequest()` builds HTTP request with payload in the right place (body uses JSON with `"fendix"` placeholders for sibling fields so server validation doesn't 400 before vulnerable code runs; header strips CR/LF since net/http rejects malformed headers); new `targetsForEndpoint()` enumerates (param, location) pairs (body only on POST/PUT/PATCH; falls back to single `("id", query)` for fully-bare endpoints).
- **SQLi expansion** — 3 → 5 time-based DB payloads (added SQLite `' AND CASE WHEN 1=1 THEN randomblob(99999999) ELSE 0 END--`, Oracle `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`); new `probeSQLiErrorBased()` (single `'"`-class payload, regex match against 5 DB-specific error signatures from sqlmap/OWASP, HIGH severity HIGH confidence); new `probeSQLiBoolean()` (true/false payload pair `' OR '1'='1` vs `' AND '1'='2`, finding on status flip OR length-delta > 5%, MEDIUM confidence to convey false-positive risk).
- **Refactored existing probes** to take `ProbeLocation` parameter — `probeSQLi`, `probeCMDi` are now location-aware. `probeCRLF` is query-only by design (CR/LF gets stripped from header values upstream; body values don't reach response-header construction).
- **`--max-probes-per-endpoint` flag**: added `cfg.MaxProbesPerEndpoint int` to `ScanConfig`; new CLI flag wired in `main.go`; new `effectiveMaxProbes(cfg)` helper treats 0 as "use the default" so safe zero-values keep working. Old `MaxProbesPerEndpoint = 20` constant kept as the default value for back-compat (existing test asserts on it directly).
- **14 new unit tests** across `crawler_test.go` (4) and `injection_test.go` (10): header param extraction with auth-header filter, body param extraction OAS 3 + Swagger 2, $ref-schema skip, error-based detection MySQL + no-FP on generic error JSON, boolean-based detection length-flip + no-flip on static response, body-JSON serialization with placeholder siblings, CR/LF header stripping, body probing reaches target, header probing reaches target, max-probes override, max-probes default-on-zero, fallback `("id", query)`, body-only-for-body-methods.
- **2 new e2e regressions** (`go/internal/e2e/e2e_test.go`):
  - `TestActiveProbe_BodyParam_FindsErrorBasedSQLi`: POSTs to a vulnerable JSON endpoint that reflects MySQL syntax error on bare quotes; asserts the report contains `error-based` substring.
  - `TestActiveProbe_HeaderParam_ProbesCustomHeader`: declares X-Trace-Id as `in: header`, counts incoming requests with X-Trace-Id set; asserts non-zero hits.
- **Existing test signature updates**: 3 call sites for `probeSQLi`/`probeCMDi` updated for new `ProbeLocation` arg. `TestSqliPayloads` updated for 3 → 5 DB count. `TestIntegration_MultipleParams` got `MaxProbesPerEndpoint=200` because the per-endpoint probe budget is now realistic for 3 params × all probe types — exercises the new flag.
- **Real-world re-test on `/tmp/fendix-test/vuln_server.py`**: full active scan now emits `SQL Injection (SQLite, error-based) @ GET /api/v1/users` (was completely missed pre-TASK-086 — vuln-server reflects SQLite `unrecognized token` on bare-quote payload, our regex matches) plus `SQL Injection (boolean-based) @ GET /api/v1/ping` (a known-acceptable false positive from CMDi-vulnerable shell-out endpoint where shell output differs by 1 char between `' OR '1'='1` and `' AND '1'='2` payloads — MEDIUM confidence conveys the right uncertainty). Scan total: 43 findings (3 critical + 3 high + 19 medium + 12 low + 6 info).

**Decisions made:**

- **Kept `MaxProbesPerEndpoint = 20` as a constant** rather than removing it. Existing tests reference it directly; preserving the symbol avoids unnecessary churn. The new `effectiveMaxProbes(cfg)` helper layers the config-driven override on top.
- **Body-param probing is method-gated**: only POST/PUT/PATCH. Sending GET with a body is a footgun — most servers ignore or reject. Captured in `methodAcceptsBody()`.
- **JSON body construction puts `"fendix"` in sibling fields, not empty strings** — empty strings often fail server-side validation (e.g. min-length-1 username) before reaching the vulnerable code. Non-empty placeholder maximizes the chance the payload field is the one that gets evaluated.
- **Header values get CR/LF stripped via `strings.NewReplacer`** for non-CRLF probes. Go's net/http rejects requests with CR/LF in header values as malformed, and we'd lose detection of legitimate header-value injection in SQL/CMDi paths if we passed the raw payload through. CRLF probes still send the raw URL-encoded payload via the URL form (existing `probeCRLF` impl).
- **Boolean-based SQLi is MEDIUM confidence, not HIGH** — length-delta detection is inherently noisy on dynamic responses (timestamps, random IDs). Status-flip is a stronger signal but folded into the same finding for simplicity. The 5% length threshold matches the spec; tightening to status-only would miss too many real cases.
- **Error-based SQLi sends just `fendix'"`** rather than `fendix' OR 1=1--`. The 4-char payload is enough to trip parsing on virtually every SQL engine (single quote alone often suffices); shorter payload = lower chance of being filtered by middleware before reaching the DB.
- **OAS 3 body-param extractor walks one level deep** (top-level properties only). Nested objects would multiply probe count without improving detection — most JSON-body SQLi surfaces in flat top-level fields.
- **CRLF stays query-only** — extending to header probes would always be no-ops because Go's http client strips CR/LF from header values; extending to body probes would require parsing the response for reflected raw `\r\n` which is a different detection path entirely.
- **No version bump or release tag this session.** Per the morning's plan, v0.3.0 = TASK-085 + TASK-086. Both are done; ready to ship next session pending CHANGELOG fold (`[Unreleased]` → `[0.3.0] - <date>`).

**Files modified:**

- `go/internal/scanner/scanner.go` — Endpoint extended with Headers + BodyParams.
- `go/internal/scanner/crawler.go` — added `extractHeaderParamsList()`, `extractBodyParamNames()`, `schemaPropertyNames()`, `skippableHeaderNames` map; `fromSpec` populates new fields.
- `go/internal/scanner/crawler_test.go` — 4 new tests for header/body param extraction + $ref skip.
- `go/internal/scanner/injection.go` — major refactor: added `ProbeLocation`, `effectiveMaxProbes`, `methodAcceptsBody`, `probeTarget`, `targetsForEndpoint`, `buildProbeRequest`, `buildJSONBody`, `paramLabel`, `sqliErrorPayload`, `sqliErrorPatterns`, `sqliBooleanPayloads`, `sqliBooleanLengthThreshold`, `probeSQLiErrorBased`, `probeSQLiBoolean`, `sendBoolProbe`. `probeSQLi` + `probeCMDi` updated to take `ProbeLocation`. `probeCRLF` updated to use `effectiveMaxProbes`. `CheckInjectionWithAudit` rewritten to iterate over (param, location) pairs from `targetsForEndpoint`. `sqliPayloads` extended with SQLite + Oracle entries (3 → 5).
- `go/internal/scanner/injection_test.go` — 10 new tests for new probe types + body/header probing + max-probes flag + `targetsForEndpoint` semantics; 3 existing call-site updates for new ProbeLocation arg; 2 assertion updates (sqliPayloads count, MultipleParams budget).
- `go/internal/models/config.go` — added `MaxProbesPerEndpoint int`.
- `go/cmd/fendix/main.go` — added `--max-probes-per-endpoint` flag wired to `cfg.MaxProbesPerEndpoint`.
- `go/internal/e2e/e2e_test.go` — added 2 e2e regressions for body + header probing; added `bytes`, `fmt`, `io` imports.
- `CHANGELOG.md` — `[Unreleased]` Added section: 6 new bullets for TASK-086 (body-param probing, header-param probing, error-based SQLi, boolean-based SQLi, SQLite + Oracle payloads, `--max-probes-per-endpoint` flag).
- `tasks/CURRENT_SPRINT.md` — TASK-086 marked ✅ with full implementation notes.
- `tasks/MEMORY.md` (this file) — Phase 11 progress (1/7 → 2/7 done); TASK-086 entry; new Last Session Summary; "Next session" pointer reset to "cut v0.3.0 or start TASK-087".

**Build state at session end:**

- `make build` ✓ (binary built with VERSION=v0.2.0-1-gaff18ef)
- `make test` ✓ (Go race-clean across 5 packages; Python 150/150)
- `make e2e` ✓ (6/6 — 4 prior + 2 new TASK-086 regressions)

**Next session should start with:**

1. **(Carry-over from prior session) Verify v0.2.0 release succeeded** — browser-load `https://github.com/Abdel-RahmanSaied/Fendix/releases/tag/v0.2.0` and confirm linux/amd64, darwin/amd64, darwin/arm64 binaries with sha256 checksums.
2. **Cut v0.3.0** — both v0.3 batch tasks (TASK-085 + TASK-086) are done. Steps:
   - Fold `[Unreleased]` section in `CHANGELOG.md` into a `[0.3.0] - <today>` versioned section. Group: Added (provider secrets, `.env` scanning, body-param probing, header-param probing, error-based SQLi, boolean-based SQLi, SQLite + Oracle payloads, `--max-probes-per-endpoint`); Fixed (anti-overlap regex anchors).
   - Conventional commit `feat: v0.3.0 — coverage parity (TASK-085 + TASK-086)`.
   - Annotated tag `v0.3.0` and push to origin (release.yml triggers on `v*`).
   - Real-world re-test on the same fixtures to confirm no regressions (the in-session test on vuln_server already showed positive deltas; one more pass on `/tmp/fendix-test/badcode/` for whitebox).
3. **Begin TASK-087 — Static analyzer expansion (v0.4 batch).** Per `tasks/PHASES.md`: string-concat SQLi (the original Bobby Tables pattern, currently missed because we only catch f-strings), `pickle.loads`, `yaml.load(..., Loader=Loader)` without SafeLoader, MD5/SHA1 used for password hashing, open-redirect patterns (`response.redirect(request.GET.get('url'))`), SSRF (`requests.get(user_input)`), auth-header trust patterns (`if request.headers.get('X-Admin'): ...`). All AST-based in `python/analyzers/ast_analyzer.py`.

**Open questions:**

- **Boolean-based SQLi false positives on shell-injection endpoints** — confirmed in real-world re-test that `/api/v1/ping` (CMDi-vulnerable, not SQLi-vulnerable) produced a boolean-based finding because the shell output `pinging ' OR '1'='1` differs in length from `pinging ' AND '1'='2` by 4 bytes. This is technically a true positive in the sense that "user input affects response shape" — it's just attributed to the wrong vuln class. MEDIUM confidence partially compensates. If false-positive volume becomes a problem in real usage, options are: (a) require BOTH status flip AND length flip; (b) require length-flip ratio > 10% instead of 5%; (c) add a tiebreaker probe that should produce identical output if it's truly CMDi rather than SQLi. Defer until real users complain.
- **Body-param probing budget** — current budget of 20 hits hard on POST endpoints with 3+ body fields × 3 probe types per location. Real users with rich request bodies will need to bump `--max-probes-per-endpoint`. The default keeps the v0.2 contract (no surprise probe explosion); the flag exists. Should the default rise in v0.4? Worth raising once we have feedback from someone running fendix against a real REST API.
- **Body probes only target `application/json` content** — multipart, urlencoded, XML bodies are not yet covered. JSON is the dominant modern API contract so this is high-value-first; add other formats only if real users need them.
- **OAS `$ref` deref still deferred** — body schemas defined via `$ref: '#/components/schemas/User'` produce zero body params. This is the same limitation as TASK-081 for parameter `$ref`s. Together they likely undercount endpoint coverage on real specs (Stripe, GitHub, etc. heavily use $ref). Would warrant its own task, possibly Phase 12.

---

## Earlier Session (2026-04-29 evening — TASK-085: secret-pattern coverage)

**Session goal:** Begin Phase 11 with TASK-085 — expand secret patterns to industry-baseline coverage (gitleaks-comparable) and fix the `.env`-scanning gap.

**Accomplished:**

- **8 new provider patterns added** to `python/analyzers/secrets.py`: `GITHUB_TOKEN` (`gh[opusr]_` + 36, CRITICAL), `STRIPE_LIVE_KEY` (`sk_live_` + 20+, CRITICAL), `SLACK_TOKEN` (`xox[abprs]-` + 10+, HIGH), `GOOGLE_API_KEY` (`AIza` + exactly 35, HIGH), `ANTHROPIC_API_KEY` (`sk-ant-` + 20+, CRITICAL), `OPENAI_API_KEY` (`sk-(?:proj-|svcacct-)?` + 32+, CRITICAL), `NPM_TOKEN` (`npm_` + 36, HIGH), `GCP_SERVICE_ACCOUNT` (canonical JSON `"type": "service_account"`, CRITICAL). Total pattern count 7 → 15.
- **`.env`-only pattern path** — new `_ENV_PATTERNS` list with `ENV_SECRET` regex matching unquoted `KEY=value` where the key suffix is credential-y (`KEY|TOKEN|SECRET|PASSWORD|...`). Gated by new `_is_env_file()` helper so the relaxed regex only fires on `.env*` files; this avoids false positives in regular code where unquoted assignment is normal syntax.
- **Dotfile-walker bug fixed** — `.env` files have `Path.suffix == ""` and were silently skipped by the suffix-based file filter in `_walk()`. Walker now also yields env-files by name. This was a separate latent bug surfaced by the TASK-085 work (independent of the regex fix).
- **3 new fixture files**: `provider_tokens.py` (8 provider tokens), `gcp_service_account.json` (canonical SA JSON), `.env` (4 unquoted-secret lines + 2 should-not-match lines for negative coverage).
- **10 new test methods**: 8 per-provider `test_X_detected` + `test_env_unquoted_secret_detected` + `test_anti_overlap_openai_does_not_match_anthropic`. All 150 Python tests pass (was 140; +10).
- **Real-world re-test on `/tmp/fendix-test/badcode/`**: full whitebox scan went from 16 findings (6 critical + 10 high) → 19 findings (8 critical + 11 high). Net delta: +2 critical (GitHub + Stripe), +1 high (the 3 ENV_SECRET findings minus existing overlaps with the new STRIPE pattern on the same `.env` line). Six new individual findings on the same fixture that pre-fix would have completely missed: 1 GitHub token, 2 Stripe keys, 3 unquoted `.env` secrets.
- **All builds green**: `make test` 150/150 Python + Go race-clean across 5 packages; `make e2e` 4/4 (1.9s).

**Decisions made:**

- **Two-tier pattern table.** Considered putting the `.env` regex into the main `_PATTERNS` list with a much broader regex that handles both quoted and unquoted. Rejected — the unquoted variant has high false-positive rate in code (e.g. `LOG_LEVEL=debug`), so gating to `.env*` files is the correct tradeoff. Implementation: separate `_ENV_PATTERNS` list applied conditionally in `_scan_file`.
- **Provider regex anchoring with `(?<![A-Za-z0-9])`/`(?![A-Za-z0-9])`** rather than `\b` — `\b` treats `_` and `-` as word chars in different ways across language tokens; the explicit lookbehind/ahead is unambiguous and matches our intent: the prefix must not be inside a longer alphanumeric run.
- **OpenAI pattern length floor at 32 chars** — real OpenAI legacy keys are 48+, project keys 50+. `{32,}` is conservative enough to admit fixture/example values while rejecting random noise. Below ~16 chars the false-positive rate spikes (random `sk-` followed by hex IDs).
- **Anti-overlap (OpenAI vs Anthropic) verified by construction**: after `sk-`, OpenAI's regex requires alnum body. `sk-ant-` has a `-` after `ant`, breaking the body match before reaching `{32,}`. Captured as a regression test.
- **Google API key length set to exactly 35** (not `{35,}`). Real Google keys are uniformly 39 chars total (`AIza` + 35). Wider matches admit too many strings of the form `AIza...` in unrelated text.
- **GCP service-account JSON detected by canonical signature line**, not the whole JSON structure. Multi-line regex would require buffering the file across lines (the analyzer is line-oriented) and would only catch the same files anyway. The signature line `"type": "service_account"` is the universally-present marker.
- **No version bump or release tag this session.** TASK-085 is one of two intended v0.3.0 tasks (TASK-086 is the other). Cutting v0.3 with only secrets coverage but not the active-scanner expansion would force a v0.3.1 within days; better to bundle both.

**Files modified:**

- `python/analyzers/secrets.py` — module docstring updated; added 8 patterns to `_PATTERNS`; added `_ENV_PATTERNS` list and `_is_env_file()` helper; modified `_walk()` to yield env-files; modified `_scan_file()` to apply env patterns conditionally.
- `python/tests/test_secrets.py` — 10 new test methods in `TestPatternDetection`.
- `python/tests/fixtures/secrets_target/provider_tokens.py` — NEW (8 provider tokens with shape-valid fake values).
- `python/tests/fixtures/secrets_target/gcp_service_account.json` — NEW (canonical SA JSON shape).
- `python/tests/fixtures/secrets_target/.env` — NEW (unquoted KEY=value samples + comment + non-secret control).
- `CHANGELOG.md` — `[Unreleased]` section added with `Added`/`Fixed` subsections.
- `tasks/MEMORY.md` (this file) — Phase 11 progress; this Last Session Summary; "Next session" pointer reset to TASK-086.
- `tasks/CURRENT_SPRINT.md` — TASK-085 marked ✅ with concrete delta numbers.

**Build state at session end:**

- `make build` ✓ (binary built with VERSION=v0.2.0-1-gaff18ef from latest commit)
- `make test` ✓ (Go race-clean across 5 packages; Python 150/150 — was 140)
- `make e2e` ✓ (4/4 e2e regression tests, 1.9s)

**Release status carried over:**

- v0.2.0 tag is on remote but the GitHub Releases API returns 404 to unauthenticated requests (private repo). **User should manually verify** in the browser that `release.yml` ran successfully and three platform binaries are attached. If the workflow failed, fix-forward and retag.
- `gh` CLI still not installed locally. Not a v0.2 blocker.

**Next session should start with:**

1. **(Carry-over) Verify v0.2.0 release succeeded** — browser-load `https://github.com/Abdel-RahmanSaied/Fendix/releases/tag/v0.2.0` and confirm linux/amd64, darwin/amd64, darwin/arm64 binaries with sha256. Or `brew install gh && gh release view v0.2.0`.
2. **TASK-086 — Active scanner expansion (v0.3 batch with TASK-085).** Spec:
   - **Body params + headers**: `crawler.go` currently extracts only `in: query` and `in: path` parameters (TASK-081). Extend to `in: header` (skip standard auth headers) and `requestBody` content schema (extract field names from JSON schema property objects). Wire into `injection.go` so probes target body fields too — for application/json bodies, inject into one field at a time while keeping the rest valid.
   - **Error-based SQLi**: scan response body for DB error signatures (`syntax error at or near`, `ORA-00933`, `unclosed quotation mark`, `SQL syntax.*near`, etc.). Treat as HIGH confidence finding.
   - **Boolean-based SQLi**: send a `' OR 1=1--` and a `' AND 1=2--` variant; compare response-body length and status. >5% length delta or status flip = finding.
   - **SQLite + Oracle DB payloads**: add `randomblob(?)` time-based for SQLite, `dbms_pipe.receive_message` for Oracle. Existing 3 (MySQL/Postgres/MSSQL) → 5 DB types.
   - **`--max-probes-per-endpoint` flag**: replace the hardcoded `MaxProbesPerEndpoint=20` constant with a CLI flag. Default 20.
   - **e2e regression**: extend the vuln-server fixture to expose a JSON POST endpoint with a vulnerable body field; add an e2e test asserting body-param probing works.
3. After TASK-086 completes, evaluate cutting v0.3.0. If the diff is small and clean, ship. If it grew or accumulated other risks, pause for review.

**Open questions:**

- **GENERIC_API_KEY vs new provider patterns**: there's overlap potential — e.g. a line like `STRIPE_KEY = "sk_live_..."` might match both `STRIPE_LIVE_KEY` (provider) AND `GENERIC_API_KEY` (since "STRIPE_KEY" contains the key suffix and the value is in quotes 20+ chars). Currently this would emit 2 findings on the same line. TASK-088 (findings dedup, v0.4) addresses this generally; consider whether to add per-line de-dup specifically in `secrets.py` sooner. Decision deferred to TASK-088.
- **`OPENAI_API_KEY` regex breadth**: `sk-[A-Za-z0-9]{32,}` is intentionally loose to accept legacy keys, project keys (`sk-proj-`), and service-account keys (`sk-svcacct-`). It will *not* match Stripe `sk_live_...` (different separator) or Anthropic `sk-ant-...` (dash breaks alnum body). But it could conceivably hit unrelated `sk-` strings in user data. Worth considering tightening if false-positive reports come in from real codebases.
- **CHANGELOG `[Unreleased]` section** is now growing — when v0.3.0 is cut, fold it into a versioned section. Convention for the project remains Keep a Changelog.

---

## Earlier Session (2026-04-29 afternoon — release-prep & ship v0.2.0)

**Session goal:** Ship v0.2.0 — finish Phase 10 release prep, re-verify the 6 P0 bugs against the same 2026-04-28 fixtures, commit + tag + push.

**Accomplished:**

- **CHANGELOG `[0.2.0] - 2026-04-29` written** — Fixed (TASK-079/080/081/082/084), Changed (TASK-083 flagged as breaking for SARIF consumers), Added (e2e infrastructure).
- **CI e2e job added** to `.github/workflows/ci.yml`: depends on `go` + `python` jobs, sets up both toolchains, runs `make e2e`. Verified locally (1.6s, 4/4 pass).
- **Real-world re-test against 2026-04-28 fixtures** — all 6 P0 bugs confirmed gone:
  1. TASK-079 `--save-baseline` → 3119-byte baseline.json with 7 findings written (httpbin.org).
  2. TASK-080 `--code`-only → exit 0, 16 findings (6 critical + 10 high) from `/tmp/fendix-test/badcode/`. Pre-fix would have been exit 2.
  3. TASK-081 spec params → probes hit `param="host"` on `/api/v1/ping` (CMDi finding=true) and `param="url"` on `/api/v1/redirect` (CRLF finding=true). Pre-fix only `id` was probed.
  4. TASK-082 URL `--spec` → log `endpoints from spec count=5 spec=http://127.0.0.1:8765/openapi.json`.
  5. TASK-083 SARIF dedup → 11 unique rules / 41 results, all IDs of form `fendix.<category>.<title-slug>`. Pre-fix was 1:1.
  6. TASK-084 `make test` → 140/140 from repo root (verified at session start).
- **Single release commit `2ca82ce`** — 15 files, +1546/-123. Includes all Phase 10 code (was uncommitted from prior session) + this session's CHANGELOG/CI/sprint updates + `plan.md` (full v0.1→v1.0 roadmap). Conventional Commits style per MEMORY engineering standards.
- **Annotated tag `v0.2.0`** (object `acd2f32`, peels to `2ca82ce`) created locally, pushed to `origin` — `.github/workflows/release.yml` triggered automatically by the `v*` tag pattern.

**Decisions made:**

- **Single commit, not two.** Considered splitting "Phase 10 code" from "release prep", but the working tree mixed both kinds of edits in `tasks/MEMORY.md` (prior-session content + this-session content). One honest commit beat fragile interactive staging.
- **Included `plan.md` in the commit.** It's referenced from MEMORY.md as the v0.1→v1.0 roadmap source and is more than just session scratch.
- **Conventional Commits style preserved** — recent log mixes styles, but MEMORY.md mandates `feat:`/`fix:`/etc. The commit follows that.
- **Tag v0.2.0 was pushed without first watching CI on the commit.** Reasoning: (a) CI was green locally across all suites, (b) the release workflow is independent of `ci.yml` (triggers on `v*`, not on push to main), (c) the release builds linux/darwin separately and includes a sha256 step that would surface any cross-compile breakage. If CI on `main` fails, that's a separate fix-forward, not a release blocker.
- **`gh` CLI not installed locally** — couldn't watch the Actions runs from here. Verified via `git ls-remote --tags origin` that the tag landed; release artifacts will be visible at the GitHub Releases page when `release.yml` finishes.

**Files modified this session (delta on top of 2ca82ce post-commit):**

- `tasks/MEMORY.md` — Phase 10 release section closed out; this Last Session Summary; "Next session" pointer reset to TASK-085.
- `tasks/CURRENT_SPRINT.md` — Phase 10 marked complete with shipped state; new Phase 11 sprint table starting with TASK-085.
- `tasks/PHASES.md` — Phase 10 status `🟢 Code Complete` → `✅ Complete`; Phase 11 → `🔄 In Progress`.

**Files committed in `2ca82ce`:**

- `.github/workflows/ci.yml` — added `e2e` job
- `CHANGELOG.md` — `[0.2.0] - 2026-04-29` entry
- `Makefile`, `go/cmd/fendix/main.go`, `go/internal/engine/orchestrator.go`, `go/internal/reporters/sarif.go`, `go/internal/reporters/sarif_test.go`, `go/internal/scanner/crawler.go`, `go/internal/scanner/crawler_test.go`, `python/tests/test_self_audit.py` — Phase 10 code (TASK-079..084)
- `go/internal/e2e/e2e_test.go` — NEW e2e infrastructure
- `plan.md` — NEW v0.1→v1.0 roadmap (from 2026-04-28 session)
- `tasks/MEMORY.md`, `tasks/CURRENT_SPRINT.md`, `tasks/PHASES.md` — sprint state

**Build state at session end:**

- `make build` ✓
- `make test` ✓ (Go race-clean across 5 packages; Python 140/140)
- `make e2e` ✓ (4/4 regression tests, 1.6s)
- Local commit `2ca82ce` matches `origin/main`; tag `v0.2.0` matches `origin/v0.2.0`.

**Next session should start with:**

1. **Verify the v0.2.0 release succeeded** — load the GitHub Releases page (or `gh release view v0.2.0` once installed). Confirm linux/amd64, darwin/amd64, darwin/arm64 binaries published with sha256 checksums. If `release.yml` failed, fix-forward (likely cross-compile or embed-engine issue) and retag (`git tag -d v0.2.0 && git push origin :refs/tags/v0.2.0 && retag`). If it passed, consider sanity-testing one of the published binaries on the host platform (`darwin/arm64`).
2. **Begin Phase 11 — TASK-085: expand secret patterns + fix `.env` unquoted-value scanning.** This is the single highest-visibility coverage gap. Spec:
   - **Add patterns** to `python/analyzers/secrets.py`: GitHub PAT (`ghp_[A-Za-z0-9]{36}`), Stripe live (`sk_live_[A-Za-z0-9]{24,}`), Slack tokens (`xoxb-`/`xoxp-`/`xoxa-`), Google API key (`AIza[0-9A-Za-z\-_]{35}`), Anthropic (`sk-ant-`), OpenAI (`sk-[A-Za-z0-9]{48}`), npm (`npm_[A-Za-z0-9]{36}`), GCP service-account JSON (`"type":\s*"service_account"` near `"private_key"`).
   - **Fix `.env` scanning** — the existing `HARDCODED_PASSWORD` regex requires quoted values; `.env` uses unquoted `KEY=value`. Either add a separate `.env`-specific pattern or relax the regex when filename ends in `.env*`.
   - **Add fixtures** under `python/tests/fixtures/secrets/` — one file per pattern type, including obvious-fake values that match the regex but are clearly not real keys.
   - **Tests** in `python/tests/test_secrets.py` — assert each new pattern fires on the corresponding fixture, plus a no-false-positive test on the existing benign fixtures.
   - **Re-test against `/tmp/fendix-test/badcode/`** — the prior session's badcode fixture has 10 secret types; current build catches some but not all. After TASK-085, count should jump.
3. After TASK-085, evaluate whether to ship v0.3.0 immediately or batch with TASK-086 (active-scanner expansion). Per `tasks/PHASES.md`: v0.3 = TASK-085+086, v0.4 = TASK-087..091.

**Open questions:**

- The release pipeline currently builds for linux/amd64 + darwin/amd64 + darwin/arm64 only. Should `linux/arm64` (common on cloud runners) be added in v0.3 or wait until TASK-099 (Phase 13 reproducible release pipeline)? Worth raising before publishing v0.3.
- `gh` CLI is missing on this machine. Worth installing via Homebrew so future release-watch loops don't require browser context-switching. Not a v0.2 blocker.
- The `release.yml` workflow uses `softprops/action-gh-release` — recent versions auto-generate release notes from commit messages. Should be fine since `2ca82ce`'s body is already release-note quality, but if the resulting GitHub Release page is poorly formatted, hand-edit it once after the workflow completes.

---

## Earlier Session (2026-04-29 — Phase 10 code)

Kept for traceability. Goal was to fix all 6 P0 broken-flag bugs from the 2026-04-28 real-world test pass.

**Accomplished:**

- **All 6 Phase 10 P0 tasks complete** (TASK-079 through TASK-084). Details in "Completed tasks — Phase 10" above.
- **New e2e test infrastructure** (`go/internal/e2e/`, `make e2e`) — closes the bug class where unit tests pass but the CLI flag is unreachable. Gated behind `//go:build e2e` so it doesn't slow down normal `go test ./...`. 4 regression tests committed: `TestSaveBaseline_WritesFile`, `TestCodeOnlyScan_ProducesFindings`, `TestActiveProbe_UsesSpecParam`, `TestSpecURL_FetchedAndParsed`.
- All builds green: Go race-clean, 140/140 Python tests, 4/4 e2e tests, full reporter and scanner unit suites.

**Decisions made:**

- **e2e tests live inside the Go module** at `go/internal/e2e/` rather than at repo root `tests/e2e/`. Reasons: (1) keeps everything in a single Go module — no separate `go.mod` to maintain; (2) consistent with `auth_integration_test.go` which is also in-module; (3) `//go:build e2e` is the standard Go pattern for opt-in test suites.
- **TASK-081 scope**: implemented query + path params only. Body params deferred to TASK-086 (Phase 11) per plan. Headers explicitly skipped — they're not currently exposed to the active scanner. `$ref` parameter entries are skipped (not resolved); deref is out of scope for v0.2.
- **TASK-082 format detection layering**: URL suffix → HTTP Content-Type → first-byte sniff. This handles real-world specs published at extension-less URLs (`/openapi`, `/spec`).
- **TASK-083 rule ID format**: `fendix.<category>.<title-slug>`. Opaque to consumers but human-readable, deterministic, and stable across runs (so suppression baselines work). The per-finding `SEC-NNN` stays in JSON output but is now a finding-instance ID, not a rule ID.
- **TASK-084 belt-and-suspenders fix**: corrected the Makefile (the documented intent) AND hardened the test (defensive against any future cwd drift). The test fix doesn't have its own task — it's a small additional change inside TASK-084's scope, captured in this summary.
- **`make e2e` always builds first** — naive `go test -tags e2e` would skip the Python engine embedding step in `make build`, and the `--code` and `--spec`-style scans would fail at runtime. The Makefile target ordering avoids that footgun.

**Files created/modified:**

- `go/cmd/fendix/main.go` — TASK-079: read `--save-baseline` flag, assign to `cfg.SaveBaselinePath`
- `go/internal/engine/orchestrator.go` — TASK-080: reorder no-endpoints guard
- `go/internal/scanner/crawler.go` — TASK-081 + TASK-082: `loadSpec`/`fetchSpec`/`looksLikeJSON`/`extractParamsList`/`mergeParams` helpers; `fromSpec` rewritten to use them
- `go/internal/scanner/crawler_test.go` — TASK-081/082: 6 new unit tests
- `go/internal/reporters/sarif.go` — TASK-083: `ruleKeyFor`/`slug` helpers, dedup key change in `RenderSARIF`
- `go/internal/reporters/sarif_test.go` — TASK-083: new `TestRenderSARIF_RulesDedupedByCheckType`
- `go/internal/e2e/e2e_test.go` — NEW: 4 e2e regression tests + shared `fendixBinary`/`mockTarget`/`contains` helpers
- `Makefile` — TASK-084: drop cwd shift in `test-python`; new `e2e` target
- `python/tests/test_self_audit.py` — TASK-084: cwd-agnostic via `REPO_ROOT = Path(__file__).resolve().parents[2]`
- `tasks/MEMORY.md`, `tasks/CURRENT_SPRINT.md`, `tasks/PHASES.md` — sprint status updates

**Build state at session end:**

- `make build` ✓
- `make test` ✓ (Go race-clean across 5 packages; Python 140/140)
- `make e2e` ✓ (4/4 regression tests)

**Next session should start with:**

1. Phase 10 release prep:
   - Add `[Unreleased] → [0.2.0] - 2026-04-29` entry in CHANGELOG.md listing the 6 fixes (one bullet each, link the task IDs).
   - Wire `make e2e` into `.github/workflows/ci.yml` so the regression tests gate every PR.
   - Tag `v0.2.0` and push.
   - Optional: re-run the 2026-04-28 real-world test pass against the new build to confirm all 6 bugs are gone (use the `/tmp/fendix-test/vuln_server.py` and `/tmp/fendix-test/badcode/` fixtures from the prior session, recreate from MEMORY notes if cleaned).
2. Then start Phase 11 P1 — pick **TASK-085 (expand secret patterns + fix .env unquoted-value scanning)** first; it's the highest-visibility coverage gap (every external evaluator compares against gitleaks). See `tasks/PHASES.md` Phase 11 for the full task list.

**Open questions:**

- Should `--save-baseline` and `--baseline` be combinable in a single run (save the post-diff result)? Currently they are — the orchestrator runs `ApplyBaselineDiff` (step 9) before `SaveBaseline` (step 10), so a baseline run with both flags writes the diffed list, not the full set. Worth documenting explicitly; might be surprising. Defer to Phase 12 schema-cleanup task TASK-092.
- The new SARIF rule IDs are not backwards-compatible with v0.1.0 SARIF outputs — anyone who already consumed v0.1 SARIF in a baseline file will see all "new" rules in v0.2. Note this in the v0.2.0 CHANGELOG as a breaking change.

---

## Previous Session Summary (2026-04-28 — real-world evaluation)

Kept for traceability since Phase 10 work directly references the bugs found here.

**Accomplished:**

- Built `bin/fendix` from commit `5a8e299` cleanly (`make build` works; embedded Python engine extracts to `~/.fendix/engine`).
- Ran existing test suite: 33 Go test files race-clean, 138/140 Python tests pass; 2 false failures traced to a Makefile `cd python/` cwd bug (paths in `test_self_audit.py` are relative to repo root).
- Exercised black-box, white-box, hybrid, and active scans against real targets:
  - `httpbin.org` (live)
  - `petstore3.swagger.io` (live + 13-path OpenAPI 3 spec)
  - GitHub's 12 MB OpenAPI spec (parsed only — 1145 endpoints discovered ✓)
  - Custom Swagger 2.0 sample (parsed ✓)
  - Local deliberately-vulnerable test server at `/tmp/fendix-test/vuln_server.py` covering SQLi, command injection, CRLF, exposed secrets, weak auth
  - Local deliberately-bad Python codebase at `/tmp/fendix-test/badcode/` covering 10 secret types, multiple injection patterns, EOL deps
- Identified 6 P0 bugs (broken user-facing flags) + 7 P1 coverage gaps + ~14 P2/P3 items.
- Wrote `plan.md` in repo root summarizing the full v0.1 → v1.0 plan with file refs, acceptance criteria, effort estimates.
- Created Phases 10-13 in `tasks/PHASES.md` (TASK-079 through TASK-104).
- Reset `tasks/CURRENT_SPRINT.md` to active Phase 10 sprint with task table, DoD, and real-world evidence inline per task.

**P0 bugs found (now Phase 10 in PHASES.md):**

1. **`--save-baseline` is dead code at the CLI** — flag declared at `go/cmd/fendix/main.go:150`, never read; `cfg.SaveBaselinePath` always empty; orchestrator path exists but unreachable. Unit test at `baseline_test.go:156` passes because it tests `SaveBaseline()` directly — masks the CLI gap. → TASK-079.
2. **`--code`-only scans refuse to run** — `orchestrator.go:61-63` early-exits on "no endpoints discovered" before the white-box branch at line 95 can run. → TASK-080.
3. **Active scanner ignores spec-defined query parameters** — `crawler.go:340 extractPathParams` only handles path `{id}`; OpenAPI `parameters: [{name, in: query}]` dropped. Active scanner falls back to hardcoded `"id"` for every endpoint, so all probes miss when the real vuln param is anything else (`host`, `url`, `username`, etc.). Confirmed broken on the vuln-server fixture. → TASK-081.
4. **`--spec` won't accept a URL** — `--spec http://host/openapi.json` silently fails with "no such file" and falls back to brute-force. Many real services publish specs at `/openapi.json`. → TASK-082.
5. **SARIF generates 1 rule per finding** — 160 findings → 160 unique rule IDs (`SEC-001`..`SEC-160`). GitHub Code Scanning groups by `ruleId`, so the same vuln across 21 endpoints scatters into 21 distinct "rules". Should be 1 rule per check type. → TASK-083.
6. **`make test` fails from clean checkout** — `cd python/ && pytest` breaks `test_self_audit.py`. Fix is a one-line Makefile change. → TASK-084.

**Coverage gaps observed (Phase 11):**

- Secrets analyzer has only 7 patterns; **misses GitHub PAT (`ghp_`), Stripe live (`sk_live_`), Slack, Google API keys, Anthropic, OpenAI, npm, GCP service-account JSON**. Standard scanners (gitleaks, trufflehog) ship 100+.
- `.env` files are scanned (extension is in the list) but the `HARDCODED_PASSWORD` regex requires quoted values; `.env` uses unquoted `KEY=value` — so values never match.
- Static SQLi catches f-strings; **misses `"sql " + var` string-concat** (the original Bobby Tables pattern).
- No static checks for: `pickle.loads`, weak crypto for passwords (md5/sha1), open redirects, auth-header-trust anti-patterns, SSRF.
- Active SQLi: only 3 time-based payloads (MySQL `SLEEP`, Postgres `pg_sleep`, MSSQL `WAITFOR`). No SQLite, Oracle, error-based, or boolean-based.
- Crawler wordlist is 50 paths, API-prefix biased (httpbin's root paths only got `/robots.txt` discovered).
- **No deduplication** — same "missing CSP" reported 21× across endpoints.
- **No correlated findings** appeared in any hybrid run, despite both engines firing on overlapping endpoints.
- Dependency CVE list is a hardcoded ~10-package fallback when `pip-audit` is absent.

**What worked well (validates v0.1 architecture):**

- Spec parser handles OpenAPI 3, Swagger 2, AND a 12 MB GitHub spec without issue (1145 endpoints).
- Static analyzers caught: AWS keys, JWT, RSA private key, DB connection strings, generic API keys, f-string SQLi, `subprocess(shell=True)`, `os.system()`, all 6 EOL deps with real CVE IDs.
- Data-exposure check correctly flagged exposed `password` and `api_key` in API response as CRITICAL with masked evidence — best result of the run.
- HTML report renders cleanly (185 KB self-contained, dark theme).
- Ignore rules suppress correctly with audit log.
- `--fail-on` exit codes work as documented.

**Decisions made:**

- Plan structured into Phases 10-13 mapped to releases v0.2 / v0.3 / v0.4 / v0.5 / v1.0.
- ~11 weeks of focused work to v1.0 (one developer FT).
- v0.2 is the milestone that unblocks "evaluation by external users" — without it, the very first thing a reviewer tries (`--save-baseline` for CI gate, or `--code` for SAST-only) breaks silently.
- Cross-cutting recommendation: end-to-end tests over unit tests. The `--save-baseline` bug had passing unit tests. Going forward, every CLI flag needs a test that runs the binary and asserts observable effect.
- Cross-cutting recommendation: rule registry as a first-class concept — fixes SARIF, simplifies ignore rules, enables auto-generated "what does fendix detect" docs.

**Files created/modified:**

- `plan.md` — NEW: full v0.1 → v1.0 production-readiness plan in repo root
- `tasks/PHASES.md` — MODIFIED: added Phases 10-13 (P0/P1/P2/P3) with goals, exit criteria, task IDs TASK-079 through TASK-104; updated overview table
- `tasks/CURRENT_SPRINT.md` — REPLACED: now tracks Phase 10 sprint with task table, DoD, real-world evidence per task, and Phase 11 preview
- `tasks/MEMORY.md` — MODIFIED: Current Project State updated to Phase 10; new Pending Tasks sections for Phases 10-13; this Last Session Summary

**Test fixtures created (not committed; useful to revisit):**

- `/tmp/fendix-test/vuln_server.py` — deliberately vulnerable HTTP server (SQLi via sqlite, cmdi via shell=True, CRLF in Location header, exposed secrets in `/api/v1/me`, OpenAPI spec at `/openapi.json`). Use it as the e2e test target for Phase 10/11 work.
- `/tmp/fendix-test/badcode/` — Python codebase with 10 secret patterns (handles AWS/JWT/RSA/Stripe/GitHub/DB conn/passwords), multiple injection patterns, weak crypto, and EOL deps in `requirements.txt`.

**Next session should start with:**

1. Read `tasks/CURRENT_SPRINT.md` for the task list.
2. Pick TASK-084 first (Makefile fix, ~15 min) — gets `make test` passing on clean checkouts and unblocks CI changes.
3. Then TASK-079 (`--save-baseline` wiring, ~30 min) and TASK-082 (URL `--spec`, ~1 hr) — both are small and high-value.
4. TASK-080 (`--code`-only) and TASK-081 (spec params → `Endpoint.Params`) need small architectural thought; TASK-083 (SARIF rule registry) is the largest.
5. Before starting, create `tests/e2e/` with at least one example e2e test that runs `bin/fendix` and asserts an externally-observable effect — this is the cross-cutting investment that prevents the next "passing unit test, broken CLI" surprise.

**Open questions:**

- Should TASK-081 also enable probing on body parameters (JSON request bodies) in this sprint, or defer that to TASK-086 (Phase 11)? Recommendation: defer body params to Phase 11 — keep Phase 10 focused on flag wiring, not new feature surface.
- The 12 MB GitHub spec parses to 1145 endpoints. Should there be a default upper bound on endpoint count (with a `--max-endpoints` flag) to prevent accidental scans of very large APIs? Worth raising during Phase 12 (TASK-095 scan budgets).

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
