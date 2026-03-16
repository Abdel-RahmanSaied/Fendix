# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 3 — Python Engine

**Sprint goal:** Build a standalone Python static analysis engine that reads ScanRequest from stdin and streams Finding JSON to stdout.

---

## Previous Sprint (Phase 2 — Auth Scanner) ✅ Complete

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-021 | AuthContext model and multi-source resolution | ✅ | 4 auth types, auto-detect, flag→env→profile, 30 tests |
| TASK-022 | Unauthenticated access check | ✅ | CRITICAL if 200 without auth, 3 tests |
| TASK-023 | JWT validation bypass checks (3 scenarios) | ✅ | Malformed, expired, alg:none — all CRITICAL, 8 tests |
| TASK-024 | IDOR two-account check | ✅ | --auth-user2, response comparison, 5 tests |
| TASK-025 | Credential masking in all reporters | ✅ | SanitizeFindings, 7 tests |
| TASK-026 | ~/.fendix/profiles/ config system | ✅ | YAML profiles, ProfileLoader, 8 tests |
| TASK-027 | Tests: auth checks against mock JWT server | ✅ | Realistic JWT validator, 5 integration tests |

---

## This Sprint's Tasks (Phase 3 — COMPLETE ✅)

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-028 | engine.py entrypoint and IPC contract | ✅ | All 5 checks, stderr logging, error isolation, 8 tests |
| TASK-029 | Secrets analyzer with 7 pattern types + tests | ✅ | AWS key/secret, PEM, API key, password, JWT, DB conn string; 24 tests |
| TASK-030 | OpenAPI spec parser (2.0 + 3.x) + tests | ✅ | 4 auth checks, 6 YAML fixtures, 18 tests |
| TASK-031 | Semgrep rules: auth.yaml (4 rules) | ✅ | Flask, Django, FastAPI, jwt.decode |
| TASK-032 | Semgrep rules: injection.yaml (3 rules) | ✅ | SQL %, subprocess shell=True, eval/exec |
| TASK-033 | Semgrep rules: secrets.yaml (2 rules) | ✅ | Hardcoded assignment, DB URL |
| TASK-034 | Semgrep runner + result mapping | ✅ | Mocked subprocess, graceful fallback, 20 tests |
| TASK-035 | AST analyzer (Python + JS basic patterns) | ✅ | Python ast + JS heuristics, 21 tests |
| TASK-036 | Dependency CVE checker (PyPI + npm) | ✅ | Local vuln list + pip-audit/npm-audit, 32 tests |
| TASK-037 | Performance test: engine startup and scan time | ✅ | Startup < 2s measured, 7 tests |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Next Sprint: Phase 4 — Orchestration & Correlation

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-038 | Subprocess spawner with stdin/stdout wiring | 🔲 | Go spawns python/engine.py |
| TASK-039 | Streaming Finding reader (Go side) | 🔲 | Read JSON lines from Python stdout |
| TASK-040 | Correlator with endpoint normalization | 🔲 | Cross-reference black+white findings |
| TASK-041 | Sequential ID assignment (SEC-001...) | 🔲 | Deterministic ordering |
| TASK-042 | .fendix-ignore suppression parser | 🔲 | Suppress by rule/path/endpoint |
| TASK-043 | Baseline diff comparison | 🔲 | --baseline / --save-baseline |
| TASK-044 | --fail-on exit code logic | 🔲 | Exit 1 if findings at threshold |
| TASK-045 | End-to-end integration test: hybrid scan | 🔲 | Fixture project, correlated findings |

## Definition of Done for Phase 3 (ACHIEVED ✅)

- [x] engine.py reads stdin ScanRequest, streams Findings, emits {"done":true}
- [x] Secrets analyzer detects all 7 pattern types
- [x] OpenAPI 2.0 + 3.x spec parsing with auth checks
- [x] Semgrep rules for auth, injection, secrets
- [x] Semgrep runner executes rules and maps results
- [x] AST analyzer for Python + JS patterns
- [x] Dependency CVE checker
- [x] Engine startup < 2 seconds (measured)
- [x] `go build ./...` passes
- [x] `go test ./...` passes (202 tests)
- [x] `python -m pytest` passes (130 tests)
