# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 5 — Active Scanner (next)

**Sprint goal:** Implement optional injection probing — SQL injection, command injection, header injection. Off by default, requires `--enable-active`.

---

## Previous Sprint (Phase 3 — Python Engine) ✅ Complete

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

---

## This Sprint's Tasks (Phase 4 — COMPLETE ✅)

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-038 | Subprocess spawner with stdin/stdout wiring | ✅ | PythonSpawner, ScanRequest, mock engine tests, 19 tests |
| TASK-039 | Streaming Finding reader (Go side) | ✅ | readFindings() with malformed skip, field validation, 8 reader tests |
| TASK-040 | Correlator with endpoint normalization | ✅ | Fuzzy endpoint match, category mapping, severity escalation, 14 tests |
| TASK-041 | Sequential ID assignment (SEC-001...) | ✅ | Verified existing in orchestrator |
| TASK-042 | .fendix-ignore suppression parser | ✅ | YAML, ID/endpoint/category/glob, expiry dates, 15 tests |
| TASK-043 | Baseline diff comparison | ✅ | title+endpoint+category key, JSONReport format, 11 tests |
| TASK-044 | --fail-on exit code logic | ✅ | Verified existing in orchestrator |
| TASK-045 | End-to-end integration test: hybrid scan | ✅ | Mock engine, ignore, baseline, 3 integration tests |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Next Sprint: Phase 5 — Active Scanner

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-046 | Safe probe framework with audit logging | 🔲 | --enable-active gate, probe audit log |
| TASK-047 | Time-based SQLi detection (3 DB types) | 🔲 | MySQL, Postgres, MSSQL payloads |
| TASK-048 | CMDi canary detection | 🔲 | Echo canary, no destructive payloads |
| TASK-049 | CRLF header injection detection | 🔲 | Header injection via CRLF |
| TASK-050 | Per-endpoint probe rate limiter | 🔲 | Max probes per endpoint |
| TASK-051 | Tests: active probes against vulnerable mock server | 🔲 | Deliberately vulnerable endpoints |

## Definition of Done for Phase 4 (ACHIEVED ✅)

- [x] Orchestrator spawns Python engine as subprocess
- [x] Stdin/stdout IPC working end-to-end
- [x] Go collects streaming findings from Python
- [x] Correlator merges matching black-box + white-box findings
- [x] Correlated findings have elevated confidence
- [x] Unconfirmed white-box findings marked MEDIUM confidence
- [x] Sequential ID assignment (SEC-001, SEC-002...)
- [x] `.fendix-ignore` suppression file working
- [x] Baseline diff mode working (`--baseline`, `--save-baseline`)
- [x] `--fail-on` exit code logic working (for CI/CD)
- [x] `go build ./...` passes
- [x] `go test ./...` passes (179 tests)
- [x] `python -m pytest` passes (130 tests)
