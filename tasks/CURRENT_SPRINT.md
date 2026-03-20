# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 5 — Active Scanner ✅ Complete

**Sprint goal:** Implement optional injection probing — SQL injection, command injection, header injection. Off by default, requires `--enable-active`.

---

## Previous Sprint (Phase 4 — Orchestration & Correlation) ✅ Complete

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

---

## This Sprint's Tasks (Phase 5 — COMPLETE ✅)

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-046 | Safe probe framework with audit logging | ✅ | ProbeAuditLog, ProbeRecord, PrintDisclaimer, --enable-active gate, wired into orchestrator |
| TASK-047 | Time-based SQLi detection (3 DB types) | ✅ | MySQL SLEEP, Postgres pg_sleep, MSSQL WAITFOR; baseline+4s threshold; confirmation probe for HIGH confidence |
| TASK-048 | CMDi canary detection | ✅ | Safe echo payload, canary reflection detection in response body |
| TASK-049 | CRLF header injection detection | ✅ | %0d%0a Set-Cookie injection, cookie reflection check |
| TASK-050 | Per-endpoint probe rate limiter | ✅ | MaxProbesPerEndpoint=20, checked before every probe via audit log count |
| TASK-051 | Tests: active probes against vulnerable mock server | ✅ | 22 tests: vulnerable server, safe server, multi-param, auth propagation, context cancellation |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Definition of Done for Phase 5 (ACHIEVED ✅)

- [x] `--enable-active` flag gates all active probes
- [x] Time-based SQLi detection (MySQL, Postgres, MSSQL payloads)
- [x] Baseline response time measurement (3-sample median)
- [x] Safe CMDi detection (echo canary, no destructive payloads)
- [x] CRLF header injection detection
- [x] Max probe limit per endpoint enforced (20)
- [x] Full audit log of every probe sent
- [x] Legal disclaimer printed when `--enable-active` used
- [x] `go build ./...` passes
- [x] `go test ./...` passes (201 tests)
- [x] `python -m pytest` passes (130 tests)

---

## Next Sprint: Phase 6 — Reporting

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-052 | Finalize JSON reporter with full metadata schema | 🔲 | |
| TASK-053 | Finalize HTML reporter with sorting, expand/collapse, print CSS | 🔲 | |
| TASK-054 | Implement SARIF 2.1.0 reporter | 🔲 | |
| TASK-055 | Validate SARIF output against official schema | 🔲 | |
| TASK-056 | Implement fendix report re-render command | 🔲 | |
| TASK-057 | Add GitHub Actions example workflow to docs | 🔲 | |
