# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 9 — Hardening ✅ Complete

**Sprint goal:** Production-ready. Edge cases handled. Performance validated. Security of the tool itself reviewed.

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

## This Sprint's Tasks (Phase 8 — COMPLETE ✅)

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-065 | Write README.md (all 10 sections) | ✅ | Already complete from prior session; verified all 10 sections present |
| TASK-066 | Write CONTRIBUTING.md | ✅ | Dev setup, check examples (Go/Python/Semgrep), coding standards, IPC contract, PR process |
| TASK-067 | Write docs/checks/ — one page per check | ✅ | 11 check docs: headers, cors, auth, exposure, ratelimit, injection, secrets, semgrep, spec-parser, ast-analyzer, deps |
| TASK-068 | Complete all ADRs | ✅ | 4 new ADRs (003-006): severity scoring, active probe safety, embedded engine, report formats; total 6 |
| TASK-069 | Write CHANGELOG.md | ✅ | Keep a Changelog format; all features under [Unreleased] |
| TASK-070 | Audit all godoc comments (Go) | ✅ | 92 exported symbols verified; 0 missing |
| TASK-071 | Audit all docstrings (Python) | ✅ | 16 public symbols; 1 missing fixed (emit_finding); 0 missing |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Definition of Done for Phase 8 (ACHIEVED ✅)

- [x] README.md complete (all 10 sections)
- [x] `docs/adr/` — all architectural decisions documented (6 ADRs)
- [x] `docs/checks/` — one page per check (11 files)
- [x] `CONTRIBUTING.md` — how to add a new check, development setup
- [x] `CHANGELOG.md` — maintained from first release
- [x] All Go exported symbols have godoc comments (92/92)
- [x] All Python public functions have docstrings (16/16)
- [x] `go build ./...` passes
- [x] `go test ./...` passes (385 tests)
- [x] `python -m pytest` passes (130 tests)

---

## This Sprint's Tasks (Phase 9 — COMPLETE ✅)

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-072 | Write performance benchmark suite | ✅ | readFindings, Correlate, normalizeEndpoint, CalculateSeverity, RenderJSON/HTML/SARIF benchmarks with -benchmem |
| TASK-073 | Fuzz test Finding JSON parser | ✅ | Go native fuzzing; FuzzReadFindings (362k+ execs), FuzzNormalizeEndpoint (204k+ execs); 0 panics |
| TASK-074 | Fuzz test OpenAPI spec parser | ✅ | Python hypothesis; 8 fuzz tests; found+fixed 3 real bugs (_parse_file None, paths type, components type) |
| TASK-075 | Self-audit: run Fendix against Fendix codebase | ✅ | 17 findings all from test fixtures; 0 production vulnerabilities; automated self-audit test |
| TASK-076 | Resilience testing | ✅ | 12 scanner + 17 engine tests: garbage, timeout, cancel, conn refused, invalid URL, slow drip, malformed streams |
| TASK-077 | Memory profiling on large scan simulation | ✅ | 2000 findings: 2.3KB/finding; 1000 correlation: 15MB; all under budget |
| TASK-078 | Audit all error messages for actionability | ✅ | 7 messages improved with "what to do" guidance |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Definition of Done for Phase 9 (ACHIEVED ✅)

- [x] Performance benchmarks: readFindings 4ms/1000, CalculateSeverity 27ns, RenderJSON 2.4ms/1000
- [x] Python engine startup < 2 seconds (verified in Phase 3)
- [x] Fuzz testing on Finding JSON parser — 362k+ executions, 0 panics
- [x] Fuzz testing on OpenAPI spec parser — 3 real bugs found and fixed
- [x] Self-audit: Fendix against itself — 0 production vulnerabilities
- [x] Malformed responses handled without panic (12 scanner resilience tests)
- [x] Network timeouts handled without hanging (timeout + context cancel tests)
- [x] Python engine crash handled without crashing Go binary (verified in spawner tests)
- [x] Memory profiled for large scans: 2.3KB/finding, 15MB/1000 correlations
- [x] All error messages are actionable (7 improved)
- [x] `go build ./...` passes
- [x] `go test ./...` passes (~454 tests)
- [x] `python -m pytest` passes (140 tests)

---

## All Phases Complete 🎉

All 9 phases and 78 tasks are done.

### v0.1.0 Release Prep ✅

| Item | Status | Notes |
|---|---|---|
| LICENSE file (MIT) | ✅ | Was missing — created |
| .fendix-ignore.example | ✅ | Was missing (referenced in README) — created with all rule types |
| CHANGELOG.md versioned | ✅ | [Unreleased] → [0.1.0] - 2026-04-11 |
| Version updated to 0.1.0 | ✅ | MEMORY.md updated |
| Build green | ✅ | Go build + tests, Python 140 tests |

**Ready for:** `git tag -a v0.1.0 -m "Fendix v0.1.0 — initial release"` and push.
