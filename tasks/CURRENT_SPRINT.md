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

## This Sprint's Tasks

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-028 | engine.py entrypoint and IPC contract | 🔲 | |
| TASK-029 | Secrets analyzer with 7 pattern types + tests | 🔲 | |
| TASK-030 | OpenAPI spec parser (2.0 + 3.x) + tests | 🔲 | |
| TASK-031 | Semgrep rules: auth.yaml (4 rules) | 🔲 | |
| TASK-032 | Semgrep rules: injection.yaml (3 rules) | 🔲 | |
| TASK-033 | Semgrep rules: secrets.yaml (2 rules) | 🔲 | |
| TASK-034 | Semgrep runner + result mapping | 🔲 | |
| TASK-035 | AST analyzer (Python + JS basic patterns) | 🔲 | |
| TASK-036 | Dependency CVE checker (PyPI + npm) | 🔲 | |
| TASK-037 | Performance test: engine startup and scan time | 🔲 | |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Definition of Done for This Sprint

- [ ] engine.py reads stdin ScanRequest, streams Findings, emits {"done":true}
- [ ] Secrets analyzer detects all 7 pattern types
- [ ] OpenAPI 2.0 + 3.x spec parsing with auth checks
- [ ] Semgrep rules for auth, injection, secrets
- [ ] Semgrep runner executes rules and maps results
- [ ] AST analyzer for Python + JS patterns
- [ ] Dependency CVE checker
- [ ] Engine startup < 2 seconds
- [ ] `go build ./...` passes
- [ ] `go test ./...` passes
- [ ] `python -m pytest` passes
