# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 0 — Foundation

**Sprint goal:** Compilable skeleton with all models, CI running, `fendix version` works.

---

## This Sprint's Tasks

| ID | Task | Status | Notes |
|---|---|---|---|
| TASK-001 | Initialize Go module and directory structure | ✅ | Go module + all dirs |
| TASK-002 | Initialize Python package structure | ✅ | engine.py + analyzers + tests |
| TASK-003 | Finding model (Go) with JSON serialization | ✅ | 3 JSON tests |
| TASK-004 | ScanConfig model (Go) | ✅ | AuthContext + ScanConfig |
| TASK-005 | Severity scoring with table-driven tests | ✅ | 25 test cases |
| TASK-006 | cobra CLI skeleton + version command | ✅ | 4 commands, 17 flags |
| TASK-007 | GitHub Actions CI workflow | ✅ | Go + Python jobs |
| TASK-008 | Makefile | ✅ | build, test, lint, clean |
| TASK-009 | ADR-001: Go+Python hybrid decision | ✅ | docs/adr/ |
| TASK-010 | ADR-002: Newline-delimited JSON IPC | ✅ | docs/adr/ | |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Definition of Done for This Sprint

- [x] `make build` succeeds
- [x] `make test` passes (go test ./... + pytest)
- [ ] `make lint` passes (gofmt + golint + ruff + black)
- [x] `fendix version` prints version string
- [ ] GitHub Actions CI runs green on push (needs repo + push)
- [x] ADR-001 and ADR-002 written
