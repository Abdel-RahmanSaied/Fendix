# Code Review — Fendix v0.20
Reviewed by: Reviewer Agent
Date: 2026-06-28

## Exit criteria: **PASS**

> Roadmap: *"Baseline numbers exist. Every future change compares against them."*

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `benchmarks/baselines/baseline.json` exists with real numbers | ✅ | dvwa TP=13/FP=0 (recall 100%), juiceshop TP=12/FP=5 (recall 100%) — live Docker run, fully triaged |
| `metrics/events.jsonl` written during scans (opt-in) | ✅ | Functional run with `FENDIX_METRICS=true` produced structural events; `metrics show` summarized |
| `tests/regression/snapshots/` committed | ✅ | `simple-go-project.snap`, `simple-python-project.snap` |
| CI runs benchmark + regression | ✅ | `baseline.yml` (delta gate, dispatch/tags) + `ci.yml` `go test ./...` (regression/smoke) |
| `fendix benchmark run` works end-to-end | ✅ | Ran live against DVWA + Juice Shop |
| `fendix metrics show` works end-to-end | ✅ | Verified |

## Product Constitution: **PASS**

| Rule | Status | Note |
|------|--------|------|
| 1 — Never rewrite working systems | ✅ | Orchestrator only *extended* (~25-line hook + helper); no scan logic touched. `baseline.yml` is additive (existing `benchmark.yml`/`heavy-eval.yml`/`scripts/` untouched); `ci.yml` got a comment only |
| 2 — Trust before features | ✅ | v0.20 added zero user-facing features — measurement infra only |
| 3 — Every finding has evidence | ➖ | N/A (Evidence model is v0.22) |
| 4 — Every decision explainable | ✅ | Regression logic is deterministic + per-metric reported; `compare` prints each regressing delta |
| 5 — Benchmark before marketing | ✅ | Honest baseline; triage surfaced a real FP bug rather than hiding it |
| 6 — Performance regressions are bugs | ✅ | `performance_test.go` gates <30s / <500MB in CI |
| 7 — Backward compatibility | ✅ | CLI output unchanged (metrics off by default → no stdout change; smoke tests confirm json/sarif still valid); no existing flags changed; new subcommands are additive |
| 8 — AI assists, never decides | ➖ | N/A to v0.20 |
| 9 — Developer experience first-class | ✅ | `tests/README.md` clear; new errors wrapped with context; `metrics show` friendly on empty |
| 10 — Optimize for engineering time saved | ✅ | Reused existing eval infra rather than duplicating; avoided a redundant CI job; dashboard is functional, not vanity |

## Code-quality spot check
- **Error handling:** `fmt.Errorf("…: %w", err)` wrapping throughout; **no `_ =` on error returns** (metrics record/flush failures log at DEBUG, never swallowed).
- **Context propagation:** `Scan`/`Run`/`waitForHTTP` take and honor `context.Context`.
- **Godoc:** every exported symbol documented.
- **Tests:** new packages all carry unit tests (rates+edges, save/load+regression, collector rotation+env, reader tolerance, target scoring); subprocess smoke + regression suites added.
- **gofmt/vet/build:** clean across the module.

## Documentation check
- [x] `TASK_MANIFEST.md` complete; all tasks DONE; pre-existing issues + 2 blockers logged
- [x] `go/tests/README.md` present
- [x] New subcommands appear in `--help`
- [x] `.gitignore` covers generated/downloaded files

## Issues found
- **None blocking.** Forward-looking (non-blocking): OWASP corpus download must be hardcoded + checksum-verified when implemented at v0.27 (SECURITY_AUDIT M-1). Two roadmap items flagged for the owner: BLOCKER #2 (OWASP/Java timeline) and the exposure-scanner FP bug (v0.21 trust work).

## Recommendation: **SHIP**

Reason: v0.20's single goal — an honest, committed, regression-gated baseline
plus opt-in product metrics — is met and verified end-to-end, with zero
user-facing change and zero new HIGH security findings. The work strengthened
trust rather than spending it: the benchmark triage *found* a real
false-positive defect in the existing scanner and logged it honestly for
v0.21 instead of papering over it. All Constitution rules applicable to this
phase are satisfied; build/vet/gofmt/tests are green.
