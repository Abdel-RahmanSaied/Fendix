# Phase 1 trust fixes — v0.11.1 candidate

Drafted by the bootstrap session 2026-05-14, extended by the second
session 2026-05-14 to include Sprint 02.5. Branch: `phase1-trust-fixes`
(4 commits ahead of `main`). Not yet pushed.

---

## Summary

Phase 1 of the enterprise-readiness plan ([`tasks/enterprise-readiness/PLAN.md`](tasks/enterprise-readiness/PLAN.md)).
Four sprints, four commits, one branch, ready to ship as v0.11.1.

- **Sprint 01 (`1a81ee8`)** — fix the pip-audit naming gap the audit's
  §15.5 calls out as the *single most important fix before external
  evaluation*. Package doc + log lines now state honestly that the
  Python dep-CVE path is a native OSV.dev `/v1/query` REST client; new
  opt-in `--use-pip-audit` flag actually shells out to pip-audit when
  the user wants it (with a stderr-warning fallback if pip-audit is
  not on PATH). Closes audit §15.5.
- **Sprint 02 (`41d7507`)** — pip dep-CVE scans now use OSV.dev's
  `/v1/querybatch` endpoint with a concurrency cap of 4 batches.
  Replaces the per-package serial loop the audit's §15.4 named as the
  first thing that would break under enterprise load. **~62× faster on
  a 150-pinned-deps fixture** (7.84s → 0.13s). Per-batch failures fall
  back to per-package `/v1/query` automatically; a querybatch outage
  cannot hide CVEs. Closes audit §15.4.
- **Sprint 03 (`28ab994`)** — `fendix verify` now has CI-script-friendly
  exit codes (0/1/2 = resolved/still-present/unknown) and a `--help`
  text that's honest about which finding shapes are MVP-deferred.
  Surfaced and fixed a hidden dispatcher bug along the way: correlated
  findings with URL endpoints used to be routed through `verifyURL`
  and produced a misleading single-side verdict — they now hit a
  source-gate before the shape switch and return Status=unknown with
  the workaround. Closes audit §7.
- **Sprint 02.5 (`130a90b`)** — mirrors Sprint 02's batch+concurrency
  work into the npm scanner. `npm.Scan` now uses `/v1/querybatch` with
  the same 4-in-flight concurrency cap; per-chunk fallback to
  `/v1/query` preserves CVE coverage on a batch-endpoint outage. **~62×
  faster on a 150-resolved-deps fixture** (7.87s → 0.127s), identical
  ratio to the pip path. Public surface unchanged — same signature,
  same sentinel errors, same Finding shape. Same alias trade-off as
  pip: batch findings carry only the OSV-id; alias hydration deferred
  to Sprint 02.6.

## Audit-section coverage (per the PLAN.md DoD)

| Sprint | Audit ref |
|---|---|
| 01 | [`FENDIX_AUDIT_REPORT.md` §15.5](FENDIX_AUDIT_REPORT.md) |
| 02 | [`FENDIX_AUDIT_REPORT.md` §15.4](FENDIX_AUDIT_REPORT.md) |
| 02.5 | [`FENDIX_AUDIT_REPORT.md` §15.4](FENDIX_AUDIT_REPORT.md) (npm extension of pip's §15.4) |
| 03 | [`FENDIX_AUDIT_REPORT.md` §7](FENDIX_AUDIT_REPORT.md) |

## Honest deferrals

- **Alias hydration** for batch-path findings (`Sprint 02.6`) is
  documented as a TODO in both pip and npm `queryOSVBatch`. Today the
  batch path emits only the OSV-id reference; the per-package fallback
  retains full CVE-* aliases. Customers who need alias parity can add
  a `GET /v1/vulns/{id}` follow-up. ~0.5 day if a customer asks.
- **npm recursive walk** (Sprint 02.7, no file yet) — pip got
  `pip.ScanRecursive` in Track 4 gap 1, but npm still expects one
  `package-lock.json` at the scan root. Monorepos with nested
  lockfiles still get scanned only at the root. ~0.25 day if a
  customer hits it.

## Test plan

- [x] `make test` — Go: all 21 packages green with `-race`. Python:
      179 passed + 1 pre-existing fuzz failure
      (`test_check_auth_never_crashes`) untouched per the bootstrap
      prompt's hard rule.
- [x] `make e2e` — 5 new `TestE2EVerify*` tests green. Two pre-existing
      e2e failures (`TestCorrelator_HybridScanProducesCorrelatedFinding`,
      `TestReachable_HybridScanProducesReachableCorrelated`) confirmed
      to fail on `main` too; not touched by this PR.
- [x] `make bench` — engine throughput unchanged within run-to-run
      noise (1k-endpoint scan: 30.86ms post-Sprint-02.5 vs 31.57ms
      pre-sprint baseline on the same branch; both well within noise
      of `main`'s ~31.8ms).
- [x] `bench` — `BenchmarkPipDepCVE_*` shows ~62× pip speedup
      (Serial: 7,841ms; Batch: 126ms at 150 deps with 50ms RTT).
- [x] `bench` — new `BenchmarkNpmDepCVE_*` shows ~62× npm speedup
      (Serial: 7,874ms; Batch: 127ms at 150 deps with same RTT).
- [x] `bin/fendix scan --help` — shows the new `--use-pip-audit` flag
      with documented description.
- [x] `bin/fendix verify --help` — shows new exit-code table +
      supported / unsupported finding shapes table.
- [x] Manual: `bin/fendix scan --use-pip-audit --code <fixture>` against
      a `flask==2.0.1, requests==2.20.0` requirements.txt produces 17
      dep-CVEs (incl. transitive `urllib3` advisories pip-audit
      resolves).
- [x] Manual: same scan with pip-audit removed from PATH falls back to
      OSV.dev (8 dep-CVEs, ~5× faster) and emits the documented stderr
      warning.

## Files outside Phase 1 scope

None modified. Each sprint stayed strictly inside the file paths its
sprint file listed. The 7 modified files in Sprint 03 include
`go/internal/cli/exit.go` (a new package created from scratch, as the
sprint file directed). Sprint 02.5 touched only the npm scanner
package + CHANGELOG + PLAN + its own sprint file.

## What this PR does NOT do

- Push to `origin` (deliberately — handing back to the human reviewer).
- Tag v0.11.1.
- Add OSV alias hydration (deferred to Sprint 02.6 — applies to both
  pip and npm batch paths).
- Add an npm recursive walk for monorepos (Sprint 02.7 if needed).
- Touch the `.gitkeep` file at `go/internal/embedded/engine/.gitkeep`,
  which gets re-modified by every `make build`. That's a build artifact
  unrelated to Phase 1; left for separate triage.

## Branch state

```
130a90b perf(npm): OSV.dev /v1/querybatch for dep-CVE scans (Sprint 02.5)
28ab994 feat(verify): scope docs + CI-friendly exit codes (Sprint 03)
41d7507 perf(pip): OSV.dev /v1/querybatch + concurrency cap (Sprint 02)
1a81ee8 feat(pip): honest naming + opt-in pip-audit subprocess (Sprint 01)
c16156c docs: add NEXT_SESSION_PROMPT.md to bootstrap Phase 1 sprints  (already on main)
```

Each sprint commit independently:
- builds (`make build`)
- passes `make test`
- passes `make bench` with no regression vs. main
- updates `CHANGELOG.md` under `[Unreleased]` → v0.11.1
- updates its sprint file's Status section with actual-vs-estimate
  and surprises

## When merged

Tag `v0.11.1` from the merged commit. The CHANGELOG is already
structured for it (the v0.11.1 section sits at the top of `[Unreleased]`).
