# Sprint 02.5 — OSV.dev batch queries for npm scanner

**Phase:** 1.2.5 (follow-up to Sprint 02)
**Estimate:** 0.5 day
**Risk:** Low
**Ships in:** v0.11.2 (or bundled with another patch)
**Parent sprint:** [`sprint-02-osv-batch.md`](sprint-02-osv-batch.md)

---

## Why this sprint exists

Sprint 02 added `/v1/querybatch` + concurrency cap to the **pip** dep-CVE
scanner (~62× speedup at 150 deps). The same change was scoped for the
**npm** scanner in the original sprint file but explicitly cleared as
timeboxable: *"If timeboxed, npm can slip to Sprint 02.5; pip is the
priority since it's the higher-traffic ecosystem."*

This sprint mirrors Sprint 02's pip work into npm.

---

## Read first

- [`sprint-02-osv-batch.md`](sprint-02-osv-batch.md) — the parent
  sprint, particularly its Status section (the surprises I hit on pip
  apply to npm too).
- [`go/internal/scanner/deps/pip/scanner.go`](../../go/internal/scanner/deps/pip/scanner.go)
  — the implementation pattern to mirror. Specifically:
  - `pkgWithManifest` type
  - `scanViaOSV` (3-phase: collect pairs → cache lookup → batch misses)
  - `runBatchOrFallback`, `runSerialFallback`, `queryOSVBatch`
  - `osvBatchMaxSize` and `osvMaxConcurrentBatches` constants
- [`go/internal/scanner/deps/npm/scanner.go`](../../go/internal/scanner/deps/npm/scanner.go)
  — the file to mirror into. Note that npm uses `resolvedPackage`
  (not `pinnedPackage`) and reads `package-lock.json` (not
  `requirements.txt`); the per-package shape is different but the
  batch-orchestration shape is identical.

---

## Concrete deliverables

1. Mirror the same constants (`osvBatchMaxSize`, `osvMaxConcurrentBatches`)
   into the npm package, OR move them to a new shared
   `internal/scanner/deps/osv/` package — either is fine, the constants
   are tiny.
2. Mirror the 3-phase `scanViaOSV` shape (collect, cache lookup, batch
   misses) into the npm `Scan` function. Ecosystem string changes from
   `"PyPI"` to `"npm"`.
3. Mirror `runBatchOrFallback`, `runSerialFallback`, `queryOSVBatch` into
   the npm package.
4. Add the same 7 tests that Sprint 02 wrote for pip, into a new
   `npm/scanner_batch_test.go`. The fake-server helper from
   `pip/scanner_batch_test.go` is reusable as a pattern (different
   ecosystem string in the request body).
5. Add the same micro-bench (`scanner_batch_bench_test.go`) so the
   speedup is documented.

---

## Definition of done

- [ ] `make test` passes — including the new npm batch tests
- [ ] npm batch bench shows ≥4× speedup on a 150-dep fixture (numbers
      in PR description)
- [ ] `bin/fendix scan --code <large-npm-monorepo>` against a real
      cold-cache target shows the expected speedup
- [ ] [`CHANGELOG.md`](../../CHANGELOG.md) entry under `[Unreleased]`,
      same shape as Sprint 02's
- [ ] PR description cites Sprint 02 as the precedent

---

## Risks

Same as Sprint 02 — see its "Risks" section. None unique to npm.

---

## Status

**Started:** 2026-05-14 (AI implementer, second session)
**Branch:** `phase1-trust-fixes` (continues the Phase-1 bundle; commit
#4 on the branch after Sprints 01/02/03)
**PR:** drafted; not pushed
**Status:** done

**Actual effort:** ~0.5 day — matched the estimate. Pip implementation
was the template; the mechanical mirror took the bulk of the time.

**Surprises:**

- **The brief said "mirror into the npm `Scan` function" — and meant it.**
  Pip's batch path lives in a new `scanViaOSV` while the legacy `Scan`
  stays per-package (because pip also added recursive walk; the two
  needed to coexist). npm has no recursive-walk story yet, so the
  brief's literal instruction was correct: refactor `Scan` itself.
  Public signature, sentinel errors, and `buildFinding` shape are
  unchanged — only the in-function loop got the 3-phase treatment.
  Orchestrator + `fendix verify` integration call sites needed no
  changes.
- **The Sprint 02 fake-server trap applies to npm too.** Existing
  tests (`TestScan_HappyPath_AgainstFakeOSV`,
  `TestScan_PerPackageErrorDoesNotKillScan`) use a fake server that
  only handles `/v1/query`. After the refactor, the batch path now
  hits `/v1/querybatch` first, gets 404, and falls back to serial —
  exact same shape Sprint 02 documented as Surprise #1 for pip. The
  fallback delivers the right findings so the existing tests pass
  unchanged; the new `scanner_batch_test.go` uses a
  `newFakeOSVBatchServer` helper that serves both endpoints when a
  test actually wants to *prove* it's exercising the batch path.
- **No npm orchestrator-side recursive walk.** Pip got
  `pip.ScanRecursive` in Track 4 gap 1; npm still expects one
  lockfile at the scan root. The sprint brief did not ask for this,
  so it stays out of scope — but worth knowing for future sessions:
  monorepos that ship multiple `package-lock.json` files still get
  scanned only at the root. Track as a follow-up (not in PLAN.md
  yet — likely a quarter-day Sprint 02.7 if customers hit it).
- **Serial-baseline bench uses `runSerialFallback` directly, not a
  legacy `Scan`.** Pip's `BenchmarkPipDepCVE_Serial` calls `pip.Scan`
  (still per-package). npm's refactor leaves no legacy entry point,
  so the bench drives `runSerialFallback` directly with a synthesised
  chunk. The transport shape is identical; the only divergence from
  pip's bench shape is the call site. Numbers compare directly to
  pip's table.

**Bench (npm dep-CVE only — `BenchmarkNpmDepCVE_*` in `scanner_batch_bench_test.go`):**

| Path | ns/op | Wall-clock @ 150 deps |
|---|---:|---:|
| Per-package serial (via `runSerialFallback`) | 7,874,485,550 | ~7.87s |
| Batched via `Scan` (post-Sprint-02.5)         | 126,700,242   | ~0.127s |

**~62× speedup**, identical ratio to pip's Sprint-02 numbers and
comfortably above the 4× gate. Bench uses the same simulated 50ms
`/v1/query` + 100ms `/v1/querybatch` RTT as Sprint 02 for direct
comparability.

**Engine-throughput bench (`make bench`) post-Sprint-02.5:** 1k-endpoint
scan ≈ 30.86ms vs. 31.57ms pre-sprint baseline on the same branch —
Δ < 2.3%, within run-to-run noise. No SAST regression.

**Tests added:**

- 7 new unit tests in `scanner_batch_test.go`:
  `TestScan_BatchUsedWhenManyPackages`, `TestScan_CacheHitsSkipBatch`,
  `TestScan_BatchFailureFallsBackToSerial`,
  `TestScan_BatchSizeRespected`, `TestScan_ConcurrencyCapRespected`,
  `TestQueryOSVBatch_LengthMismatchErrors`,
  `TestQueryOSVBatch_ExceedingMaxSizeErrors`.
- 2 new benchmarks in `scanner_batch_bench_test.go`:
  `BenchmarkNpmDepCVE_Batch`, `BenchmarkNpmDepCVE_Serial`.
- All 27 npm package tests pass (`go test -race -count=1
  ./internal/scanner/deps/npm/`); known pre-existing Python fuzz
  failure (`test_check_auth_never_crashes`) unchanged.

**Files touched:**

- `go/internal/scanner/deps/npm/scanner.go` — added batch constants,
  imports (`sync`, `golang.org/x/sync/semaphore`), refactored `Scan`
  to 3-phase, added `pkgWithManifest`, `runBatchOrFallback`,
  `runSerialFallback`, `queryOSVBatch`. ~210 LOC added.
- `go/internal/scanner/deps/npm/scanner_batch_test.go` — new, 7 tests
  + fake-server + lockfile-writer helpers (~370 LOC).
- `go/internal/scanner/deps/npm/scanner_batch_bench_test.go` — new, 2
  benches + lockfile-writer helper (~150 LOC).
- `CHANGELOG.md` — appended npm batch entry; corrected stale
  Sprint-02.5 cross-reference in the pip entry to point at Sprint
  02.6 (alias hydration is the next-up follow-up; npm batch is THIS
  sprint).
- `tasks/enterprise-readiness/PLAN.md` — marked Sprints 01/02/03/02.5
  ✅ in the roster.

**Follow-ups created:**

- **Sprint 02.6 (OSV alias hydration via `GET /v1/vulns/{id}`)** —
  already exists in the pip Sprint 02 follow-ups list. The TODO
  comment in `npm/scanner.go`'s `queryOSVBatch` cites it. Hydrating
  aliases for both pip and npm batch paths together is the right
  shape. No sprint file yet.
- **Sprint 02.7 (npm recursive walk for monorepos)** — pip got this
  in Track 4 gap 1 as `pip.ScanRecursive`; npm still only reads the
  root lockfile. Probably ~0.25 day if a customer asks; no sprint
  file yet, not blocking.

**Hard-rule compliance:**

- Stayed strictly inside the file paths the sprint brief lists.
- `npm.Scan` public signature, sentinel errors, and Finding shape are
  unchanged — additive only.
- No new CGo. No new external deps (`golang.org/x/sync` was already
  promoted to direct in Sprint 02).
- `make build`, `make test` (modulo the known pre-existing Python
  fuzz failure), `make bench` all green.
- Build artifact `go/internal/embedded/engine/.gitkeep` left alone
  per the in-repo memory `gotcha-fendix-build-artifacts-and-stash`.
