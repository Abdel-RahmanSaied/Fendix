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

**Not started.** Created 2026-05-14 as the explicit timebox-out follow-up
from Sprint 02 (which deferred npm per its own permission).
