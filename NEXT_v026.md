# Fendix v0.26 — Kickoff handoff
Prepared by: Orchestrator Agent
Handoff from: v0.25 completion (2026-06-29)

## Where we are
v0.20 baselines · v0.21 trust · v0.22 Evidence Architecture · v0.23 Confidence
Engine · v0.24 Decision Reports · **v0.25 Developer Experience** (CLI-success-rate
instrumentation, teaching errors + quickstart, O(changed-files) incremental
scans, triage-first PR comment, detection-aware `init`).

## v0.26 theme (confirm against the roadmap owner)
The roadmap associates the next core phase with **accuracy & benchmarking** —
publishing real recall/precision numbers (Rule 5: *benchmark before marketing*).
Confirm scope before starting; the phase name in this repo's roadmap doc is the
source of truth, not this file.

### Known sequencing blocker to resolve FIRST (already documented)
- **OWASP Benchmark is Java; Fendix has no Java analyzer until v0.27.** Running
  it now yields recall ≈ 0 — a misleading baseline (violates Rule 5). The v0.20
  target already loud-SKIPs for this reason. Before v0.26 claims any benchmark
  number: either move OWASP Benchmark to v0.27+ (after Java), and/or wrap the
  existing `scripts/heavy-eval` Juliet-style Python/Go SAST corpus as the
  language-appropriate target. See FENDIX_AUDIT_REPORT "BLOCKER #2".

## v0.25 measurement still owed (the honest part of "measure it")
v0.25 shipped the DX changes + the instrumentation, NOT a proven number. To
close the v0.25 success metrics:
- **time-to-triage ≥30%**: run the human protocol — timed "read this PR comment,
  give the merge decision" on v0.20-formatted vs v0.25-formatted comments. Not a
  CI gate; a measured before/after, like the v0.20 baseline.
- **CLI success rate ≥95%**: now measurable. `FENDIX_METRICS=1` over real usage,
  then `fendix metrics show` reads the rate + failure-class breakdown.
- **ignored-findings-rate ↓**: not yet instrumented — would need suppression-add
  / verify-outcome events in the collector.

## v0.25 deferred (with reason — candidates for v0.26+)
- **Content-hash incremental scan cache** (`~/.fendix/cache/...`): high effort +
  invalidation risk. B3 already made diff scans O(changed files); the cache is
  the next increment once the latency proxy shows per-file re-read dominates.
- **Partially-staged blob scanning** (`git show :path`): touches commit-time
  correctness; defer until the staged-vs-working-tree gap causes real false
  blocks.
- **Per-ecosystem SCA / dep-CVE caching**: out of scope for DX; the dominant
  `--fast` cost was the walk (fixed in B3), not govulncheck.
- **Configurable pre-commit hook** (`.fendix.yaml` / `fendix hook run`): mostly
  ergonomic; no clear metric movement beyond B3.
- **Progress-feedback TTY spinner**: UX-subjective and not deterministically
  measurable; left out under "ship only what moves the metric" (its mapper in
  the understand workflow also failed, so it was never scoped).

## Carry-overs from earlier phases
- **8c App Check Run** (BLOCK→`conclusion:failure`): needs the GitHub App to
  gain `checks: write` (operator config). Implement `internal/ghapp/checkrun.go`
  once granted.
- v0.23 confidence fidelity: injection/xss/ssrf scanners could populate
  `Evidence.Payload`/`Response` natively so the score uses them.

## Rules that bind v0.26
- Rule 5: benchmark before marketing — no published number without a real,
  language-appropriate corpus.
- Rule 8: AI never decides scoring/benchmarks.
