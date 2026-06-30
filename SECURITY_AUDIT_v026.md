# Security Audit — Fendix v0.26 (Accuracy & Benchmarking)
Audited by: Security Agent (+ 6-lens adversarial review workflow)
Date: 2026-06-30
Scope: a truth-reconciliation phase — docs/claims, the Python accuracy harness,
heavy-eval scoring, a CI gate, and BENCHMARKS.md. No scanner code changed.

## Findings
### CRITICAL / HIGH / MEDIUM (security) — none.
The review's MUST-FIX items were correctness/honesty defects (a wrong corpus
count, an unswept doc with a stale 1.000), not security vulnerabilities. All
fixed in D8.

## Attack-surface analysis
- **No new scanner attack surface.** v0.26 changed only Markdown docs, the
  Python accuracy/heavy-eval harnesses, and a CI workflow comment+step. The Go
  scanner binary is byte-for-byte unchanged (verified: regression snapshots and
  the reproduced 0.987 both hold without a rebuild-of-changed-Go).
- **CI gate is injection-free.** The new `heavy-eval.yml` step runs
  `scripts/accuracy/run.py --python-engine --min-f1 0.98 ./bin/fendix` — fixed
  literal arguments, no `${{ }}` interpolation of untrusted input into the run
  block. The earlier `${{ }}`-in-run audit posture is preserved.
- **No secret/data exposure.** The harnesses score local corpora and emit
  counts/ratios; no payloads, repo contents, or credentials enter any published
  artifact.

## Rule 8 (AI never decides) — confirmed
The adversarial `refute:rule8` lens verified that every published-number scoring
path — `scripts/accuracy/run.py`, `scripts/heavy-eval/{score,gate}.py`,
`python/benchmark/run_benchmark.py`, `go/internal/benchmark` — imports nothing
that calls an LLM or the network at scoring time. The bootstrap CI RNG is now a
per-call deterministic `random.Random(seed)` (no global-order dependence).

## Rule 5 (benchmark before marketing) — the core of this phase
- Every published accuracy number now traces to a re-runnable in-repo command
  (BENCHMARKS.md), captured on the current binary with a version+date stamp.
- The synthetic F1 is now CI-gated (`--min-f1 0.98`) so it cannot silently drift
  from the marketed value again (the root cause of the v0.11.0→current gap).
- OWASP Benchmark still loud-SKIPs (Java → v0.27); the `refute:owasp` lens
  confirmed no fabricated 0.0 can reach results/baseline/Compare.

## Trust posture (Rule 2)
Reconciling stale, unreproducible accuracy claims to honest reproduced numbers
(including disclosing a real SSRF false negative rather than rounding to 1.000)
is a direct trust improvement — the security-adjacent property this product
sells.

## Sign-off
- [x] No CRITICAL/HIGH security findings
- [x] No new attack surface; CI gate injection-free
- [x] Rule 8 holds (deterministic, no AI/network in scoring)
- [x] Rule 5 satisfied (every number reproducible + stamped + gated)
- [x] OWASP cannot emit a fabricated number
