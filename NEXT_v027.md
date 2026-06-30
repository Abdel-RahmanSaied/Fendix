# Fendix v0.27 — Kickoff handoff
Prepared by: Orchestrator Agent
Handoff from: v0.26 completion (2026-06-30)

## Where we are
v0.20 baselines · v0.21 trust · v0.22 Evidence · v0.23 Confidence · v0.24
Decision Reports · v0.25 Developer Experience · **v0.26 Accuracy & Benchmarking**
(reconciled stale-to-v0.11.0 numbers to reproduced values; published a
reproducible BENCHMARKS.md; CI-gated the synthetic F1 so it can't silently drift).

## v0.27 theme (per the roadmap): Java analyzer
The roadmap puts a **Java analyzer** at v0.27 — and it is the gate for the
**OWASP Benchmark**, which has been loud-SKIPping since v0.20 precisely because
it is Java and Fendix had no analyzer (running it = recall ≈ 0 = a Rule 5
violation). Confirm scope against the roadmap before starting.

### The OWASP unlock (do this carefully — it's a Rule 5 landmine)
- `go/internal/benchmark/targets/owasp.go` currently loud-SKIPs. Until **real
  Java ground-truth labels exist**, have `Run()` return `ErrTargetSkipped` so an
  empty/zero result can NEVER be persisted as a 0.0 number.
- Only publish an OWASP recall/precision number once the Java analyzer is real
  AND the corpus is labeled — then it joins BENCHMARKS.md with the same
  reproduce-command + caveat discipline as every other number.

## Deferred from v0.26 (accuracy hardening — strong v0.27 candidates)
- **SSRF multi-hop string-concat false negative** (disclosed in BENCHMARKS.md):
  `url = "https://" + request.args["x"]; requests.get(url)` is missed because
  taint doesn't propagate through the concat `BinOp` into the sink. The
  open-redirect multi-hop case was fixed this way at v0.11; generalise that to
  SSRF (and audit the other reachable sinks for the same gap). Restores
  synthetic F1 to 1.000 *legitimately*. Then bump the CI floor (`--min-f1`).
- **B1 — DAST scorer honesty** (`go/internal/benchmark/targets/target.go`): parse
  `known_false_positives[]`, classify expected-FP vs unexpected-FP, tighten
  `findingMatches()` to 1:1 normalized-category matching, rename DAST "recall"
  → "Regression Coverage" in output.
- **B2 — DAST reproducibility**: pin DVWA image to a digest; drop the dead
  `memory_mb`/noisy `duration_ms` regression gates; resolve baseline/ground-truth
  paths from repo-root (or `go:embed`) so `fendix benchmark run` works from any
  CWD; regenerate `baseline.json` from a clean tagged build.
- **B5 — corpus quality**: add known-missed vulns so DAST FN can be nonzero
  (recall stops being vacuous); add a real-repo true-negative set so precision
  is measurable; make the heavy-eval SHA-fetch fallback a hard failure (it
  silently scores against the default branch today — a Rule 5 hole); `git rm`
  the committed 5MB Mach-O `labels/go-vulnerable-module/vulnerable-test`
  (non-portable on ubuntu CI); wire/delete orphan label files.
- **MF-4** — heavy-eval G2: exclude `min_count:0` rows from the recall
  denominator (some bandit/gosec rows can never miss → recall partly mechanical).
- **MF-6** — perf marketing in `docs/benchmarks.md` mixes stale v0.8–v0.18 rows
  on unspecified hardware: regenerate from a current `make bench` with a
  CPU/OS/Go stamp, or mark "indicative, not CI-gated". (Perf, not accuracy —
  out of v0.26's core scope.)
- **MF-8** — label heavy-eval stage 4d "govulncheck parity" (not accuracy) in
  docs/accuracy.md (already correct in BENCHMARKS.md).

## Carry-overs from earlier phases
- 8c App Check Run (needs GitHub App `checks: write`).
- v0.25 measurement validation owed: human time-to-triage protocol; CLI-success-
  rate over real usage; ignored-findings-rate instrumentation (see NEXT_v026).

## Rules that bind v0.27
- Rule 5: no OWASP/Java number until the analyzer is real AND the corpus labeled.
- Rule 8: scoring stays deterministic — no model/network at score time.
- Rule 1: build on the existing benchmark harness + analyzer architecture; don't rewrite.
