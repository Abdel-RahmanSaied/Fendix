# Fendix v0.28 — Kickoff handoff
Prepared by: Orchestrator Agent
Handoff from: v0.27 completion (2026-06-30)

## Where we are
v0.20 baselines · v0.21 trust · v0.22 Evidence · v0.23 Confidence · v0.24
Decision Reports · v0.25 Developer Experience · v0.26 Accuracy & Benchmarking ·
**v0.27 Java analyzer (first increment)** — SSRF multi-hop taint fix (synthetic
F1 → 1.000, legit + CI-gated), Java regex SAST (cmdi/SQLi/weak-crypto/deser at
TierNativeGo), OWASP two-layer skip gate, honesty cleanup.

## v0.28 candidate theme: deep Java taint analyzer (the real OWASP unlock)
v0.27 shipped Java **regex** SAST. The roadmap's real prize — a meaningful
**OWASP Benchmark** number — needs a **deep Java taint analyzer**. This is a
large, quarter-scale effort; scope it honestly and do NOT publish an OWASP
number until ALL of the "definition of done" below holds.

### OWASP "un-SKIP" definition of done (all required — from the v0.27 blueprint)
1. **Deep Java taint analyzer** (not regex): Java source parsing (servlets/JSP),
   source→sink propagation that **survives sanitizer calls** (ESAPI/encoders
   clear taint), **interprocedural** flow across methods/files, and recognition
   of OWASP's `BenchmarkTest` harness shape. Net-new infra (a parser dep —
   tree-sitter-java via CGo, or `javalang`, or a JVM engine — plus Java
   source/sink/sanitizer models). NOT an edit to `ast_analyzer.py` (Rule 1).
2. **A labeled `benchmarks/targets/owasp-known.json`** ground-truth corpus
   (none exists; only dvwa/juiceshop today).
3. **A pinned, reproducible OWASP source** (fixed Benchmark commit), scored by
   the existing deterministic offline `score()` (keep it pure — Rule 8).
4. **An honest tier** that reflects PROVEN Java taint — NOT the existing
   `tree_sitter_sidecar` label retrofitted over a regex pass (that would
   re-create the v0.26 violation: that tier gets the top confidence bump +
   clears the proven-path gate, `confidence.go:92-93`).

Only when 1–4 hold does `owasp.go` un-SKIP (today it skips in both Scan() and
Run(); a test pins that no 0.0 can persist).

## Done in v0.27 (was going to be deferred — the review corrected me)
- **MF-4 (heavy-eval `min_count:0` recall inflation): DONE.** `score.py` now
  reclassifies `min_count:0` rows as `permitted_absent` (excluded from the
  recall denominator) instead of free hits; `docs/accuracy.md` corrected (the
  Node aggregate's fabricated "8/8 = 1.000" → "2 real + 6 permissive"; bandit
  "10/10" → "5 real + 5 permissive"). The original deferral rationale was wrong
  (the review re-scored the cached corpora: bandit recall stays 1.000, only the
  count changed; corpora are locally re-scorable). Unit-tested in
  `scripts/heavy-eval/test_score.py`. Still TODO in v0.28: run a full real
  heavy-eval to refresh the remaining historical Track-4b/4c "N/N" cells and
  re-confirm the gate floors.

## Deferred from v0.27 (validate/ship in v0.28)
- **SSRF `_url_authority_is_constant` secondary cleanup:** the broad Attribute-
  name (`url/base/endpoint/host`) and all-caps-Name trust (ast_analyzer.py
  ~:2434-2440) is a latent recall gap left out of the minimal B1 diff.
- **B1 `findingMatches` tightening** (`target.go`): bidirectional substring +
  Location-as-substring matching is latent (current numbers aren't wrong).
- **B2 CWD-relative benchmark paths** (`target.go`/`baseline.go`): fragility,
  not a correctness bug — resolve from repo-root or `go:embed`.
- **DVWA digest pin** (`dvwa.go`/`corpus.py` pull `:latest`; `dvwa-known.json`
  is triaged against a specific capture) — pin to a digest + re-capture.

## Carry-overs from earlier phases
- 8c App Check Run (needs GitHub App `checks: write`).
- v0.25 measurement validation owed (human time-to-triage protocol; CLI-
  success-rate over real usage; ignored-findings instrumentation).
- v0.26: competitor head-to-head + correlation-FP-reduction benchmarks (need
  shared-corpus methodology before any comparative claim — Rule 5).

## Rules that bind v0.28
- Rule 5: no OWASP/Java accuracy number until a real Java taint engine + labeled
  corpus exist and reproduce.
- Rule 8: scoring + detection stay deterministic.
- Rule 1: build the Java taint engine as new infra; do not retrofit the Python
  AST analyzer or mislabel the regex pass as taint.
