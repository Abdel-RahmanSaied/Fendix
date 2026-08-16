# Fendix v1.1 — Kickoff handoff
Prepared by: Orchestrator Agent
Handoff from: v1.1 Real-World Precision completion (2026-07-08)

## Where we are
v0.20→v0.30 was the engine-quality + Java-regex-coverage arc. **v1.1
(Real-World Precision)** built the real-world SAST benchmark track, unblocked and
captured the first honest TWISCOPE-class precision baseline, closed the residual
FP classes (B1–B8), audited the Phase-C recall/coverage rules (C1–C4), and wired
the whole thing into CI. The synthetic taint corpus still gates at **F1 == 1.000**
(22 TP / 0 FP / 0 FN / 29 TN); Go suite and Python suite green.

## What v1.1 shipped

### Task P — the perf unblock (Product-Constitution Rule 6)
`ASTAnalyzer._expr_references_secret` restarted `ast.walk` per resolved binding
with no memoization → O(fan-out) re-walk. A shared `id(node)` set makes every
node inspected once. Measured: the TWISCOPE `delivery_tasks.py` file went from
**>150 s (killed)** to **0.004 s**; the whole-repo `--python-engine` scan from
**~50 min** to **9.0 s**. Locked by `TestSecretInLogFanOutPerf` (TP preserved
through a deep accumulator, non-secret log not flagged, fast-completion fence).

### Task 0.5 — the REAL baseline (now that the scan is fast)
Captured 2026-07-08 and recorded honestly in `benchmarks/realworld/README.md`
and `BENCHMARKS.md §5`: **1 confirmed TP retained, 0 FN, 8/11 labeled FP classes
eliminated, SAST taint noise ~90 → 5 findings, 2 residual FPs quantified.** The
33.3 % precision-over-labeled is disclosed as a thin-denominator lower bound.
`baseline.json` carries a hand-merged `realworld/twiscope` reference row
(dvwa/juiceshop untouched).

### Phase C — recall/coverage rules
- **C1 (LLM-prompt sink), C2 (env/config SSRF source), C3 (httpx constructor
  base_url SSRF)** were AUDITED and found **already shipped** — kept as regression
  locks (19 pytest cases + corpus cases). Added one gated negative,
  `ssrf-settings-authority-safe`, so the C2 FP-4 config-authority suppression is
  now part of the F1 gate.
- **C4 (verify for correlated + active-probe findings)** was the genuinely-new
  work — implemented with TDD (8 tests). Correlated: two-sided verify (resolved
  the moment either the blackbox endpoint is gated OR the whitebox file is gone).
  Active-probe: consent-gated re-probe via a new `--enable-active` verify flag.

### Phase D — docs + CI + handoff
BENCHMARKS.md §5 + accuracy.md Track 5 (measured numbers + per-class deltas +
caveats); ci.yml synthetic-corpus gate step + `run_benchmark.py --gate`;
baseline.yml realworld-tier wiring + corpus gate on tag builds; these handoff
docs.

## Mine-to-do next (small, bounded — candidates for v1.2)
- **Triage the 2 unlabeled TWISCOPE SAST unknowns** (`data_handling.py:450`
  path-traversal, `connection_views.py:247` open-redirect) → add `tp`/`fp` labels
  so they leave the `unknown` bucket and sharpen the number.
- **Public real-world tier**: pick 1–2 permissively-licensed pinned-SHA repos,
  author labels, commit them → the realworld gate becomes CI-enforced (today the
  seed tier is private and loud-SKIPs in CI). This is the last step to a
  CI-gated real-code precision number.
- **SANAD seed entry**: absent this run (`/tmp/Sanad-AI-Agent` not present) →
  loud-SKIPs. Restore the checkout + re-verify its labels to add a second seed.

## HARD operator-gated blockers (cannot be agent-done)

> **Re-checked 2026-08-05.** This list had been copied forward verbatim since
> v0.29 without re-verification; two of the three entries were already closed.
> Re-verify against live state before carrying it forward again.

1. **Java-parser architecture decision** → unblocks the deep Java taint engine +
   any real OWASP Benchmark number. OWASP stays two-layer SKIP until chosen.
   **STILL OPEN.** CGo tree-sitter would break the single-static-binary
   invariant; WASM-via-wazero and javalang-on-Python are the non-breaking
   options. Java today is 11 line-local regex rules (`TierNativeGo`), never
   branded as taint.
2. ~~**Release secrets + DNS** (`COSIGN_ENABLED`, `get.fendix.dev`)~~ —
   **CLOSED.** Verified 2026-08-05: repo variable `COSIGN_ENABLED=true` (set
   2026-04-30); `https://get.fendix.dev/install.sh` serves HTTP 200; the
   `Release` workflow succeeded on both real tags (`v1.0.0`, run
   `28477488565`; `v1.1.0`, run `28933432097`), each publishing **92 assets**
   including 28 signature/SBOM/attestation files.
3. **Open-source license + announcement** — *partially closed.* The **license
   decision is made**: MIT (`LICENSE`, repo root) with the posture ratified in
   `docs/adr/ADR-007-open-source.md` (Status: Accepted, 2026-05-01). Only the
   **public announcement/launch post** remains a business call.

## Rules that bind
Rule 1 (build on existing mechanisms — C1–C4 reused the AST/verify machinery),
Rule 5 (no number without a reproducible source — the TWISCOPE number ships with
its exact reproduce command and honest caveats), Rule 6 (performance regressions
are bugs — Task P), Rule 8 (deterministic scoring, no AI decides a label).
