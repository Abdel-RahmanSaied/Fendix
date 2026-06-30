# Fendix v0.30 — Kickoff handoff
Prepared by: Orchestrator Agent
Handoff from: v0.29 completion (2026-06-30)

## Where we are
v0.20→v0.28 (engine-quality arc) + **v0.29** (Java XSS + path-traversal rules →
**11 Java regex rules** total, line-local, TierNativeGo). OWASP still SKIP, no
number. Java SAST coverage at the regex tier is now broad.

## Honest state of "finish all versions → v1.0"
The readily-available, agent-completable engine increments are largely **done**.
What remains to a real v1.0 splits into mine-to-do (small) and operator-gated
(blocking):

### Mine-to-do (small, bounded — candidates for v0.30/v0.31)
- **README repositioning + telemetry statement** (master plan TASK-110/111,
  ~1 day): tighten the top-of-README pitch + a crisp "what Fendix sends to the
  network" statement. Pure docs; no number claims.
- FP-hardening / coverage parity passes if benchmark triage surfaces anything.
- Refresh the historical heavy-eval Track-4b/4c cells against a real run
  (needs a network corpus clone — carried since v0.27).

### HARD operator-gated blockers (cannot be done by an agent — must be surfaced)
1. **Java-parser architecture decision** → unblocks the deep Java taint engine +
   any real OWASP Benchmark number. CGo tree-sitter breaks the single-static-
   binary invariant; WASM-via-wazero or javalang-on-Python are the non-breaking
   options. Operator must choose. Until then OWASP stays SKIP.
2. **Release secrets + DNS**: `COSIGN_ENABLED=true` repo variable +
   `get.fendix.dev` — needed to fire and validate the v1.0 signed-release
   pipeline (nfpm .deb/.rpm + multi-arch Docker + cosign keyless are already
   wired; they've just never run against a real tag).
3. **Open-source license + announcement** (TASK-112) — a business/legal call.

## The v1.0 tag itself is operator-gated
A credible v1.0 RELEASE requires (2) to validate the pipeline and (3) for the
launch posture. The engine is in good shape; the gate is operator actions, not
more agent code. The next agent should: finish the mine-to-do docs, then
produce a **v1.0-readiness report** that enumerates what's done and lists
blockers (1)–(3) for the operator — rather than invent further micro-versions.

## Rules that bind
Rule 1 (build on existing mechanisms), Rule 5 (no number without a reproducible
source — no Java/OWASP accuracy number), Rule 8 (deterministic, no AI).
