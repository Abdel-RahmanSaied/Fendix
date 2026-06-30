# Fendix v0.29 — Kickoff handoff
Prepared by: Orchestrator Agent
Handoff from: v0.28 completion (2026-06-30)

## Where we are
v0.20 baselines → v0.27 Java analyzer (first increment) → **v0.28 Java SAST
coverage expansion** (9 Java regex rules total + an inert OWASP corpus skeleton;
OWASP still SKIP, no number).

## The honest endpoint of "finish all versions" = v1.0
The v0.2x engine arc has no documented terminus past here — I am now defining
each next version. To keep that honest and bounded (not an endless arc), v0.29+
should **converge on a credible v1.0 release**, not invent indefinite engine
phases. Two tracks remain, and both have hard gates:

### Track A — bounded engine increments (mine to do)
- **Finish the held-back Java regex rules:** XSS (`response.getWriter().print(`
  + `javaReqSource`) and path-traversal (`new File(`/`Paths.get(` +
  `javaReqSource`) — the v0.28 blueprint queued these as the first follow-up.
  Same TierNativeGo / FP-guard / no-number discipline.
- FP-hardening + coverage parity passes across languages as needed.

### Track B — the v1.0 release readiness checklist (master plan Phase 13/14)
Much is already done (cosign keyless, nfpm .deb/.rpm, multi-arch Docker,
SECURITY.md, BENCHMARKS.md, perf suite). Remaining to a credible v1.0:
- Validate the release pipeline end-to-end (cut `v0.6.0-rc1` → confirm signed
  artifacts + packages build) — **but this is OPERATOR-gated**: needs
  `COSIGN_ENABLED=true` repo variable + `get.fendix.dev` DNS. I cannot do these.
- README repositioning + telemetry statement (TASK-110/111 — mine, ~1 day).
- Open-sourcing the engine (TASK-112) — a license + repo-split + announcement
  decision that is **operator-owned**, not an agent call.
- Refresh the historical Track-4b/4c heavy-eval cells against a real run
  (carried from v0.27/v0.28: needs a network corpus clone).

## HARD blockers I cannot clear (operator-owned — must be surfaced, not faked)
1. **Java-parser architecture decision** (deep Java taint / real OWASP number):
   CGo tree-sitter vs WASM-tree-sitter-via-wazero vs javalang-on-Python — the
   first breaks the single-static-binary invariant. Until decided, OWASP stays
   SKIP and no OWASP/Java accuracy number ships.
2. **Release secrets/DNS** (`COSIGN_ENABLED`, `get.fendix.dev`) — needed to fire
   and validate the v1.0 signed-release pipeline.
3. **Open-source license + announcement** (TASK-112) — a business/legal call.

## Standing directive
Keep shipping real, reviewed, honest increments toward v1.0 without stopping.
Do NOT fake completion of operator-gated items (1–3) or claim numbers Fendix
hasn't earned — surface those crisply and keep advancing everything else.

## Rules that bind
Rule 1 (build on existing mechanisms), Rule 5 (no number without a reproducible
source), Rule 8 (deterministic, no AI in detection/scoring).
