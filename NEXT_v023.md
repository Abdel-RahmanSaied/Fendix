# Fendix v0.23 — Confidence Engine
Kickoff prepared by: Orchestrator Agent
Handoff from: v0.22 completion (2026-06-28)

## Where we are
- **v0.20** — baselines established (committed `baseline.json` + regression gate).
- **v0.21** — trust earned (zero unresolved HIGH; Trust Center + Privacy published).
- **v0.22** — Evidence Architecture: `Engine → Evidence → Finding → Decision`
  is live. Every scanner emits `evidence.Evidence`; correlation runs natively
  on Evidence; provenance (RuleID/Payload/Response/Metadata) + lineage thread
  through correlation. Public CLI output byte-identical. Internal Decision
  object exists (BLOCK/WARN/INFO/IGNORE), exit-code-locked to `checkFailOn`.

## v0.23 goal (from the roadmap)
Produce **deterministic, explainable** security decisions. Rule-based only —
never AI. Every decision must justify itself in plain text.

## What v0.22 already gives v0.23 (build on, don't rebuild)
- `internal/evidence.Evidence` carries the confidence INPUTS: source engine,
  rule id, location, **payload + response**, taint chain, reachability, route
  confirmation, source tier, **lineage** (the BB+WB inputs that merged).
- `CorrelateEvidence` already threads that provenance through correlation, so
  the confidence scorer can read it post-correlation.
- `internal/decision.Decision{Status, Confidence, Reason, Evidence}` is the
  slot for the score + reason; `ExitCode` is locked to legacy semantics.

## v0.23 deliverables
- Rule-based confidence scoring (0–100), inputs: static evidence, runtime
  confirmation (DAST), auth context, endpoint reachability, payload-validation
  success, cross-engine agreement.
- Reason breakdown per decision (plain text) + evidence-chain tracing
  (lineage is already captured — surface it).
- Confidence unit tests + benchmarks; accuracy validated against the v0.20
  baseline.

## Exit criteria
> Every security decision comes with a confidence score and a plain-text reason. No black boxes. No AI in the scoring path.

## Guardrails carried forward
- **No AI in the scoring path** (Constitution Rule 8) — rule-based + auditable.
- Confidence is INTERNAL in v0.23 (the user-facing Decision report is v0.24);
  keep CLI output stable, guarded by the v0.20 snapshots + `benchmark compare`.
- To actually USE the threaded provenance, scanners that have a payload/
  response (injection/xss/ssrf) should start populating `Evidence.Payload`/
  `Evidence.Response` natively — a small, incremental per-scanner enhancement
  now that the plumbing exists.

## Carry-over (non-blocking, from v0.22)
- LOW: if Evidence is ever serialized directly, redact Payload/Response
  (`SECURITY_AUDIT_v022.md` L-1).

## v0.23 agent prompt
Generate `fendix-v023-agents.md` (same multi-agent structure), oriented around
the rule-based confidence scorer consuming the Evidence provenance, with the
"deterministic + explainable + no-AI" invariant front and center.
