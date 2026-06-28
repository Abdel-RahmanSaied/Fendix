# Fendix v0.22 — Evidence Architecture
Kickoff prepared by: Orchestrator Agent
Handoff from: v0.21 completion (2026-06-28)

## Where we are
- **v0.20** — baselines established (committed `baseline.json` + regression gate).
- **v0.21** — trust earned: zero unresolved HIGH; trust story documented & reproducible (Trust Center, Privacy). Most HIGH fixes were already done by enterprise-readiness sprints; v0.21 closed the config-leak FP + fail-open installer and locked the rest.

## v0.22 goal (from the roadmap)
Refactor internals to `Engine → Evidence → Finding → Decision`. **CLI behavior
stays exactly the same — users notice nothing; engineers notice everything.**

## Deliverables
- Evidence domain model (fields: source engine, rule, location, payload, response, metadata, timestamp, confidence)
- Evidence interfaces + backward-compat adapters
- Correlation Service V2 (evidence normalization, dedup, cross-engine matching, confidence inputs, aggregation)
- Internal Decision object (`BLOCK / WARN / INFO / IGNORE`) — NOT exposed publicly yet
- Migration tests + regression suite

## Exit criteria
> CLI works exactly as before. Internal architecture upgraded. All tests pass.
- Existing CLI output unchanged (the v0.20 output-snapshot tests are the guard).
- No performance regression > 10% vs the v0.20 baseline (`fendix benchmark compare`).
- Correlation test coverage > 80%.

## Guardrails carried forward
- **Rule 1** is the whole game here: this is a refactor *behind* a stable CLI.
  The v0.20 `tests/regression/output_format` snapshots + `benchmark compare`
  are the safety net — run them continuously.
- v0.20 already has a `models.Finding` with rich provenance (Source, SourceTier,
  Route, TaintChain, Reachable, ProvenPath) — the Evidence model should build on
  that, not replace it.

## Carry-over (non-blocking, from v0.21)
- LOW: config-leak FN edge case (a server serving a real `.env` as `text/html`
  is now skipped) — acceptable trade-off, documented in `SECURITY_AUDIT_v021.md`.
- Audit logging is still INFO-level only (no structured security trail) — a
  post-v1.0 hardening item, not on the v0.22 critical path.

## v0.22 agent prompt
Generate `fendix-v022-agents.md` (same multi-agent structure), oriented around
the Evidence/Decision refactor with the "CLI unchanged" invariant front and center.
