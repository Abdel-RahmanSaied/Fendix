# Fendix v0.24 — Decision Reports
Kickoff prepared by: Orchestrator Agent
Handoff from: v0.23 completion (2026-06-28)

## Where we are
- **v0.20** baselines · **v0.21** trust · **v0.22** Evidence Architecture
  (Engine→Evidence→Finding→Decision live; provenance + lineage threaded).
- **v0.23** Confidence Engine: `internal/confidence.Score` produces a
  deterministic 0–100 score + plain-text reasons per decision, wired into
  `decision.Decision.Score`. Internal only — output byte-identical, no AI.

## v0.24 goal (from the roadmap)
Surface the Decision layer to users. Turn a wall of findings into a summary:
```
25 findings → 4 confirmed → 3 blocking → 18 informational
```

## What v0.23/v0.22 already give v0.24 (build on, don't rebuild)
- `decision.Decision{Status BLOCK/WARN/INFO/IGNORE, Confidence, Score{Value,Band,Reasons}, Evidence}` — the per-finding verdict + explainable score already exist.
- `decision.ExitCode` is locked to legacy `checkFailOn` (PR-blocking semantics ready).
- The Evidence lineage/provenance is available for the "confirmed" (correlated) count.

## v0.24 deliverables
- Decision report format (BLOCK/WARN/INFO/IGNORE summary) — **this is where output CHANGES** (the first user-facing surfacing).
- SARIF compatibility maintained; GitHub Action PR annotations with decision status.
- CLI decision summary output; confidence score visible in reports.
- PR blocking on BLOCK-status findings.

## Exit criteria
> Engineers see decisions, not just findings. PR blocking works. SARIF compatibility intact. Report generation adds < 200ms.

## Important note on the byte-identical invariant
v0.20–v0.23 were all output-stable. **v0.24 is the first phase that intentionally
changes user-facing output** (decision summary + visible confidence). So:
- The v0.20 output-snapshot tests WILL change — update them deliberately
  (`FENDIX_UPDATE_SNAPSHOTS=1`) and review every diff.
- Keep the raw `findings[]` JSON schema backward-compatible; add the decision
  summary as a NEW section, don't break existing consumers.

## Carry-over (non-blocking)
- LOW: keep surfaced confidence reasons to structural strings; don't interpolate Payload/Response (`SECURITY_AUDIT_v023.md` L-1).

## v0.24 agent prompt
Generate `fendix-v024-agents.md` (same multi-agent structure), oriented around
surfacing the Decision layer to the CLI + GitHub Action with deliberate,
reviewed output-snapshot updates.
