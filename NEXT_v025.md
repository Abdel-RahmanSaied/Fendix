# Fendix v0.25 — Developer Experience
Kickoff prepared by: Orchestrator Agent
Handoff from: v0.24 completion (2026-06-28)

## Where we are
- v0.20 baselines · v0.21 trust · v0.22 Evidence Architecture · v0.23 Confidence
  Engine · **v0.24 Decision Reports** (decision summary + visible confidence in
  JSON/SARIF/HTML/CLI/PR; PR blocking via exit code; first intentional output change).

## v0.25 goal (from the roadmap)
Make Fendix *faster and less frustrating to use*. Measure it. Ship only what
moves the metric. DX is adoption: ignored findings = no security improvement.

## v0.25 deliverables
- Improved CLI UX (better error messages, progress feedback).
- Faster incremental scans (changed files only).
- Better PR comment formatting.
- Improved pre-commit workflow.
- Developer onboarding improvements.

## Success metrics (must MEASURE, not assume)
- Average time-to-triage reduced ≥ 30% vs the v0.20 baseline.
- CLI success rate ≥ 95%.
- Ignored-findings rate decreasing.

## What v0.24/earlier already give v0.25
- The decision summary + confidence score (v0.24) are the raw material for a
  cleaner, prioritized PR comment + CLI UX — surface "3 blocking" first.
- Diff-aware scanning already exists (`--diff`/`--staged`, v0.16) — v0.25's
  "faster incremental scans" builds on it.
- The metrics collector (v0.20, `FENDIX_METRICS`) is the instrument for the
  time-to-triage / CLI-success-rate metrics — extend it, don't rebuild.

## Carry-overs into v0.25/later
- **8c App Check Run** (BLOCK→`conclusion:failure`): needs the GitHub App to
  gain `checks: write`. Implement `internal/ghapp/checkrun.go` once the
  manifest permission is added (operator config).
- LOW (v0.22): if Evidence is ever serialized directly, redact Payload/Response.
- v0.23 confidence fidelity: scanners with a payload/response (injection/xss/
  ssrf) could populate `Evidence.Payload`/`Response` natively so the score uses
  them (currently scored from the Finding projection).

## v0.25 rules (roadmap "Won't Do")
- No chatbot, no web dashboard, no mobile app. Measure DX; ship only what moves it.

## v0.25 agent prompt
Generate `fendix-v025-agents.md`, oriented around measured DX improvements with
the metrics collector as the yardstick.
