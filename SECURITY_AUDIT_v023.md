# Security Audit — Fendix v0.23 (Confidence Engine)
Audited by: Security Agent
Date: 2026-06-28
Scope: `internal/confidence` + its wiring into `internal/decision`. Internal,
additive; public output byte-identical (snapshot/schema/full suite green).

## Findings
### CRITICAL / HIGH / MEDIUM — none.

### LOW
- **L-1 (forward-looking) — reason strings in v0.24.** `confidence.Result.Reasons`
  are fixed rule descriptions + a lineage trace built from each input's
  `Source` + `Category` (e.g. `blackbox(injection)`). They carry **no payload,
  response, secret, or finding content** today. When v0.24 surfaces the score
  in reports, keep it to these structural strings — do not interpolate
  `Evidence.Payload`/`Response` into reasons.

## Analysis
- **Pure & deterministic.** `Score` is a pure function: no I/O, no network, no
  exec, no goroutines, no randomness, no time. Same input → same output (tested).
- **No AI** in the scoring path (Constitution Rule 8) — every point is a fixed,
  documented constant delta.
- **Internal-only.** `Decision.Score` is not serialized; the existing
  `models.Confidence` enum, severity computation, and public JSON/SARIF/HTML
  are untouched (output byte-identical).
- No new secrets, no new egress, no new exec, no new file paths.

## Sign-off
- [x] No CRITICAL findings unresolved
- [x] No new HIGH findings introduced by v0.23
- [x] No AI in the scoring path; deterministic + reproducible
- [x] Public output byte-identical (no new exposure surface)
