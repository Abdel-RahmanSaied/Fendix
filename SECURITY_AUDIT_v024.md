# Security Audit — Fendix v0.24 (Decision Reports)
Audited by: Security Agent (+ 6-lens adversarial review workflow)
Date: 2026-06-28
Scope: surfacing the internal Decision + Confidence layers in the public
reports (JSON/SARIF/HTML/CLI) and PR feedback. First intentional output change
of the v0.2x arc (additive).

## Findings
### CRITICAL / HIGH / MEDIUM (security) — none.
The medium from the adversarial review (M1) was a pre-existing schema-doc drift,
not a security issue; fixed in D8.

### Positive — net security improvement
- **action.yml shell-injection FIXED.** Three pre-existing `${{ inputs.* }}`
  interpolations into `run:` steps (install/scan/enforce) were routed through
  `env:` — closing real injection vectors (the exact rule Fendix ships).
- **PR-comment badge hardened** (`inlineCode(f.Status)`) — defense-in-depth for
  the exported `RenderPRComment`.

## Data-exposure analysis
- **New report fields are non-sensitive.** `status`, `confidence_score`,
  `confidence_band` are a fixed enum/int. `confidence_reasons` are fixed rule
  descriptions + a lineage trace built from each input's `source`+`category`
  (e.g. `blackbox(injection)`) — no payload, response, secret, or finding
  content. The decision summary is integer counts.
- **No Payload/Response leak.** Confidence is scored from the Finding-projected
  Evidence, which has no Payload/Response (those stay Evidence-internal). So the
  v0.22 "internal-only provenance" guarantee is intact even though the score is
  now surfaced.
- **stdout purity preserved.** The human decision summary is stderr-only;
  `--format json|sarif` stdout stays machine-parseable (verified + adversarial
  lens `refute:stdout` confirmed).

## Determinism / integrity
- Confidence scoring: pure, deterministic, no AI/network/time/rand (Rule 8).
  Reasons reconstruct Value exactly (cap reason added).
- Exit code: byte-identical to legacy `checkFailOn` (contract-locked); no new
  blocking reasons introduced.
- SARIF: still valid 2.1.0 (additions in the `properties` extension + the
  existing `level` enum).

## Sign-off
- [x] No CRITICAL findings unresolved
- [x] No new HIGH findings introduced by v0.24 (adversarial review: 0 crit/high)
- [x] Net security improvement (action.yml injections closed)
- [x] No new sensitive data in any report or annotation
