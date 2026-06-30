# Security Audit — Fendix v0.28 (Java SAST coverage expansion + OWASP skeleton)
Audited by: Security Agent (+ 5-lens adversarial review workflow)
Date: 2026-06-30
Scope: 5 new Java regex rules (XXE, insecure cookie, weak randomness, LDAP
injection, SSRF) + an inert OWASP corpus skeleton.

## Findings
### CRITICAL / HIGH (security) — none unresolved.
The review's HIGH (JAVA_WEAK_RANDOM false-positive class) and MEDIUM (JAVA_XXE
FQN miss) were detection-quality defects, not vulnerabilities in Fendix — both
fixed in the review pass.

## Positive — detection capability (Rule 2: trust)
Five real, high-signal Java detections added (XXE, insecure cookie, weak RNG,
LDAP injection, SSRF), each at the honest regex tier with a tightened FP
profile after review. A noisy weak-RNG rule was retightened (assignment-target
gated) rather than shipped loud — trust over coverage.

## New attack-surface analysis
- **No new execution/injection surface.** The rules are read-only regex over
  `.java` files, identical mechanism to the existing Go/JS/Java rules.
- **OWASP skeleton is inert.** `benchmarks/targets/owasp-known.json` is loaded
  by nothing on any scan/score path; `owasp.go` Scan() + Run() both
  `ErrTargetSkipped`; `runSuite` never persists/compares it;
  `TestOWASPSkeletonIsNotScoreable` pins it empty (mutation-verified by the
  review). It cannot produce or persist a number.

## Rule 5 (benchmark before marketing) — intact
- No Java or OWASP accuracy number published anywhere. Java is framed as
  "regex, line-local"; all findings emit `TierNativeGo` (never a taint tier).
- The skeleton documents the labels/mapping/definition-of-done needed before
  OWASP can ever un-SKIP — it advances the corpus shape without claiming a score.

## Rule 8 (AI never decides) — holds
Detection is deterministic regex; no AI/network at decision time.

## Deferred (operator-owned — surfaced, not faked)
The deep Java taint engine + the Java-parser architecture decision (CGo
tree-sitter breaks the single-static-binary invariant) + any OWASP number.
Tracked in NEXT_v029.md + the skeleton's `_definition_of_done`.

## Sign-off
- [x] No unresolved CRITICAL/HIGH security findings
- [x] New Java coverage adds no injection/execution surface; FP-tightened
- [x] OWASP skeleton inert; no number can be produced or persisted
- [x] Rule 5 + Rule 8 intact
