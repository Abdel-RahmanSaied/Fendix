# Code Review — Fendix v0.28 (Java SAST coverage expansion + OWASP skeleton)
Reviewed by: Reviewer Agent (informed by the 5-lens adversarial review workflow)
Date: 2026-06-30

## Exit criteria: **PASS**
> *"Broader, real Java SAST coverage Fendix can honestly claim — advancing toward the Java-taint goal without faking the quarter-scale engine or claiming an OWASP number."*

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Real, broader Java coverage | ✅ | 5 new rules (XXE/cookie/weak-RNG/LDAP/SSRF) → 9 Java rules total; verified firing on vuln code. |
| Honestly claimed | ✅ | All `TierNativeGo`; no Java/OWASP number; BENCHMARKS.md language table explicit. |
| No fake engine / no OWASP number | ✅ | Deep taint + parser decision deferred (operator-owned); OWASP two-layer SKIP; inert skeleton pinned empty. |
| FP discipline | ✅ | Review-flagged weak-RNG FP class fixed (assignment-target gated); 0 FPs on the 4 review fixtures + safe shapes. |

## Product Constitution: **PASS**
| Rule | Status | Note |
|------|--------|------|
| 1 Never rewrite | ✅ | Rides the existing textscan rule mechanism; no engine rewrite. |
| 2 Trust before features | ✅ | Retightened the noisy weak-RNG rule rather than ship it loud. |
| 5 Benchmark before marketing | ✅ | No Java/OWASP number; OWASP can't produce one; skeleton documents the DoD. |
| 8 AI never decides | ✅ | Deterministic regex. |

## Adversarial review (5 lenses)
Verdict **FIX-FIRST** → fixed → **SHIP**. One HIGH (weak-RNG over-fire on
token-word-in-comment/string/identifier) + one blocking MEDIUM (XXE missed FQN
dom4j SAXReader) — both fixed and regression-tested. The OWASP skeleton was
mutation-verified inert; the other four rules + Rule-5 honesty held.

## Issues found
None blocking after the fix pass. Deferred (NEXT_v029): held-back Java rules
(XSS, path-traversal), the deep Java taint engine + its operator-owned parser
decision, and convergence on the v1.0 release-readiness checklist (with its
operator-gated blockers: COSIGN/DNS, open-source license).

## Recommendation: **SHIP**
Reason: v0.28 broadens Java SAST with five real, honestly-tiered detections,
lays inert OWASP corpus scaffolding that cannot fabricate a number, and — after
an adversarial review that caught a real FP class and an FQN miss — ships with a
tightened, trustworthy rule set. No quarter-scale work is faked; the deep-taint
engine and its architecture decision are surfaced for the operator.
