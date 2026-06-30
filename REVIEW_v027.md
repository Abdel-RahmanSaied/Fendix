# Code Review — Fendix v0.27 (Java analyzer, first increment)
Reviewed by: Reviewer Agent (informed by the 6-lens adversarial review workflow)
Date: 2026-06-30

## Exit criteria: **PASS**
> *"Real, reproducible Java SAST coverage Fendix can honestly claim — without claiming an OWASP Benchmark number it hasn't earned."*

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Real Java coverage shipped | ✅ | 4 Java textscan rules (cmdi/SQLi/weak-crypto/deser); a vulnerable .java file went from 1 finding (secret) to 4. Tier = `native_go` (regex), not taint. |
| Honestly claimed (no overclaim) | ✅ | Framed "regex, line-local" everywhere; NO Java/OWASP accuracy number; BENCHMARKS.md language-coverage table is explicit. |
| OWASP not claimed | ✅ | `Scan()` + `Run()` both `ErrTargetSkipped`; `TestOWASPSkipsInBothLayers` pins that no 0.0 can persist. |
| Bonus: SSRF FN fixed | ✅ | Synthetic F1 1.000 (reproduced, CI-gated 0.99); 5 new multi-hop SSRF tests + host-extension/constant-host guards. |

## Product Constitution: **PASS**
| Rule | Status | Note |
|------|--------|------|
| 1 Never rewrite working systems | ✅ | Java rides the existing textscan rule mechanism; ~12-line taint fix in one function; no engine rewrite. |
| 2 Trust before features | ✅ | SSRF detection gain + honesty cleanup (removed a fabricated recall). |
| 5 Benchmark before marketing | ✅ | No Java/OWASP number; OWASP gated; min_count:0 recall inflation removed (scorer + docs). |
| 8 AI never decides | ✅ | Regex + deterministic scoring; no AI/network at decision time. |

## Adversarial review (6 independent refutation lenses)
Verdict **FIX-FIRST** → all addressed → **SHIP**. Two HIGH (Java SQL rule
over-firing on `Executor.execute`; a live fabricated `expectation_recall=1.000`
for permissive-only targets) + nits, all fixed in D8. The review also disproved
the original MF-4 deferral (the cached corpora ARE re-scorable; bandit recall
unchanged), so MF-4 was implemented this phase rather than deferred. What held:
the SSRF fix is correct (no new real miss), the OWASP gate provably persists no
number, the JSON scan-report schema is back-compatible.

## Issues found
None blocking after D8. Deferred (with reasons) in NEXT_v028: the deep Java
taint engine (the real OWASP unlock + its definition-of-done), a full real
heavy-eval run to refresh the remaining historical Track-4b/4c cells, and the
SSRF `_url_authority_is_constant` secondary cleanup / B1-findingMatches / B2
path & DVWA-digest hardening.

## Recommendation: **SHIP**
Reason: v0.27 makes Java a first-class scanned language at an honest regex tier,
fixes a real SSRF false negative (restoring a reproducible, CI-gated 1.000),
hardens the OWASP gate against a fabricated number, and removes a live recall
overclaim — with an adversarial 6-lens review that caught (and forced the fix
of) a real Java FP and a doc-published fabrication. No Java or OWASP accuracy
number is claimed; the deep-taint work is honestly scoped to v0.28+.
