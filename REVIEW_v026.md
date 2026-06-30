# Code Review — Fendix v0.26 (Accuracy & Benchmarking)
Reviewed by: Reviewer Agent (informed by the 6-lens adversarial review workflow)
Date: 2026-06-30

## Exit criteria: **PASS**
> *"Honest, reproducible, published accuracy numbers. No marketing claim without a re-runnable benchmark."* (Rule 5)

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Every published number reproducible | ✅ | BENCHMARKS.md: each number has a command + corpus + stamp + caveat. Verified by re-running: taint 1.000, synthetic 0.987, DAST 13/0 + 12/5. |
| No marketing claim without a benchmark | ✅ | Stale v0.11.0 headline (1.000) reconciled to 0.987 across README/accuracy.md/marketplace/launch-post/operator-rollout; unbacked correlator FP claims softened to mechanism language. |
| Can't silently drift again | ✅ | `scripts/accuracy/run.py --min-f1` + push/PR CI gate at F1 ≥ 0.98 (the missing guard behind the original drift). |
| OWASP handled honestly | ✅ | Loud-SKIP preserved; documented in BENCHMARKS.md; verified no fabricated 0.0 can be persisted. Deferred to v0.27 (Java). |

## Product Constitution: **PASS**
| Rule | Status | Note |
|------|--------|------|
| 1 Never rewrite working systems | ✅ | Built on the existing harnesses; scanner binary unchanged; gate added as an opt-in flag. |
| 2 Trust before features | ✅ | Honest reconciliation (incl. disclosing the SSRF FN) is a trust improvement. |
| 5 Benchmark before marketing | ✅ | Every number reproducible + stamped + gated; OWASP/Java omission documented. |
| 8 AI never decides | ✅ | Scoring is deterministic; bootstrap RNG now per-call; no AI/network at score time. |

## Adversarial review (6 independent refutation lenses)
Verdict **FIX-FIRST** → all addressed → **SHIP**. The review caught a real
arithmetic error (corpus 56/38, not 55/37) and an unswept doc
(`operator-rollout.md` still at 1.000) — both fixed in D8, plus the medium
(marketing-plan recall) and nits (bootstrap RNG, NIST-framing comments, count
drift, stamp). What holds was extensive: SAST/taint/DAST all reproduce exactly,
the gate works, OWASP is safe, Rule 8 holds.

## Issues found
None blocking after D8. Deferred (with reasons) in NEXT_v027: the SSRF
multi-hop taint fix (restores 1.000 legitimately), B1/B2 DAST scorer honesty +
reproducibility, B5 corpus quality (real negatives, remove committed Mach-O,
vendored corpus), MF-4 (heavy-eval min_count:0 denominator), MF-6 (perf
marketing regen). The pre-existing `benchmark baseline --save` single-target
clobber is noted for hardening.

## Recommendation: **SHIP**
Reason: v0.26 turned Fendix's accuracy story from assertion into evidence —
every published number is now reproducible, stamped, caveated, and CI-gated
against drift; the one real gap (a multi-hop SSRF FN) is disclosed rather than
rounded away; and an adversarial 6-lens review (which found and forced the fix
of a wrong count and an unswept doc) confirms the result is honest and complete.
