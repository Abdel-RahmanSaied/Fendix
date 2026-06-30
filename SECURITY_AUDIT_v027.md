# Security Audit — Fendix v0.27 (Java analyzer, first increment)
Audited by: Security Agent (+ 6-lens adversarial review workflow)
Date: 2026-06-30
Scope: SSRF taint fix, Java regex SAST rules, OWASP two-layer skip gate,
benchmark/heavy-eval honesty cleanup.

## Findings
### CRITICAL / HIGH (security) — none unresolved.
The review's two HIGH findings were a SAST false-positive (Java SQL rule
over-firing on `Executor.execute`) and a Rule-5 accuracy overclaim — both fixed
in D8. Neither was an exploitable vulnerability in Fendix.

## Positive — detection capability improved (Rule 2: trust)
- **SSRF multi-hop taint fix.** Fendix now detects the `"scheme://" + tainted`
  SSRF shape it previously missed (a real detection gain), restoring synthetic
  F1 to 1.000 — reproducibly and CI-gated, not a stale claim. Conservative,
  recall-preserving authority handling (documented over-fire on `:port`).
- **Java SAST coverage.** Four new line-local Java rules (cmdi, SQLi, weak
  crypto, insecure deserialization) — real coverage of a previously-blind
  language, honestly tiered as regex (`TierNativeGo`), not taint.

## New attack-surface analysis
- **Java rules add no execution/injection surface** — they are read-only regex
  over `.java` files, same mechanism as the existing Go/JS rules. The
  Executor.execute false positive is fixed (the regex no longer crosses an
  inner call and only matches JDBC-specific method names).
- **No untrusted input reaches a shell/eval** in any v0.27 code path (Go
  scanner, Python taint, heavy-eval scorer). The heavy-eval scorer change is
  pure arithmetic/classification.

## Rule 5 (benchmark before marketing) — strengthened
- **No Java or OWASP accuracy number is published.** Java is documented as
  regex/line-local with no recall figure (no labeled Java corpus).
- **OWASP cannot emit a fabricated number** — `Scan()` AND `Run()` both return
  `ErrTargetSkipped` (machine-pinned by `TestOWASPSkipsInBothLayers`); the
  reason string honestly states deep Java taint is required (→ v0.28+).
- **Removed a live overclaim:** `min_count:0` presence-advisory rows no longer
  count toward `expectation_recall` (scorer + docs), so targets that measure
  nothing no longer publish a fabricated 1.000.

## Rule 8 (AI never decides) — holds
Detection (regex, taint) and scoring (deterministic counts/ratios, seeded
bootstrap) involve no AI/network at decision time.

## Sign-off
- [x] No unresolved CRITICAL/HIGH security findings
- [x] Net detection improvement (SSRF) + new Java coverage, honestly tiered
- [x] No new injection/execution surface
- [x] Rule 5: no Java/OWASP number; OWASP can't fabricate one; recall overclaim removed
- [x] Rule 8: deterministic, no AI/network in detection or scoring
