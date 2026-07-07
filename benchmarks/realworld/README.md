# Real-world benchmark corpus

Seed entries (twiscope, sanad) are private: their source paths live in a
git-ignored `local.yaml` here, mapping entry name → absolute path:

    twiscope: /Users/you/WorkDir/Twiscope/TwiScope-backend
    sanad: /tmp/Sanad-AI-Agent

When an entry has no configured path the target loud-SKIPs (never silently
green). Public entries clone at a pinned SHA and carry CI. Run:

    fendix benchmark run --target realworld/twiscope   # one seed entry
    fendix benchmark baseline --save                   # record the post-fix baseline

## Seed-tier baseline status (Phase A, 2026-07-07)

The private seed repos (twiscope, sanad) are **absent** on the author machine
and there is no `local.yaml`, so both entries loud-SKIP:

    → realworld/twiscope: scanning...
      SKIPPED: realworld twiscope: benchmark target skipped — no local path
      configured … seed tier is intentionally private
    → realworld/sanad: scanning...
      SKIPPED: realworld sanad: … seed tier is intentionally private

No seed precision number was recorded (a SKIP, not a fabricated 0). `baseline.json`
is deliberately left unchanged: a `baseline --save` restricted to the skipped
realworld entries would overwrite the committed dvwa/juiceshop baseline with an
empty result set. Re-run with the private checkouts + `local.yaml` present to
capture the real post-fix TWISCOPE precision number.

### RESOLVED — matcher defect (findings with positional `SEC-NNN` IDs)

**Was:** `MatchFinding` keyed labels on the finding `ID` expecting the raw
analyzer shape `SEC-PY_SSRF`, but the orchestrator re-numbers every finding to
a positional `SEC-NNN` (`internal/engine/orchestrator.go:581`) before output,
so every real finding scored `unknown` (mini-fixture repro: `1 unknown`,
`UNKNOWN SEC-001 app.py:7`).

**Fix (harness-side only — no orchestrator/output change):** `MatchFinding`
now resolves rule identity through a three-step chain
(go/internal/benchmark/labels.go `ruleMatches`), with the file+line±3 anchor
applying in all paths:

1. **Rule-shaped ID** (remainder after `SEC-` contains letters/underscores,
   e.g. `SEC-PY_SSRF`): direct match on the label's `rule:` — preserves the
   Phase A contract and any engine that keeps rule ids in output.
2. **Positional ID** (`SEC-001`): match via a static `ruleToCWE` map against
   the finding's `references` — the rule identity that survives the
   orchestrator (`CWE-918` for PY_SSRF, `CWE-89` for PY_SQL_INJECTION, …).
   Each CWE was verified against the `_emit_finding` call sites in
   `python/analyzers/ast_analyzer.py` (notably: PY_WEAK_CRYPTO_PASSWORD →
   CWE-916, PY_AUTH_HEADER_TRUST → CWE-290, PY_LLM_PROMPT_INJECTION → CWE-77).
3. **Final fallback** (rule not in the CWE map, or the finding carries no
   references): a deterministic title-keyword table (`ruleTitleKeywords`).

Locked by `TestMatchFindingPositionalIDViaCWE` /
`TestScoreRealWorldPositionalIDs` (unit, hand-built real-shaped findings) and
`TestRealWorldMatcher_MiniFixtureRealScanScoresTP`
(`go test -tags e2e ./internal/e2e/`), which runs a REAL
`fendix scan --code … --python-engine` of the committed mini fixture and
asserts the score flipped from `0 tp / 1 unknown` to `1 tp / 0 unknown`.
