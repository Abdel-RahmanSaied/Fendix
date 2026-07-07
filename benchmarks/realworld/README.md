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

### KNOWN DEFECT — the finding→label matcher does not match real scans

`ScoreRealWorld` / `MatchFinding` (go/internal/benchmark/labels.go) keys a label
to a finding by the finding's `ID` field, expecting the shape `SEC-PY_SSRF`
(rule id embedded). **The production JSON report does not carry the rule id in
`ID`.** The orchestrator re-numbers every finding to a positional `SEC-NNN`
(`internal/engine/orchestrator.go:581` → `findings[i].ID = fmt.Sprintf("SEC-%03d", i+1)`),
so a real SSRF finding emits as `SEC-001`, and `ruleOf("SEC-001")` = `"001"` ≠
`"PY_SSRF"`. Every real finding therefore scores as `unknown`, never `tp`/`fp`.

Reproduced end-to-end against the committed mini fixture (a real
`fendix scan --python-engine` of testdata/realworld/mini):

    realworld/_minicheck: precision 0.0% over 0 labeled (0 tp, 0 fp), 1 unknown …
      UNKNOWN  SEC-001  app.py:7

The rule identity that DOES survive to the report is the CWE reference
(`references: ["CWE-918"]` for SSRF, `CWE-89` for SQLi, …) and the `title`;
`category` is too coarse (SSRF/SQLi/path-traversal all → `injection`). The
matcher key (and the `rule:` field in every labels.yaml) must be reworked onto a
surviving signal (CWE, or a rule→title/CWE map) before any Phase B precision
delta is meaningful. The plan's A1.3 premise — "the finding's rule id is
`models.Finding.ID` with shape `SEC-PY_SSRF`" — is stale.
