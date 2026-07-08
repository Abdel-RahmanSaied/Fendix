# Real-world benchmark corpus

Seed entries (twiscope, sanad) are private: their source paths live in a
git-ignored `local.yaml` here, mapping entry name → absolute path:

    twiscope: /Users/you/WorkDir/Twiscope/TwiScope-backend
    sanad: /tmp/Sanad-AI-Agent

When an entry has no configured path the target loud-SKIPs (never silently
green). Public entries clone at a pinned SHA and carry CI. Run:

    fendix benchmark run --target realworld/twiscope   # one seed entry
    fendix benchmark baseline --save                   # record the post-fix baseline

## Seed-tier baseline status (Phase B, 2026-07-08)

The TWISCOPE seed checkout is now wired via `local.yaml`
(`twiscope: /Users/asaied/WorkDir/Twiscope/TwiScope-backend`) and its June-triage
label anchors were re-verified against the live checkout (commit `6224eab`;
drift table below). SANAD (`/tmp/Sanad-AI-Agent`) is **absent**, so it loud-SKIPs.

### Live TWISCOPE precision number — CAPTURED 2026-07-08 (Task P unblocked it)

After the Task P perf fix (`perf(sast): memoize _expr_references_secret`, commit
`fb98444`), the full `fendix scan --code <twiscope> --python-engine` now completes
in **9.0 s total** (Python engine pass **2.2 s**, was ~50 min). The
`delivery_tasks.py` file that dominated the old runtime went from >150 s (killed,
still running) to **0.004 s**. The baseline is now trivially reproducible.

**Measured baseline (report `/tmp/twiscope.json`, 72 findings, scored offline):**

    realworld/twiscope: precision 33.3% over 3 labeled (1 tp, 2 fp), 69 unknown, 0.03 findings/KLOC
    FP classes: constant-authority=1  safe-api-misread=1
    tp=1  fp=2  fn=0  unknown=69

**What the number means (read this before quoting 33.3%).** The 33.3% is over a
*deliberately thin* denominator — the 3 labeled findings that STILL FIRE — and is a
lower bound distorted by label coverage, not a true precision. The honest reading:

- **Total 72 findings** = 45 SCA dep-CVEs + 10 hardcoded-secrets + 10 FastAPI
  missing-authn + **5 SAST taint** + 2 Dockerfile. The SAST taint surface — the
  only thing the labels cover — is just **5 findings** (down from ~90 in the June
  triage, i.e. Phase B suppressed the noise).
- **1 TP** — the confirmed Instagram-proxy SSRF (`views.py:602`), matched exactly.
- **2 residual labeled FPs still emitted**: `dispatchers.py:108`
  (`safe-api-misread` — validated webhook URL) and `connection_views.py:236`
  (`constant-authority` open-redirect on a settings-constant base). These two are
  the honest, quantified residual FP classes on this repo.
- **8 of 11 labeled FPs no longer fire** — TwitterAPI.py, FileGenerator,
  notificationApp, health_check, the two redis `.get/.delete`, `settings.py`
  path-traversal, and the psycopg2 `sql.SQL(...).format` SQLi — all correctly
  suppressed by Phase B. Because a suppressed FP simply produces no finding, it
  drops OUT of the denominator, which is *why* the 33.3% looks low: precision is
  computed over survivors, and most survivors that carry a label are the two
  residual FPs. Suppressing FPs shrinks tp+fp, so the ratio understates the win.
- **FN = 0** — the one `tp` label matched; no confirmed vuln was lost.
- **2 unlabeled SAST unknowns to triage**: `SEC-010` path-traversal
  (`TwiScope/EMM/data_handling.py:450`) and `SEC-017` open-redirect
  (`connection_views.py:247`, the second redirect in the same handler as the
  labeled `:236`). Both are candidates for the next label pass (constant-authority
  vs. real, TBD).
- **69 unknown** is dominated (67/69) by SCA + secrets + missing-authn + Dockerfile
  — out of scope for the SAST FP-class labels; they are correctly EXCLUDED from
  precision, not counted against it.

**Label-drift note:** the labels were authored against the June (pre-Phase-B)
triage, so most FP entries now describe findings the engine no longer emits. That
is the intended trajectory (fixes remove FPs), but it means the labeled denominator
is small; the defensible statement is "1 confirmed TP retained, 0 FN, 8/11 known
FP classes eliminated, 2 residual FPs quantified, SAST taint noise cut ~90→5."

**How to reproduce (scan once to JSON, score offline as many times as needed):**

    FENDIX_ENGINE=$PWD/python ./bin/fendix scan \
      --code /Users/asaied/WorkDir/Twiscope/TwiScope-backend \
      --python-engine --format json --output /tmp/twiscope.json      # ~9 s now

    cd go && FENDIX_SCORE_JSON=/tmp/twiscope.json \
      FENDIX_SCORE_LABELS=$PWD/../benchmarks/realworld/twiscope/labels.yaml \
      FENDIX_SCORE_SRC=/Users/asaied/WorkDir/Twiscope/TwiScope-backend \
      FENDIX_SCORE_NAME=twiscope \
      go test ./internal/benchmark/targets/ -run TestOfflineScore -v   # prints the score

**What WAS proven for B1–B8:** every fix is locked by the synthetic corpus gate
(`python/benchmark/corpus.json`, `HANDLED F1 == 1.000`, 22 TP / 0 FP / 0 FN / 28 TN)
plus the committed mini-fixture end-to-end matcher test — all green across B1–B8
with no regression to the pre-existing 1.000 gates. The matcher defect that would
have made ANY real number meaningless (positional `SEC-NNN` IDs scoring as
`unknown`) is fixed and proven by the `-tags e2e` mini-fixture flip
(`0 tp / 1 unknown → 1 tp / 0 unknown`).

`baseline.json` now carries a `realworld/twiscope` entry (`tp=1 fp=2 fn=0`,
`scan_duration=9.014s`) hand-merged alongside the unchanged dvwa/juiceshop DAST
entries — the measured number from 2026-07-08, not a fabricated one. It was
hand-merged (NOT via `baseline --save --target realworld/twiscope`, which rewrites
the whole map and would clobber the DAST entries).

### TWISCOPE label drift (June triage → live checkout, verified 2026-07-08)

Re-anchored in `twiscope/labels.yaml` against the current source:

| Label | June anchor | Live anchor | Note |
| --- | --- | --- | --- |
| Confirmed SSRF TP (Instagram proxy) | `views.py:597` | `views.py:602` | `requests.get(image_url…)` drifted +5 lines |
| FP-1 TwitterAPI.py | file only | `:62` | `get_user_byUserName` f-string base_url |
| FP-1 FileGenerator/controller.py | file only | `:25` | host literal `http://django:8000` |
| FP-2 notificationApp/tasks.py | `notificationApp/…` | `Twiscope_Main_App/notificationApp/tasks.py:86` | path prefix corrected |
| FP-2 health_check | `Twiscope_Main_App/health_check_views.py:32` | `monitoring/views/health_check_views.py:32` | file relocated |
| FP-4 Core/settings.py | file only | `:114` | `BASE_DIR = Path(__file__)…` |
| FP-5 connection_views.py | `linkedInApps/…` | `Twiscope_Main_App/linkedInApps/…:236` | path prefix + first-redirect anchor |

The ±3-line tolerance absorbs residual minor drift; labels with only a file-level
June anchor were set from the live checkout at label time.

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
