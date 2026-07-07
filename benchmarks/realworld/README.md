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

### Live TWISCOPE precision number — NOT captured this run (scan exceeds window)

The full `fendix scan --code <twiscope> --python-engine` does not complete within
the practical window on this machine: the TWISCOPE tree is ~1,188 Python files
(9,592 incl. `.venv`), and the AST pass runs **~45–50 min**, dominated by an
O(fan-out) pathology in `ASTAnalyzer._expr_references_secret` — it restarts
`ast.walk(expr)` for every resolved binding, so a large logging call in a large
scope (e.g. `Twiscope_Main_App/Alert_System/tasks/delivery_tasks.py`, ~45 s for
that single file) blows up combinatorially. This is a **performance** issue in the
secret-in-log path, unrelated to the Phase B precision fixes and out of scope for
v1.1 (engine behavior/perf changes are a spec non-goal). No number is fabricated.

**How to capture it (reproducible):** scan once to a persistent JSON, then score
offline with the committed scorer (`offlinescore_test.go`, commit `6224eab`) — no
re-scan needed to re-score after label edits:

    FENDIX_ENGINE=$PWD/python ./bin/fendix scan \
      --code /Users/asaied/WorkDir/Twiscope/TwiScope-backend \
      --python-engine --format json --output /tmp/twiscope.json      # ~50 min

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

`baseline.json` keeps its dvwa/juiceshop entries unchanged (no `realworld/twiscope`
entry added — a number is never fabricated). When the scan is captured, hand-merge
a `realworld/twiscope` entry alongside dvwa/juiceshop (never `baseline --save
--target realworld/twiscope`, which rewrites the whole map and clobbers the DAST
entries).

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
