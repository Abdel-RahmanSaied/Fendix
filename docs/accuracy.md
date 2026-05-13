# Fendix accuracy scorecard

This page reports fendix's true-positive, false-positive, and
false-negative rates against a labeled corpus mapped to the engine's
actual detection categories. The numbers below come from running the
v0.11.0 binary against `scripts/accuracy/corpus/` — every emission is
classified TP/FP/FN/TN against `scripts/accuracy/manifest.json`, and
per-category precision/recall/F1 fall out.

Run it yourself:

```bash
make build
python3 scripts/accuracy/run.py --python-engine
```

The harness writes the scorecard to stdout and (with `--output-json`)
a machine-readable JSON for CI gating.

## Headline numbers (v0.11.0, 2026-05-13)

| Metric | Value |
|---|---:|
| **F1**          | **1.000** |
| Precision       | 1.000 |
| Recall          | 1.000 |
| True positives  | 38 / 38 expected |
| False positives | 0 |
| False negatives | 0 |
| Categories at 100 % precision + recall | **7 of 7** |

## Per-category breakdown

| Category | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| sqli | 5 | 0 | 0 | 3 | **1.000** | **1.000** | **1.000** |
| cmdi | 5 | 0 | 0 | 3 | **1.000** | **1.000** | **1.000** |
| path_traversal | 5 | 0 | 0 | 3 | **1.000** | **1.000** | **1.000** |
| ssrf | 3 | 0 | 0 | 2 | **1.000** | **1.000** | **1.000** |
| open_redirect | 3 | 0 | 0 | 2 | **1.000** | **1.000** | **1.000** |
| xss | 4 | 0 | 0 | 2 | **1.000** | **1.000** | **1.000** |
| secrets | 13 | 0 | 0 | 3 | **1.000** | **1.000** | **1.000** |
| **OVERALL** | **38** | **0** | **0** | **18** | **1.000** | **1.000** | **1.000** |

## What was tested

The corpus has **56 labeled cases** across 7 categories — every
detection category fendix advertises whitebox coverage for:

- **6 reachable taint-chain categories** introduced over TASK-114
  (SQLi / SSRF / open-redirect, v0.7), TASK-120 (XSS, v0.8),
  TASK-121 (cmd-injection, v0.8), TASK-134 (path-traversal, v0.11)
- **1 native-Go secrets scanner** (TASK-115, v0.9) covering 15
  pattern families plus the `.env`-only `ENV_SECRET` regex

For each category the corpus has both **EXPECT_TP** cases (the
engine SHOULD flag) and **EXPECT_TN** cases (safe-shape, the engine
should leave alone). Every test case is a short, realistic function
demonstrating a single canonical pattern; ground-truth labels live
in [`scripts/accuracy/manifest.json`](../scripts/accuracy/manifest.json).

## What the scorecard tells us

**All seven categories at 100 % precision and recall.** For every
vulnerable shape in the corpus, the engine flags it; for every safe-
shape variant, the engine leaves it alone. No silent misses, no
spurious flags. 38 of 38 expected detections; 0 of 18 safe cases
mis-flagged.

This is the result of two real engine improvements surfaced during
this measurement run:

1. **`_is_open_redirect` upgraded to taint-chain posture parity.**
   Pre-fix, the detector only matched direct
   `redirect(request.args.get("x"))` calls; the far more common
   multi-hop `url = request.args["x"]; return redirect(url)` was
   silently missed. The other six reachable sinks
   (SQLi / SSRF / XSS / cmd-injection / path-traversal) were
   upgraded to constant-vs-non-constant filtering in
   TASK-114/120/121/134; open-redirect was the original TASK-114
   sink and somehow never got the chain treatment. Open-redirect
   recall: 0/3 → 3/3.

2. **cmdi posture aligned with the other reachable sinks.**
   Pre-fix, `os.system` / `os.popen` / `subprocess(shell=True)` fired
   unconditionally regardless of arg content (a deliberate TASK-121
   conservatism). On the labeled corpus that surfaced as a real FP:
   `os.system("echo hello world")` got flagged HIGH despite zero
   exploitability. New `_cmdi_arg_is_dangerous` helper skips on
   Constant args and on Name args that resolve to a Constant in
   scope — same pattern SSRF/XSS/path-traversal/open-redirect already
   use. cmdi precision: 0.833 → 1.000.

Plus one orchestrator bug fix: `runWhiteboxScan` now resolves
`code_path` and `spec` to absolute paths before sending the
ScanRequest. The Python spawner sets `cmd.Dir = engineDir` (the
python/ tree), so a relative `code_path` from the caller's cwd
silently resolved to nothing — surfaced as fendix reporting zero
findings on every real codebase using `--python-engine`.

## Known gaps

**No known gaps in the corpus's 7 categories** as of v0.11.0 +
post-evaluation fixes. The headline 1.000/1.000/1.000 is honest at
the corpus's scope. The corpus is small (56 cases, 7 categories) and
synthetic, so a 1.000 score doesn't mean fendix never misses — it
means fendix never misses *these specific canonical patterns*. Real-
world FP discipline is tracked separately in
[`tasks/FP_CORPUS.md`](../tasks/FP_CORPUS.md) against juice-shop,
this repo's own test fixtures, and TwiScope's deepin spec.

**Categories not in the corpus** (engine has no coverage so we don't
score them here, but worth listing for honesty):

- **IDOR** (Insecure Direct Object Reference) — requires blackbox
  two-user auth comparison; not a static-analysis problem fendix
  attempts. Covered by the blackbox `CheckIDOR` scanner instead.
- **CSRF** — same shape; blackbox/template-side check, not AST.
- **Hardcoded JWT validation bypass** — caught by Semgrep when the
  semgrep rule fires correctly; the bundled `auth.yaml`'s JWT rule
  has a known YAML format issue documented in `docs/plugins.md`.
- **Insecure deserialization** (pickle / yaml.unsafe_load) — caught
  by AST patterns but NOT with reachability chains (no TASK-134
  equivalent for pickle). Future-task candidate.
- **LDAP injection** — no coverage today; was offered as a TASK-134
  alternative but path-traversal was chosen for broader real-world
  impact.

These are documented as a forward-looking backlog, not papered over.

## Methodology

The harness (`scripts/accuracy/run.py`):

1. Runs `fendix scan --code corpus/ --format json` against the labeled fixtures.
2. Explodes each finding's `affected_endpoints` array into virtual
   per-endpoint findings (the engine dedups, the scorer counts each
   endpoint independently).
3. For each finding, matches by:
   - `category` field equals the manifest's `expected_category`
   - finding `title` contains any of `title_substrings` for the
     category
   - emission endpoint's file matches the fixture file path (basename or full)
   - emission line is within ±6 of a labeled case line (covers
     def-line vs sink-line offset)
4. Pairs emissions to TP/TN labels using **nearest-unclaimed-TP**
   matching so a single TP can't be claimed by multiple emissions.
5. Reports per-category and overall TP/FP/FN/TN, then derives
   precision / recall / F1.

The matcher uses `title` and `category` (not the engine-assigned
`SEC-NNN` ID, which is renumbered at scan-end) so the scorecard is
robust to ID-renumbering changes. The line tolerance handles the
gap between the labeled `def case_NN_*():` line and the actual sink
line a few rows below.

The corpus is small (56 cases) and synthetic. It is *not* a
substitute for real-world false-positive measurement against
production codebases — that's what `tasks/FP_CORPUS.md` tracks, and
it deliberately uses real targets (juice-shop, this repo's own
test fixtures, the TwiScope deepin spec) for the FP discipline
work in Phase 17a + 17d. The synthetic corpus complements the
real-world FP corpus by measuring the *positive* side: which
vulnerabilities the engine catches when they're present.

## Reproduce

```bash
# Build the engine
make build

# Run the harness
python3 scripts/accuracy/run.py --python-engine

# For CI consumption (machine-readable JSON)
python3 scripts/accuracy/run.py --python-engine --output-json /tmp/accuracy.json
```

The harness needs `--python-engine` because the 6 reachable
taint-chain categories live in the Python whitebox engine (the
native-Go path doesn't have AST analysis yet). The secrets category
runs in native Go and is exercised even without the flag.
