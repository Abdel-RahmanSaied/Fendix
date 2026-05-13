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
| **F1**          | **0.961** |
| Precision       | 0.949 |
| Recall          | 0.974 |
| True positives  | 37 / 38 expected |
| False positives | 2 |
| False negatives | 1 |
| Categories at 100 % precision + recall | **5 of 7** |

## Per-category breakdown

| Category | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| sqli | 4 | 1 | 1 | 2 | 0.800 | 0.800 | 0.800 |
| cmdi | 5 | 1 | 0 | 2 | 0.833 | 1.000 | 0.909 |
| path_traversal | 5 | 0 | 0 | 3 | **1.000** | **1.000** | **1.000** |
| ssrf | 3 | 0 | 0 | 2 | **1.000** | **1.000** | **1.000** |
| open_redirect | 3 | 0 | 0 | 2 | **1.000** | **1.000** | **1.000** |
| xss | 4 | 0 | 0 | 2 | **1.000** | **1.000** | **1.000** |
| secrets | 13 | 0 | 0 | 3 | **1.000** | **1.000** | **1.000** |
| **OVERALL** | **37** | **2** | **1** | **16** | **0.949** | **0.974** | **0.961** |

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

**Five categories are at 100 % precision + recall** — path traversal,
SSRF, open redirect, XSS, and secrets. For these categories the
engine correctly flags every vulnerable shape we threw at it and
correctly ignores every safe-shape variant. Recall = 1.000 means no
silent misses; precision = 1.000 means no spurious flags. (Open
redirect was at **0 % recall before this measurement run** — the
detection logic only matched direct `redirect(request.args.get("x"))`
calls and missed the much more common
`url = request.args["x"]; return redirect(url)` shape. Fixing it
during this evaluation upgraded the detector to use the same
constant-vs-non-constant filter the other reachable sinks already
had.)

**SQL injection comes in at F1 = 0.800.** Four of five vulnerable
shapes get flagged; one is missed and one safe-shape is incorrectly
flagged. Detail in the "Known gaps" section below.

**Command injection at F1 = 0.909.** All five vulnerable shapes are
flagged (100 % recall); one safe-shape literal-string `os.system`
call is flagged as well, dropping precision to 0.833. This is a
**deliberate engine posture** — TASK-121 chose to emit on every
`os.system` / `os.popen` / `subprocess(shell=True)` call site, with
reachability as the second-stage refinement. Literal-string args
land as a HIGH finding without `reachable: true`; users who want the
literal-string suppression can add a `.fendix-ignore` rule.

## Known gaps

| Category | Issue | Severity |
|---|---|---|
| sqli | One vulnerable shape (line 16 in `sqli.py`, `case_01_request_string_concat`) was not flagged in the engine's reported endpoint set even though it's the canonical concat pattern. Worth investigating whether the detector handles this specific assignment shape or is masking it as `case_02_request_fstring`'s shadow. | Real miss — needs follow-up |
| sqli | False positive at `sqli.py:50` — the parameterized-safe variant got flagged. Suggests the AST analyzer's safety filter for `cursor.execute(...)` doesn't catch the canonical `?`-parameterized form when the binding tuple is non-literal. | Real FP — needs follow-up |
| cmdi | `os.system("echo hello world")` (literal string, no user input) gets flagged HIGH. Deliberate engine conservatism per TASK-121: fire on every shell-out, let reachability refine. | Intentional |

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
