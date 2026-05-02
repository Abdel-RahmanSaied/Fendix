#!/usr/bin/env bash
set -euo pipefail

# Seed the first batch of "good first issue" issues on the repo.
# Run once after making the repo public.
#
# Prerequisites: gh CLI authenticated (gh auth status)
# Usage: ./scripts/seed-issues.sh

REPO="Abdel-RahmanSaied/Fendix"

echo "Creating good-first-issue tickets on $REPO..."
echo ""

# Ensure labels exist (gh errors if label doesn't exist on the repo)
echo "Ensuring labels exist..."
gh label create "good first issue" --repo "$REPO" --color 7057ff --description "Good for newcomers" 2>/dev/null || true
gh label create "help wanted" --repo "$REPO" --color 008672 --description "Extra attention is needed" 2>/dev/null || true
gh label create "semgrep-rule" --repo "$REPO" --color fbca04 --description "New Semgrep detection rule" 2>/dev/null || true
gh label create "documentation" --repo "$REPO" --color 0075ca --description "Improvements or additions to documentation" 2>/dev/null || true
gh label create "plugin" --repo "$REPO" --color d4c5f9 --description "Plugin system extension" 2>/dev/null || true
echo ""

gh issue create --repo "$REPO" \
  --title "rule: detect subprocess.run(shell=True) without input validation" \
  --label "good first issue,semgrep-rule,help wanted" \
  --body "$(cat <<'EOF'
## Rule summary

Detect `subprocess.run(..., shell=True)` where the command string includes
an f-string or `.format()` interpolation of a variable that isn't validated.

## Language(s)

Python

## Example vulnerable code

```python
def run_cmd(user_input):
    subprocess.run(f"grep {user_input} /var/log/app.log", shell=True)
```

## Example safe code

```python
def run_cmd(user_input):
    subprocess.run(["grep", user_input, "/var/log/app.log"])
```

## CWE / OWASP reference

CWE-78: Improper Neutralization of Special Elements used in an OS Command

## Suggested severity

HIGH

## Implementation notes

- Add to `python/rules/injection.yaml`
- Similar to the existing `dangerous-subprocess` rule but tighter (only shell=True + interpolation)
- Reference: `examples/plugins/custom-semgrep-pack/rules/subprocess-shell.yaml`

### Contribution checklist

- [ ] Rule YAML added to `python/rules/injection.yaml`
- [ ] At least 1 true-positive test case in `python/tests/fixtures/`
- [ ] At least 1 true-negative test case
- [ ] `python -m pytest python/tests/test_semgrep_runner.py` passes
EOF
)"

echo "  [1/5] subprocess shell=True rule"

gh issue create --repo "$REPO" \
  --title "rule: detect Django raw SQL queries without parameterization" \
  --label "good first issue,semgrep-rule,help wanted" \
  --body "$(cat <<'EOF'
## Rule summary

Detect Django's `cursor.execute()` or `RawSQL()` where the query string
uses f-strings, `.format()`, or `%` interpolation instead of parameterized queries.

## Language(s)

Python

## Example vulnerable code

```python
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

## Example safe code

```python
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
```

## CWE / OWASP reference

CWE-89: SQL Injection

## Suggested severity

CRITICAL

## Implementation notes

- Add to `python/rules/injection.yaml`
- The existing AST analyzer catches generic `cursor.execute(sql)` patterns;
  this Semgrep rule adds Django-specific coverage (`connection.cursor()`, `RawSQL`)

### Contribution checklist

- [ ] Rule YAML added to `python/rules/injection.yaml`
- [ ] At least 1 true-positive test case in `python/tests/fixtures/`
- [ ] At least 1 true-negative test case
- [ ] `python -m pytest python/tests/test_semgrep_runner.py` passes
EOF
)"

echo "  [2/5] Django raw SQL rule"

gh issue create --repo "$REPO" \
  --title "rule: detect Express.js response without helmet() middleware" \
  --label "good first issue,semgrep-rule,help wanted" \
  --body "$(cat <<'EOF'
## Rule summary

Detect Express apps that call `app.listen()` without importing or using
`helmet` (or manually setting security headers).

## Language(s)

JavaScript / TypeScript

## Example vulnerable code

```javascript
const app = express();
app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
```

## Example safe code

```javascript
const app = express();
app.use(helmet());
app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
```

## CWE / OWASP reference

CWE-693: Protection Mechanism Failure

## Suggested severity

MEDIUM

## Implementation notes

- Add to `python/rules/injection.yaml` (Semgrep rules live under `python/rules/` even for JS targets — Semgrep handles multi-language)
- This is a file-level pattern — look for `express()` + `listen()` without `helmet`
- Semgrep's `pattern-not` + `pattern-inside` combinators make this ergonomic
- Test fixtures go in `python/tests/fixtures/` as `.js` files

### Contribution checklist

- [ ] Rule YAML added to `python/rules/injection.yaml` (with `languages: [javascript, typescript]`)
- [ ] At least 1 true-positive `.js` test fixture in `python/tests/fixtures/`
- [ ] At least 1 true-negative `.js` test fixture
- [ ] `python -m pytest python/tests/test_semgrep_runner.py` passes
EOF
)"

echo "  [3/5] Express.js helmet rule"

gh issue create --repo "$REPO" \
  --title "docs: add juice-shop walkthrough screenshots to README" \
  --label "good first issue,documentation,help wanted" \
  --body "$(cat <<'EOF'
## Summary

The README references a juice-shop benchmark but has no screenshots showing
what a Fendix scan report looks like. Add 2-3 annotated screenshots.

## Context

First-time visitors to the repo need to see what the output looks like
before they invest time installing. The `fendix demo` command produces
an HTML report against juice-shop — capture that.

## Acceptance criteria

- [ ] 2-3 screenshots added to `docs/images/` (PNG, <500KB each)
- [ ] README.md updated with `![...]()` references in the "Quick start" section
- [ ] Screenshots show: (a) terminal output of a scan, (b) HTML report summary, (c) a finding detail

## How to reproduce

```bash
# Requires Docker
fendix demo --open
# Screenshot the terminal + the HTML report that opens
```
EOF
)"

echo "  [4/5] README screenshots"

gh issue create --repo "$REPO" \
  --title "plugin: custom header compliance check (reference plugin)" \
  --label "good first issue,plugin,help wanted" \
  --body "$(cat <<'EOF'
## Summary

Write a reference plugin that checks API responses for a required custom
header (e.g., `X-Request-Id` for tracing). This demonstrates the blackbox
plugin contract with a simple, achievable scope.

## Context

Demonstrates the plugin system (docs/plugins.md) with a real-world use case
beyond the existing 3 reference plugins. Shows how a blackbox plugin can
bring its own compliance logic without modifying the core engine.

## Acceptance criteria

- [ ] Plugin lives at `examples/plugins/required-header-check/`
- [ ] `plugin.yaml` with mode: blackbox, timeout: 30s
- [ ] Entrypoint script (Python) that reads ScanRequest, makes GET requests
      to each endpoint, checks for the configured header
- [ ] Emits LOW finding for each endpoint missing the header
- [ ] Header name configurable via env var (default: `X-Request-Id`)
- [ ] README in the plugin directory explaining what it does
- [ ] Works end-to-end: `fendix scan --url http://target` picks it up

## Pointers

- Plugin authoring guide: `docs/plugins.md`
- Existing reference plugins: `examples/plugins/`
- Look at `examples/plugins/custom-blackbox-check/` for the closest pattern

## How to test

```bash
cp -r examples/plugins/required-header-check ~/.fendix/plugins/
# Start any HTTP server that doesn't set X-Request-Id
python3 -m http.server 9999 &
fendix scan --url http://localhost:9999
# Should see the plugin's finding in output
kill %1
```
EOF
)"

echo "  [5/5] Required header check plugin"

echo ""
echo "Done! 5 good-first-issue tickets created."
echo "View them: gh issue list --repo $REPO --label 'good first issue'"
