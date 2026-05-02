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

- New file: `python/rules/headers.yaml` (or add to an existing JS rules file)
- This is a file-level pattern — look for `express()` + `listen()` without `helmet`
- Semgrep's `pattern-not` + `pattern-inside` combinators make this ergonomic

### Contribution checklist

- [ ] Rule YAML added to `python/rules/`
- [ ] At least 1 true-positive test case in `python/tests/fixtures/`
- [ ] At least 1 true-negative test case
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
  --title "plugin: AWS credential rotation check (reference plugin)" \
  --label "good first issue,plugin,help wanted" \
  --body "$(cat <<'EOF'
## Summary

Write a reference plugin that checks for AWS credentials older than 90 days
in source code (by parsing the credential format's embedded date, or by
checking `.aws/credentials` last-modified metadata).

## Context

Demonstrates the plugin system (docs/plugins.md) with a real-world use case
beyond the existing 3 reference plugins. Shows how a plugin can bring its
own domain logic without modifying the core engine.

## Acceptance criteria

- [ ] Plugin lives at `examples/plugins/aws-credential-age/`
- [ ] `plugin.yaml` with mode: whitebox, timeout: 30s
- [ ] Entrypoint script (Python or Bash) that reads ScanRequest, scans for
      AWS access keys, checks if the embedded date component is >90 days old
- [ ] Emits MEDIUM finding with evidence showing the key prefix + age
- [ ] README in the plugin directory explaining what it does
- [ ] Works end-to-end: `fendix scan --code ./fixture` picks it up

## Pointers

- Plugin authoring guide: `docs/plugins.md`
- Existing reference plugins: `examples/plugins/`
- AWS key format: `AKIA[A-Z0-9]{16}` — no embedded date, so this plugin
  would need to check file mtime or git blame date as a heuristic

## How to test

```bash
mkdir -p ~/.fendix/plugins/
cp -r examples/plugins/aws-credential-age ~/.fendix/plugins/
echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' > /tmp/test/.env
fendix scan --code /tmp/test
# Should see the plugin's finding in output
```
EOF
)"

echo "  [5/5] AWS credential age plugin"

echo ""
echo "Done! 5 good-first-issue tickets created."
echo "View them: gh issue list --repo $REPO --label 'good first issue'"
