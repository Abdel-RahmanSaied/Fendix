# Semgrep Rules Check

**Engine:** Python (white-box)
**Category:** `semgrep` (mapped to `auth`, `injection`, `secrets`)
**Default severity:** Varies by rule
**Active probing:** No (static analysis)

## What It Detects

Security-relevant code patterns using custom Semgrep rules. Semgrep performs pattern matching on the abstract syntax tree (AST) of source code, catching issues that simple regex cannot.

## Built-in Rules

### auth.yaml — Missing Authentication

| Rule ID | Pattern | Languages |
|---|---|---|
| `missing-flask-login-required` | Flask routes without `@login_required` | Python |
| `missing-django-login-mixin` | Django views without `LoginRequiredMixin` | Python |
| `missing-fastapi-depends` | FastAPI routes without `Depends()` auth | Python |
| `jwt-decode-no-verify` | `jwt.decode()` with `verify=False` | Python |

### injection.yaml — Injection Patterns

| Rule ID | Pattern | Languages |
|---|---|---|
| `sql-string-format` | SQL queries using `%` string formatting | Python |
| `subprocess-shell-true` | `subprocess.run(..., shell=True)` | Python |
| `eval-exec-usage` | Direct use of `eval()` or `exec()` | Python |

### secrets.yaml — Hardcoded Secrets

| Rule ID | Pattern | Languages |
|---|---|---|
| `hardcoded-secret-assignment` | Variable named `secret`/`password`/`key` assigned a string literal | Python |
| `database-url-credentials` | Database URLs with embedded username:password | Python |

## How It Works

1. Invokes `semgrep --config <rules_dir> --json --quiet <code_path>`
2. Parses Semgrep JSON output and maps to Fendix Finding format
3. Maps Semgrep severity to Fendix severity (ERROR→HIGH, WARNING→MEDIUM, INFO→LOW)
4. If Semgrep is not installed, logs a warning and skips gracefully

## Adding Custom Rules

Place YAML rule files in `python/rules/`. The Semgrep runner automatically picks up all `.yaml` files in the rules directory. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the rule template.

## Example Finding

```json
{
  "title": "SQL query uses string formatting",
  "severity": "HIGH",
  "source": "whitebox",
  "category": "injection",
  "endpoint": "src/db.py:23",
  "evidence": "query = \"SELECT * FROM users WHERE id = %s\" % user_id",
  "fix": "Use parameterized queries instead of string formatting.",
  "references": ["CWE-89"],
  "line": "src/db.py:23"
}
```

## References

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78: Command Injection](https://cwe.mitre.org/data/definitions/78.html)
