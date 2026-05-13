# Sprint 18 — Semgrep rule pack expansion

**Phase:** 6.3 | **Estimate:** 2 days | **Risk:** Low | **Ships:** v0.14.0
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §15.1 — "embedded semgrep rule pack is very small (6 rules)"

---

## Why

The bundled rule pack currently has 9 rules across 3 YAML files (audit said 6 — recount confirms 9, but the pattern stands: small). Customers who don't supply their own rules expect a "deep static analysis" that the bundled pack doesn't deliver. This sprint expands to 20+ rules, focused on patterns the native regex engine cannot catch.

---

## Read first

- [`go/internal/scanner/semgrep/rules/`](../../go/internal/scanner/semgrep/rules/) — existing 3 files:
  - `auth.yaml` (4 rules)
  - `injection.yaml` (3 rules)
  - `secrets.yaml` (2 rules)
- [`go/internal/scanner/semgrep/scanner.go`](../../go/internal/scanner/semgrep/scanner.go) — wrapper around the semgrep subprocess. Bundles rule files via `//go:embed`.
- Semgrep rule syntax: https://semgrep.dev/docs/writing-rules/rule-syntax

---

## Rules to add

### Existing `auth.yaml` — add 2 rules

- **`django-view-no-login-required`** — Django class-based view without `LoginRequiredMixin` and not in `settings.LOGIN_EXEMPT_VIEWS`
- **`flask-route-no-auth-decorator`** — Flask `@app.route(...)` with no `@login_required` or `@requires_auth` decorator within 2 lines above

### Existing `injection.yaml` — add 5 rules

- **`django-raw-sql`** — `Model.objects.raw(<non-literal>)` or `extra(where=[<non-literal>])`
- **`flask-render-template-string`** — `render_template_string(<variable>)` (SSTI surface)
- **`subprocess-shell-true`** — `subprocess.run/Popen/call/check_output(..., shell=True)` with non-literal first arg
- **`pickle-loads`** — `pickle.loads(<network or untrusted input>)` — match by lexical proximity to `request`, `socket.recv`, `urlopen`
- **`yaml-load-unsafe`** — `yaml.load(<input>)` without `Loader=yaml.SafeLoader`

### Existing `secrets.yaml` — add 4 rules

- More secret-assignment variable name patterns: `db_password`, `database_url` with embedded creds, `mongo_uri` with `mongodb://user:pass@`, GCP service account JSON inline (`{"type": "service_account", ...}`)

### NEW `crypto.yaml` — 4 rules

- **`hashlib-md5-for-password`** — `hashlib.md5(<password>)` (proximity-based: password / passwd / pwd in the same scope)
- **`hashlib-sha1-for-password`** — same, sha1
- **`des-rc4-3des`** — `Crypto.Cipher.DES`, `Crypto.Cipher.ARC4`, `Crypto.Cipher.DES3` imports
- **`random-systemrandom-misuse`** — `random.SystemRandom()` when the `secrets` module would be more idiomatic for token generation

Total: 4 (existing auth) + 2 (new auth) + 3 (existing injection) + 5 (new injection) + 2 (existing secrets) + 4 (new secrets) + 4 (new crypto) = **24 rules**.

## Rule file structure (example)

```yaml
# go/internal/scanner/semgrep/rules/crypto.yaml
rules:
  - id: hashlib-md5-for-password
    pattern-either:
      - pattern: hashlib.md5($X.encode()).hexdigest()
      - pattern: hashlib.md5($X).hexdigest()
    pattern-context:
      - pattern-inside: |
          def $FN(..., $X, ...):
            ...
            $... password $...
            ...
    message: |
      MD5 used for password hashing. MD5 is broken cryptographically;
      use bcrypt, scrypt, argon2, or PBKDF2 instead.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-327
      owasp: A02:2021
      fendix-severity: HIGH
```

The `metadata.fendix-severity` key is read by `internal/scanner/semgrep/scanner.go` to map to fendix's `models.Severity`. Confirm the mapping is already implemented; if not, add it in this sprint.

## Tests

For each new rule, in `go/internal/scanner/semgrep/scanner_test.go`:
- 1 positive test (vulnerable code → finding emitted)
- 1 negative test (safe code → no finding)

15 new rules × 2 = **30 new test cases**.

Note: these tests require semgrep installed on the CI runner. Gate behind `command -v semgrep` and skip with a `t.Skip` if absent.

## CHANGELOG

```markdown
### Added (v0.14.0)

- **Semgrep rule pack expanded** from 9 to 24 rules. New rules
  target patterns the native regex engine can't catch (multi-line,
  framework-specific, proximity-based crypto misuse):

  - Django ORM raw SQL injection (`<qs>.raw`, `.extra(where=...)`)
  - Flask `render_template_string` SSTI
  - `subprocess(shell=True)` command injection
  - `pickle.loads` / `yaml.load` deserialization
  - Django/Flask views missing auth decorators
  - MD5/SHA1 for password hashing (proximity-based)
  - DES/3DES/RC4 cipher imports
  - Additional hardcoded-secret variable name patterns

  Rules live under `internal/scanner/semgrep/rules/`; the `crypto.yaml`
  file is new. Each rule carries a `metadata.fendix-severity` tag for
  severity mapping.
```

---

## Risks

- **Flask SSTI rule** historically generates FPs on template-rendering legitimate codebases. Test against a real Flask project (e.g. `flask/flask` itself) and adjust pattern-not-inside to suppress.
- **Django auth rule** depends on the user following Django conventions (class-based views with mixins). FN on function-based views — document.

## Definition of done

Standard DoD plus:
- 30 new test cases (15 positive, 15 negative)
- Each new rule has a comment explaining the FP/FN class
- README updated with the new rule count
- E2E test: scan a known-vulnerable Python project (PyGoat? — already in heavy-eval) and assert new findings appear

## Follow-ups

- **Sprint 18.5:** Rules for Java, Ruby, PHP (if customer-driven)
- **Sprint 18.6:** Rule packs as installable plugins via `fendix plugins install`

## Status

**Not started.**
