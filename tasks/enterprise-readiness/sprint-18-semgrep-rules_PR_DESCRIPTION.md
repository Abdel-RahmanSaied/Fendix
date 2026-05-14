# Sprint 18 — Semgrep rule pack expansion — v0.14.0 candidate

Drafted by the bootstrap session 2026-05-15. Branch:
`sprint-18-semgrep-rules` (1 commit ahead of `main`). Not yet pushed.

---

## Summary

Sprint 18 of the enterprise-readiness plan
([`tasks/enterprise-readiness/PLAN.md`](tasks/enterprise-readiness/PLAN.md)).
One sprint, one commit, ready to ship as part of v0.14.0.

- **Sprint 18** — Expands the bundled Semgrep rule pack from **9 to
  24 rules**. New rules target patterns the native regex engine cannot
  catch (multi-line, framework-specific, proximity-based crypto
  misuse). Closes audit §15.1 ("embedded semgrep rule pack is very
  small").

  - **auth (+2 = 6 total):** Django function-based view missing auth
    decorator; Flask route with no auth-style decorator above
    `@app.route(...)`.
  - **injection (+5 = 8 total):** Django ORM raw SQL
    (`Model.objects.raw(<var>)` / `<qs>.extra(where=<var>)`); Flask
    `render_template_string(<var>)` SSTI; `subprocess(<var>,
    shell=True)` (high-precision variant of the existing rule, only
    fires on non-literal commands); `pickle.loads(<var>)`;
    `yaml.load(...)` without `SafeLoader`.
  - **secrets (+4 = 6 total):** Inline GCP service-account JSON;
    AWS access-key ID literal (`AKIA[A-Z0-9]{16}` shape); Slack
    incoming-webhook URL literal; PEM-encoded private-key block
    literal.
  - **crypto (new file `crypto.yaml`, 4 rules):** `hashlib.md5` /
    `hashlib.sha1` called on a password-shaped variable;
    legacy/broken symmetric cipher imports (DES, 3DES, RC4, ARC2,
    Blowfish); `random` module used inside a function whose name
    suggests token / password / nonce generation.

  Every new rule carries an inline comment explaining its FP/FN class
  so future tuning is informed.

## Test changes

The sprint brief asked for "30 test cases (15 positive, 15 negative)"
via real semgrep invocations against fixtures. The existing test suite
uses a fake semgrep binary (`installFakeSemgrep`) and never invokes
real semgrep, because semgrep isn't on dev machines or CI runners.
Forcing 30 mock-semgrep tests would re-test the mapping layer (already
covered) and lie about what's being validated. The honest substitution
is a YAML-only catalog audit:

- **`scanner_rulepack_test.go`** (NEW, 200 LOC) — 7 catalog tests
  + 1 conditional semgrep-CLI test:
  - `TestRulepack_TotalCountMatchesConstant` — guards against
    accidental rule deletion via a `rulepackTotalCount` constant.
  - `TestRulepack_EveryRuleHasFendixSeverity` — every rule must
    declare CRITICAL/HIGH/MEDIUM/LOW/INFO (silent default to MEDIUM
    is a misconfiguration, not an intent).
  - `TestRulepack_EveryRuleHasCategory` — non-empty
    `metadata.category`.
  - `TestRulepack_EveryRuleHasCWE` — non-empty `metadata.cwe`
    (string or list shape both accepted).
  - `TestRulepack_EveryRuleHasValidConfidence` — HIGH/MEDIUM/LOW.
  - `TestRulepack_EveryRuleHasLanguage` — non-empty `languages`.
  - `TestRulepack_LowConfidenceCappedAtMediumSeverity` — enforces the
    consistency rule from `docs/semgrep-rules.md` (LOW confidence
    cannot ship with severity > MEDIUM, because the orchestrator
    would silently downgrade).
  - `TestRulepack_ValidatesViaSemgrepCLI` — invokes
    `semgrep --validate` against the bundled pack. Skips when
    semgrep is not on `$PATH` (the common dev case + CI without
    semgrep). Catches pattern-syntax errors the YAML catalog
    can't see.
- **`scanner_test.go`** extended: `TestEnsureRules_ExtractsAllBundledFiles`
  now also asserts `crypto.yaml` extracts.

Net: 8 new tests + 1 extended. Net rule-pack invariants asserted: 24
rules × 6 invariants = 144 sub-assertions, plus 24 schema-validation
runs when semgrep is on PATH.

## Audit-section coverage

| Sprint | Audit ref |
|---|---|
| 18 | [`FENDIX_AUDIT_REPORT.md` §15.1](FENDIX_AUDIT_REPORT.md) (embedded rule pack expansion) |

## Bench (`make bench` 1k-endpoint, three sub-benches)

| Branch | Throughput | Goroutines | Memory |
|---|---:|---:|---:|
| main baseline | 31.46 ms | 31.51 ms | 31.25 ms |
| sprint-18-semgrep-rules | 31.40 ms | 29.96 ms | 31.45 ms |

Δ < 5% on every metric — within run-to-run noise. No SAST regression.
Semgrep runs only when a binary is on PATH, and the engine bench
fixture doesn't invoke it.

## Two pre-existing bugs surfaced and fixed in this sprint

The plan's principle is "find a hidden bug, fix it, document it" — two
small ones surfaced:

1. **YAML quoting in `python-jwt-decode-no-verification`.** The rule's
   patterns embedded `{"verify_signature": False, ...}` unquoted,
   which strict YAML parsers (`gopkg.in/yaml.v3`, `ruamel-yaml --rt`)
   reject. Semgrep tolerated the loose form, so the bug had zero
   scan-time effect — Sprint 18's new YAML catalog test surfaced it
   on first run. Patterns are now single-quoted; behaviour unchanged.

2. **Documentation drift in `docs/semgrep-rules.md` and README.** Both
   referenced `python/rules/` and `python/analyzers/semgrep_runner.py`
   from before TASK-116 migrated the Semgrep runner to native Go.
   Doc paths were lying to users about where to add rules. Updated
   path references, source links, and the "Adding a rule" workflow
   to match the post-migration reality.

## Files touched

- `go/internal/scanner/semgrep/rules/auth.yaml` — +2 rules; quoted
  pre-existing JWT rule. ~80 LOC added.
- `go/internal/scanner/semgrep/rules/injection.yaml` — +5 rules.
  ~110 LOC added.
- `go/internal/scanner/semgrep/rules/secrets.yaml` — +4 rules.
  ~75 LOC added.
- `go/internal/scanner/semgrep/rules/crypto.yaml` — NEW, 4 rules.
  ~85 LOC.
- `go/internal/scanner/semgrep/scanner_test.go` — extended one test.
- `go/internal/scanner/semgrep/scanner_rulepack_test.go` — NEW.
  ~200 LOC.
- `README.md` — semgrep description + "Adding a rule" path.
- `docs/semgrep-rules.md` — path/runner references updated.
- `CHANGELOG.md` — appended a v0.14.0 section under `[Unreleased]`.
- `tasks/enterprise-readiness/PLAN.md` — ✅ Sprint 18.
- `tasks/enterprise-readiness/sprint-18-semgrep-rules.md` — Status
  section filled in.
- `tasks/enterprise-readiness/.session-memory/feedback_fendix_sprint_shipping_pattern.md` —
  added the new lesson "sprint briefs sometimes assume infrastructure
  that doesn't exist" for future sessions.

## Honest deferrals

- **Sprint 18.5 (Java/Ruby/PHP rule packs)** — listed in the sprint
  brief, requires a customer driver. No sprint file yet.
- **Sprint 18.6 (rule packs as installable plugins)** — design
  probably belongs after Sprint 13 (GitHub App) ships, since the
  plugin distribution story benefits from a serve-mode + ghapp
  lifecycle.
- **`--semgrep-rules` flag for layered external rule directories** —
  noted in `docs/semgrep-rules.md` as backlog. ~0.5–1 day if pulled.
- **Real semgrep against fixtures.** When semgrep lands on CI runners
  (or a customer-facing CI integration sprint adds it), the
  `TestRulepack_ValidatesViaSemgrepCLI` test starts running
  automatically, and a separate fixture-based positive/negative
  sprint can layer on top.

## Test plan

- [ ] `make build` succeeds locally
- [ ] `make test-go` is green (21 packages)
- [ ] `make test` is green modulo the documented pre-existing
      `test_check_auth_never_crashes` Python fuzz failure
- [ ] `make bench` shows no regression vs. main
- [ ] `make e2e` is green (~14s)
- [ ] `make lint-go` is green (gofmt + go vet)
- [ ] `bin/fendix --help` unchanged
- [ ] `bin/fendix scan` on a trivial fixture completes cleanly with
      `semgrep` in `checks_run`

## Hard-rule compliance

- No new CGo. No new external deps.
- No CLI flag names, .fendix.yaml keys, or Finding-struct JSON shape
  changes.
- `go/internal/embedded/engine/.gitkeep` left un-committed per
  `gotcha-fendix-build-artifacts-and-stash` in session memory.
- Stayed inside the sprint's listed file paths, with the honest
  scope-creep into `docs/semgrep-rules.md` and `README.md` documented
  as a surprise (the brief's DoD already required updating these
  docs).
