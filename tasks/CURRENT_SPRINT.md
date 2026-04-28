# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 10 — P0 Flag Wiring (v0.2) ✅ Code Complete

**Sprint goal:** Fix the user-facing flags and code paths that are documented but broken. After this sprint, every CLI flag does what its `--help` text claims.

**Why now:** Real-world test pass on 2026-04-28 (commit `5a8e299`) revealed multiple silently-broken flags despite passing unit tests. Each is small in scope, but each is the first thing an external evaluator would try. See `tasks/MEMORY.md` "Last Session Summary" for the bug evidence behind each task.

**Definition of Done:**

- [x] All Phase 10 tasks below complete
- [x] `go/internal/e2e/` directory exists with one e2e test per fixed CLI flag (runs the built binary, asserts observable effect) — gated behind `e2e` build tag, run via `make e2e`
- [x] `make test` passes from a clean checkout, repo-root cwd (140 Python + Go race-clean)
- [x] All Phase 0-9 tests still pass
- [x] CHANGELOG `[0.2.0] - 2026-04-29` section lists each fix with the bug it closes
- [x] `make e2e` wired into `.github/workflows/ci.yml` as a third job (needs both `go` + `python`); verified locally
- [ ] Tag `v0.2.0` (awaiting user confirmation before push) and re-run the same real-world test pass that found these bugs — all green

---

## This Sprint's Tasks (Phase 10)

| ID | Task | Status | Owner | Notes |
| --- | --- | --- | --- | --- |
| TASK-079 | Wire `--save-baseline` flag into `ScanConfig` | ✅ | claude | Added `flags.GetString("save-baseline")` and `SaveBaselinePath` to the config literal in `main.go`. Verified end-to-end: `bin/fendix scan --url https://httpbin.org --save-baseline /tmp/x.json` writes a 7-finding file with `INFO baseline saved` log. E2e regression: `TestSaveBaseline_WritesFile`. |
| TASK-080 | Allow `--code`-only scans | ✅ | claude | Reordered the guard at `orchestrator.go:61` so it only fires when there are no endpoints AND no `CodePath` — code-only scans now reach the white-box branch. Black-box check pool with empty endpoints is a no-op (returns `[]`). E2e regression: `TestCodeOnlyScan_ProducesFindings` writes an AKIA fixture and asserts the report contains it. |
| TASK-081 | Populate `Endpoint.Params` from spec query/body params | ✅ | claude | Added `extractParamsList` (filters to `in: query` / `in: path`, skips `$ref` and headers) and `mergeParams` helpers; `fromSpec` now layers URL-template params + path-level + operation-level. Body params deferred to TASK-086 per plan. 3 unit tests + e2e `TestActiveProbe_UsesSpecParam` that records every probe at the target and asserts at least one hit `?host=` (proving spec params reach injection.go). |
| TASK-082 | Accept HTTP/HTTPS URL as `--spec` input | ✅ | claude | Refactored to `loadSpec`/`fetchSpec` with `http://` / `https://` prefix detection; format selected by URL suffix → Content-Type → first-byte sniff. 50 MB spec size cap. 4xx/5xx surface as errors instead of silent fallback. 3 unit tests (JSON URL, YAML URL via Content-Type, HTTP 404) + e2e `TestSpecURL_FetchedAndParsed`. |
| TASK-083 | Fix SARIF: 1 rule per check type, not per finding | ✅ | claude | Dedup now keys on stable `ruleKeyFor(f) = "fendix.<category>.<title-slug>"` instead of per-finding `f.ID`. New `slug()` helper. `Result.RuleID` and `Rule.ID` both use the stable key; per-finding `SEC-NNN` stays in the JSON report (not SARIF). Unit test `TestRenderSARIF_RulesDedupedByCheckType` verifies 4 findings of 2 check types → 2 rules + 4 results. All existing SARIF tests still pass. |
| TASK-084 | Fix `Makefile` `test-python` cwd bug | ✅ | claude | Two-pronged: dropped `cd $(PY_DIR) &&` in Makefile so pytest runs from repo root; ALSO hardened `test_self_audit.py` with `REPO_ROOT = Path(__file__).resolve().parents[2]` and `cwd=str(REPO_ROOT)` in subprocess calls — defensive, prevents recurrence if anyone runs pytest from another cwd. Verified 140/140 from repo root, `python/`, and via `make test`. |

**Status:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Real-world test evidence (informs every task above)

The 2026-04-28 test pass:

1. Built `bin/fendix` (commit `5a8e299`).
2. Ran `make test` — 2 false failures from cwd bug → TASK-084.
3. Scanned `httpbin.org` — only `/robots.txt` discovered (50-path API-biased wordlist). Headers/CORS findings are real.
4. Scanned `petstore3.swagger.io` with the full OpenAPI 3 spec — 160 findings, 21 endpoints, both engines fired, but **no correlated findings** (Phase 11 issue, tracked there).
5. Scanned local vuln-server fixture (`/tmp/fendix-test/vuln_server.py`, deliberately vulnerable to SQLi/cmdi/CRLF on `host`/`url`/`username` params):
   - Active scanner sent every probe to `param="id"` only → **no injection findings on a vulnerable target**. Root cause traced to `extractPathParams` ignoring spec query params → TASK-081.
   - Data-exposure check correctly flagged exposed password + API key as CRITICAL with masked evidence — best result of the run.
6. Tested `--save-baseline /path/to/file` — no file produced, no error logged → TASK-079.
7. Tested `--code ./repo` alone — early-exit on no endpoints → TASK-080.
8. Tested `--spec http://localhost/openapi.json` — silent fallback to brute-force → TASK-082.
9. SARIF output: 160 rules for 160 findings → TASK-083.

Worked correctly: spec parser (handled GitHub's 12 MB spec → 1145 endpoints), HTML report, ignore rules (suppressed 36, kept 7), CRITICAL data-exposure detection, JWT/AWS/RSA/DB-conn-string secret patterns, EOL deps detection, exit codes for `--fail-on`.

---

## Next sprint preview (Phase 11 — Coverage parity)

After Phase 10 ships v0.2, the next sprint targets the gaps where fendix is obviously behind industry baselines:

- TASK-085: Expand secrets to GitHub/Stripe/Slack/Google/Anthropic/OpenAI patterns; fix `.env` unquoted-value scanning (currently scanned as a file but no values match the quoted-value regex)
- TASK-086: Active scanner — body params + headers, error/boolean SQLi, SQLite/Oracle DBs, per-endpoint probe budget
- TASK-087: Static analyzer — string-concat SQLi, pickle, weak crypto, open redirect, SSRF, auth-header-trust patterns (AST-based)
- TASK-088: Findings deduplication — same check across N endpoints aggregates into one finding
- TASK-089: Crawler — robots.txt + sitemap.xml + HTML link parsing, larger wordlist, `--wordlist` flag
- TASK-090: Real CVE coverage via pip-audit + npm audit + govulncheck (current 10-package fallback list is too thin)
- TASK-091: Correlator — debug instrumentation, loosen matching predicate, e2e assertion that `correlated` findings appear

See `tasks/PHASES.md` Phase 11-13 for the full forward plan.

---

## Previous Sprint (Phase 9 — Hardening) ✅ Complete

| ID | Task | Status | Notes |
| --- | --- | --- | --- |
| TASK-072 | Performance benchmark suite | ✅ | readFindings, Correlate, normalizeEndpoint, CalculateSeverity, RenderJSON/HTML/SARIF benchmarks with -benchmem |
| TASK-073 | Fuzz test Finding JSON parser | ✅ | Go native fuzzing; FuzzReadFindings (362k+ execs), FuzzNormalizeEndpoint (204k+ execs); 0 panics |
| TASK-074 | Fuzz test OpenAPI spec parser | ✅ | Python hypothesis; 8 fuzz tests; found+fixed 3 real bugs (_parse_file None, paths type, components type) |
| TASK-075 | Self-audit: run Fendix against Fendix codebase | ✅ | 17 findings all from test fixtures; 0 production vulnerabilities; automated self-audit test |
| TASK-076 | Resilience testing | ✅ | 12 scanner + 17 engine tests: garbage, timeout, cancel, conn refused, invalid URL, slow drip, malformed streams |
| TASK-077 | Memory profiling on large scan simulation | ✅ | 2000 findings: 2.3KB/finding; 1000 correlation: 15MB; all under budget |
| TASK-078 | Audit all error messages for actionability | ✅ | 7 messages improved with "what to do" guidance |

### v0.1.0 Release Prep ✅

| Item | Status | Notes |
| --- | --- | --- |
| LICENSE file (MIT) | ✅ | Was missing — created |
| .fendix-ignore.example | ✅ | Was missing (referenced in README) — created with all rule types |
| CHANGELOG.md versioned | ✅ | [Unreleased] → [0.1.0] - 2026-04-11 |
| Version updated to 0.1.0 | ✅ | MEMORY.md updated |
| Build green | ✅ | Go build + tests, Python 140 tests |
