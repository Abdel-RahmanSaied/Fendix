# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 12 — P2 Quality, performance, ops (v0.5) — 🔄 In progress (1/7 done)

**Sprint goal:** Polish that turns a working scanner into one that fits production workflows: documented JSON schema, tighter unconfirmed-suffix semantics, severity↔confidence consistency, scan budgets, auth profiles, CI integration recipe.

**Definition of Done:**

- [x] Output JSON schema documented and validated in tests (TASK-092)
- [x] `[Unconfirmed by live scan]` evidence suffix only appears when correlation was actually attempted on a URL endpoint (TASK-092)
- [x] HIGH/MEDIUM/LOW severity↔confidence consistency rules enforced (TASK-092)
- [ ] Path-parameter substitution: `/users/{id}` becomes `/users/1` (TASK-093)
- [ ] Logging aggregated: max 3 WARN per check, rest at DEBUG (TASK-094)
- [ ] Global scan budget: `--max-requests N`, `--max-duration 5m`, `--respect-robots` (TASK-095)
- [ ] Auth profiles: bearer, api-key (header + query), basic, cookie, refresh-on-401, all e2e tested (TASK-096)
- [ ] `-race` passes on a 1000-endpoint scan in CI (TASK-097)
- [ ] Example GitHub Actions workflow committed: scan → SARIF → upload → PR comment (TASK-098)

| ID | Task | Status | Notes |
| --- | --- | --- | --- |
| TASK-092 | Output schema cleanup: `docs/schema.md`, JSON-schema validation in tests, evidence-suffix logic, severity↔confidence consistency | ✅ | New `docs/schema.md` + `docs/schema.json`; `RenderJSON` always emits `findings: []` (not `null`); `isURLEndpoint` gate on `[Unconfirmed by live scan]` suffix; `MaxSeverityForConfidence` + `EnforceSeverityConsistency` in models, wired as orchestrator step 5.6. 3 schema-validation tests + 8 model tests + 2 orchestrator helper tests. Pre-existing `TestCorrelate_UnconfirmedWhitebox` replaced with two more-specific tests. Real-world `--code` scan on badcode/: 22 findings, 0 misleading suffixes, 0 sev/conf violations. |
| TASK-093 | Crawler placeholder substitution: schema-derived sample values for path params | 🔲 | Currently `/users/{id}` → `/users/%7Bid%7D`. Should pull `schema.example` / `schema.type` from OpenAPI to substitute `/users/1` / `/users/abc`. |
| TASK-094 | Logging hygiene: aggregate per-check failures, cap WARN volume, downgrade rest to DEBUG | 🔲 | |
| TASK-095 | Scan budget controls: `--max-requests`, `--max-duration`, `--respect-robots`, soft-stop semantics | 🔲 | Higher user-visibility than TASK-094 — could pull forward. |
| TASK-096 | Auth profiles e2e: bearer + api-key (header/query) + basic + cookie + refresh-on-401, all under tests/e2e/ | 🔲 | |
| TASK-097 | Concurrency review: `-race` against 1000-endpoint scan in CI, fuzz worker-pool cancellation | 🔲 | |
| TASK-098 | CI integration recipe: `examples/github-actions/fendix-scan.yml` with SARIF upload + baseline-diff PR comment | 🔲 | |

**Status legend:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

---

## Phase 11 — Shipped ✅ (v0.4.0 — 2026-04-29)

All 7 tasks (TASK-085..091) shipped. Folded the never-tagged v0.3 batch (TASK-085 + TASK-086) into v0.4. Detail table preserved below under "This Sprint's Tasks (Phase 11 — v0.3 batch)".

---

## Phase 10 — Shipped ✅ (v0.2.0 — 2026-04-29)

| ID | Task | Status | Notes |
| --- | --- | --- | --- |
| TASK-079 | Wire `--save-baseline` flag into `ScanConfig` | ✅ | Verified via real httpbin.org scan: 3119-byte baseline.json with 7 findings. E2e: `TestSaveBaseline_WritesFile`. |
| TASK-080 | Allow `--code`-only scans | ✅ | Verified on `/tmp/fendix-test/badcode/`: exit 0, 16 findings (6 critical + 10 high). E2e: `TestCodeOnlyScan_ProducesFindings`. |
| TASK-081 | Populate `Endpoint.Params` from spec query/path params | ✅ | Verified on vuln_server: `host` + `url` probed (CMDi + CRLF found). E2e: `TestActiveProbe_UsesSpecParam`. Body params deferred to TASK-086. |
| TASK-082 | Accept HTTP/HTTPS URL as `--spec` input | ✅ | Verified: log "endpoints from spec count=5 spec=http://...". E2e: `TestSpecURL_FetchedAndParsed`. |
| TASK-083 | Fix SARIF: 1 rule per check type, not per finding | ✅ | Verified: 11 rules / 41 results, IDs of form `fendix.<category>.<title-slug>`. **Breaking change** for v0.1 SARIF consumers; called out in CHANGELOG. |
| TASK-084 | Fix `Makefile` `test-python` cwd bug | ✅ | 140/140 from repo root, `python/`, and via `make test`. |
| Release | v0.2.0 commit + tag + push | ✅ | Commit `2ca82ce` on `origin/main`; annotated tag `v0.2.0` (object `acd2f32`) on `origin`; `release.yml` triggered. |

---

---

## This Sprint's Tasks (Phase 11 — v0.3 batch)

Sprint plan: ship TASK-085 + TASK-086 as **v0.3.0**, then TASK-087..091 as **v0.4.0**. Splitting reduces release risk and gets the secrets-coverage win in front of evaluators sooner.

| ID | Task | Target | Status | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| TASK-085 | Expand secret patterns + fix `.env` unquoted-value scanning | v0.3 | ✅ | claude | Added 8 provider patterns (`GITHUB_TOKEN`, `STRIPE_LIVE_KEY`, `SLACK_TOKEN`, `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `NPM_TOKEN`, `GCP_SERVICE_ACCOUNT`) to `_PATTERNS`. New `_ENV_PATTERNS` list with `ENV_SECRET` regex for unquoted `KEY=value`, gated to `.env*` via `_is_env_file()`. Fixed dotfile-walker bug: `.env` had `Path.suffix=''` so was skipped entirely; `_walk` now also yields env-files by name. 9 new test methods + anti-overlap test (OpenAI vs Anthropic). Real-world badcode re-scan: 16 → 19 findings (+3 critical: GitHub + 2× Stripe; +1 high: 3× ENV minus 2 already-found-by-other-pattern overlaps; net +6 secrets-only finding deltas).|
| TASK-086 | Active scanner: body params, headers, error/boolean SQLi, SQLite/Oracle, `--max-probes-per-endpoint` flag | v0.3 | ✅ | claude | Endpoint extended with `Headers []string` and `BodyParams []string`. Crawler extracts both from OAS 2 + 3 specs (auth headers `Authorization`/`Cookie`/`X-Api-Key` filtered out; `$ref` schemas skipped). Injection probes refactored around new `ProbeLocation` enum (query/header/body); body probes serialize JSON with `"fendix"` placeholders for sibling fields. SQLi expanded: 3 → 5 time-based DBs (+ SQLite `randomblob`, + Oracle `DBMS_PIPE.RECEIVE_MESSAGE`); new error-based SQLi (regex match on MySQL/Postgres/MSSQL/Oracle/SQLite error signatures, HIGH confidence); new boolean-based SQLi (length-delta > 5% or status flip, MEDIUM confidence). New `cfg.MaxProbesPerEndpoint` field + `--max-probes-per-endpoint` CLI flag (default 20). 14 new unit tests + 2 e2e regressions (`TestActiveProbe_BodyParam_FindsErrorBasedSQLi`, `TestActiveProbe_HeaderParam_ProbesCustomHeader`). Real-world re-test on `/tmp/fendix-test/vuln_server.py`: scan now emits SQLite-error-based finding on `/api/v1/users` (was missed pre-fix) plus boolean-based on `/api/v1/ping`. |
| TASK-087 | Static analyzer: string-concat SQLi, pickle/yaml.load, weak crypto for passwords, open redirect, SSRF, auth-header-trust | v0.4 | ✅ | claude | 6 new AST patterns added to `python/analyzers/ast_analyzer.py`: `PY_PICKLE_LOAD`, `PY_YAML_UNSAFE_LOAD`, `PY_WEAK_CRYPTO_PASSWORD` (category=secrets), `PY_OPEN_REDIRECT`, `PY_SSRF`, `PY_AUTH_HEADER_TRUST` (category=auth_bypass). Plus intra-function scope tracking via new `visit_FunctionDef`/`visit_Assign` hooks closes the multi-step SQLi gap (`sql = "..." + var; cursor.execute(sql)` now resolved). Helpers: `_looks_like_password_id` uses substring match for long tokens (`password`/`passwd`/`passphrase`/`secret`) + whole-snake-case-token match for short abbreviations (`pw`/`pwd`) to avoid false positives like `pw` matching `power`. `_REQUEST_NAMES` recognizes both global `request` and Flask handler-arg `req`. New `category` parameter on `_emit_finding` (default `injection`). 16 new test methods (42 total in test_ast_analyzer.py, was 26). Real-world re-test on `/tmp/fendix-test/badcode/`: 22 → 26 findings (+4 new: multi-step SQLi at handlers.py:16, pickle.loads at :50, MD5(pw) at :38, X-Admin trust at :61). 174/174 Python tests pass. |
| TASK-088 | Findings deduplication via `AffectedEndpoints []Endpoint` | v0.4 | ✅ | claude | New `AffectedEndpoints []string` field on `models.Finding` (json:`affected_endpoints,omitempty`). New `engine.Deduplicate()` keys on `(Title, Category, Severity)`, picks highest confidence in group, promotes source via `correlated > blackbox > whitebox`, unions references. Wired into orchestrator at step 5.5 (after Correlate, before Sort/ID). HTML reporter: header shows `+N more` badge, body shows "Affected endpoints (N)" list. SARIF reporter: emits one `Location` per affected endpoint per result. 8 unit tests for `Deduplicate` + 2 reporter tests + 1 e2e regression (`TestDedup_GroupsSameFindingAcrossEndpoints`). Real-world re-test on `petstore3.swagger.io`: **160 → 10 findings (16× reduction)**; 9 deduped findings collapsed 159 occurrences across 21 endpoints (CORS, CSP, HSTS, X-Content-Type-Options, X-Frame-Options each = 1 finding × 21 endpoints). Whitebox badcode: 26 → 22 (3 `.env` lines + 2 Stripe overlaps + 2 SQLi-on-different-lines collapsed). |
| TASK-089 | Crawler upgrade: robots.txt + sitemap.xml + HTML link parsing, `--wordlist` flag, larger default list | v0.4 | ✅ | claude | New discovery strategies: `fromRobots` (parses `Disallow:`/`Allow:`/`Sitemap:` directives — Disallow paths queued as endpoint hints, not respected as restrictions), `fromSitemap` (parses `<urlset>` and `<sitemapindex>` documents, follows child sitemaps one level deep, cross-host filtered), `crawlHTMLLinks` (BFS over `<a href>` + `<form action>` with `--crawl-depth` cap, same-host only, visited-set deduplication, non-HTTP schemes `mailto:`/`tel:`/`javascript:`/`data:`/`ftp:`/`file:`/`sms:` filtered out at extraction). New CLI flags: `--wordlist /path/to/file` (overrides `CommonPaths`; plain text, `#` comments + blank lines ignored, leading `/` auto-added), `--crawl-depth` (default 1, 0 disables HTML crawl), `--max-endpoints` (default 500, 0 = no cap, applied after dedupe). `CommonPaths` expanded ~50 → 117 with admin/dashboard surfaces, source-control leakage paths, DevOps tooling, debug endpoints. **Real-world re-test on `httpbin.org`**: pre-fix discovered 1 endpoint (`/robots.txt`); post-fix discovers **3 endpoints** — `/deny` (via robots.txt Disallow), `/forms/post` (via HTML link crawl), `/robots.txt` (via brute-force). 14 new unit tests + 1 e2e regression (`TestCrawler_RobotsDisallowDiscovered`) + 1 mailto-filter regression test (caught a real-world bug during the httpbin test pass). |
| TASK-090 | Real CVE coverage: pip-audit + npm audit + govulncheck primary; hardcoded list as offline fallback | v0.4 | ✅ | claude | Refactored `python/analyzers/deps.py`: pip-audit / npm audit / govulncheck are now genuine primary paths with the hardcoded 14-package list as offline fallback (was always-fallback for npm + broken JSON-key bug for pip-audit). New consistent semantics: tool installed AND ran cleanly → use tool's output; tool absent OR failed (timeout, non-success exit, malformed JSON) → fall back to local list. New helpers: `_run_pip_audit` returns `bool` (clean run), `_has_npm_lockfile` gates npm audit on lockfile presence, `_check_go_modules` + `_run_govulncheck` + module-level `_parse_govulncheck_json` adds Go support (handles govulncheck's pretty-printed multi-line JSON via `JSONDecoder.raw_decode` — NDJSON assumption was wrong, caught during in-session live testing). **Critical bug fixed**: pip-audit JSON key was `data["vulnerabilities"]` but modern pip-audit (≥2.x) emits `data["dependencies"]` — the integration silently produced 0 findings without triggering fallback. **Real-world re-tests**: badcode/requirements.txt = 6 deps findings (offline) → 97 (with pip-audit installed, 16× coverage); Go fixture using `golang.org/x/net@v0.10.0` produces 4 HIGH govulncheck findings on the called paths (drops vendored-but-uncalled noise). 18 new unit tests (pip-audit success/failure/legacy-key/timeout/non-zero-exit/invalid-JSON, npm audit success/no-lockfile/failure, govulncheck parser called/uncalled/fix-version/aliases/required-fields/malformed-lines/empty/multi-line, govulncheck integration on go.mod/no-tool/no-go-mod) + 1 e2e regression (`TestDepsScan_VulnerableRequirements`). **Bonus fix**: e2e suite flakiness on macOS — TASK-089's 117-path wordlist + parallel httptest servers exhausted ephemeral ports because `fromBruteForce` didn't drain response bodies before close (no keep-alive reuse). Fixed by (a) `io.Copy(io.Discard, resp.Body)` before close, (b) `MaxIdleConnsPerHost=32` on the crawler transport, (c) all URL-based e2e tests now use a 1-path `tinyWordlist` helper so brute-force doesn't dominate test cost. Suite now passes 7/7 sequential runs (was ~1/5). |
| TASK-091 | Correlator: debug instrumentation, loosen matching predicate, e2e test asserting ≥1 correlated finding | v0.4 | ✅ | claude | **Endpoint normalization**: new `methodPrefixRe` strips leading HTTP-method tokens (`GET /pet/findByStatus` → `/pet/findByStatus`); pre-fix the leading method dropped the value into the file-path branch and produced `"get /pet/findbystatus"`, blocking every exact match. **Match strategy** refactored into a single `findCorrelationMatch(wbNorm, relCats, blackbox, bbNorm, bbIndex, taken)` helper that walks 3 passes in order — (1) exact via index, (2) path-suffix on `/`-boundary (handles base-path skew like spec `/pet` vs server `/api/v3/pet`), (3) fuzzy segment overlap (existing). New `pathSuffixMatch(a, b)` ensures suffix boundaries align on `/` (rejects mid-segment matches like `/3/pet` ⊄ `/api/v3/pet`). New `categoryRelated()` filter applied in suffix and fuzzy passes so categories must still align. **Bug fix**: each blackbox finding is now consumed at most once — pre-fix the index lookup didn't honour `bbCorrelated`, so two whitebox findings could both merge with the same blackbox. The refactored helper threads a `taken` set through all 3 passes. **Performance**: `bbNorm` slice pre-computes normalized blackbox endpoints once; the inner suffix+fuzzy loops index into it instead of re-running `url.Parse` per iteration (kept the `TestMemory_LargeCorrelation` 20MB budget). **Debug instrumentation**: new `slog.Debug` line on each "no match" with normalized endpoint + category; existing `slog.Info` on success now reports `match_kind=exact\|suffix\|fuzzy`. **HTTP-method noise** added to `pathSegments` filter (`get`/`post`/`put`/etc.) for defense-in-depth alongside the regex strip. **Tests**: 4 new unit tests in `correlator_test.go` (`TestCorrelate_PathSuffixMatch_PetstoreStyle`, `TestCorrelate_PathSuffixMatch_BarePath`, `TestCorrelate_BlackboxConsumedAtMostOnce`, `TestPathSuffixMatch` table-driven 9 cases) + 4 new `TestNormalizeEndpoint` cases (method prefix GET/POST/lowercase/with-full-URL). **e2e regression**: `TestCorrelator_HybridScanProducesCorrelatedFinding` runs a hybrid scan against an httptest server returning 200 OK on `/api/v1/admin` + a minimal OpenAPI 3 spec describing the same endpoint with no security; passes `--auth Bearer test` so the blackbox unauth check fires; asserts `"source":"correlated"` appears in the JSON report. All builds green: Go race-clean across 5 packages; Python 193/193; **10/10 e2e** (was 9). |

**Status legend:** 🔲 Not Started | 🔄 In Progress | ✅ Done | ⏸ Blocked

**Recommended order:** TASK-085 first (smallest, highest visibility, unlocks v0.3 ship). Then TASK-086 (depends on TASK-081 work that just shipped). After v0.3 cuts, TASK-088 (dedup) before TASK-087 (new SAST checks) so dedup is in place when N new check types arrive.

---

## Phase 10 (v0.2.0) — real-world test evidence

The 2026-04-28 test pass that informed Phase 10:

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

## Next sprint preview (Phase 12 — Quality & Ops, v0.5)

After v0.4 ships (Phase 11 complete), Phase 12 targets the polish that turns a working scanner into one that fits production workflows: scan budgets (`--max-requests`, `--max-duration`), auth-profile e2e coverage, schema cleanup, logging hygiene, CI integration recipe. See `tasks/PHASES.md` Phase 12 for the full task list (TASK-092..098).

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
