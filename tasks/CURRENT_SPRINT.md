# Fendix — Current Sprint

> Updated every session. Shows exactly what is being worked on right now.

---

## Active Phase: 11 — P1 Coverage Parity (v0.3 + v0.4) — 🔲 Not Started

**Sprint goal:** Reach industry-baseline detection coverage. Stop being "noticeably worse than gitleaks/semgrep/ZAP" on the obvious checks.

**Why now:** v0.2.0 shipped — every documented CLI flag now works. Next blocker for external evaluation is detection breadth. Reviewers compare against gitleaks (secrets), semgrep (SAST), and ZAP (DAST). Today fendix has 7 secret patterns vs. gitleaks' 100+, no string-concat SQLi, no body-param probing, and no correlated findings on hybrid runs. Each gap is a credibility hit.

**Definition of Done:**

- [ ] Secrets analyzer covers GitHub, Stripe, Slack, Google, Anthropic, OpenAI, npm, GCP service-account JSON
- [ ] `.env` files (unquoted `KEY=value`) correctly scanned
- [ ] Static SAST: string-concat SQLi, pickle/yaml.load, weak crypto, open redirect, SSRF, auth-header-trust patterns
- [ ] Active scanner probes body params + headers; SQLi covers SQLite/Oracle + error-based + boolean-based
- [ ] Findings dedup: `AffectedEndpoints []Endpoint` for the "missing CSP × 21 endpoints" case
- [ ] Crawler: robots.txt + sitemap.xml + HTML link parsing, `--wordlist` flag, larger default list
- [ ] Real CVE coverage via pip-audit + npm audit + govulncheck (hardcoded list as offline fallback)
- [ ] Correlator emits ≥1 `correlated` finding on hybrid scan against vuln-server fixture
- [ ] All Phase 0-10 tests still pass
- [ ] e2e regression tests added for any new CLI flags

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
| TASK-085 | Expand secret patterns + fix `.env` unquoted-value scanning | v0.3 | 🔲 Next | unassigned | Add: GitHub PAT (`ghp_`), Stripe (`sk_live_`), Slack (`xox[bpa]-`), Google (`AIza`), Anthropic (`sk-ant-`), OpenAI (`sk-…48`), npm (`npm_…36`), GCP service-account JSON. Fix `HARDCODED_PASSWORD` regex to handle unquoted `KEY=value` for `.env*` files. Add fixtures + tests; re-test `/tmp/fendix-test/badcode/` (should jump from 6 critical to ~10). |
| TASK-086 | Active scanner: body params, headers, error/boolean SQLi, SQLite/Oracle, `--max-probes-per-endpoint` flag | v0.3 | 🔲 | unassigned | Builds on TASK-081 (params now flow through `Endpoint.Params`). Body-param extraction needed in `crawler.go` (was deferred from TASK-081). Error-based SQLi via response-body grep for DB error signatures. Boolean-based via response-length delta. |
| TASK-087 | Static analyzer: string-concat SQLi, pickle/yaml.load, weak crypto for passwords, open redirect, SSRF, auth-header-trust | v0.4 | 🔲 | unassigned | All AST-based in `python/analyzers/ast_analyzer.py`. Closes the "f-string only" gap. |
| TASK-088 | Findings deduplication via `AffectedEndpoints []Endpoint` | v0.4 | 🔲 | unassigned | "Missing CSP × 21 endpoints" → 1 finding with 21 endpoints. Propagate to JSON, HTML, SARIF (SARIF: multiple `locations` per result). |
| TASK-089 | Crawler upgrade: robots.txt + sitemap.xml + HTML link parsing, `--wordlist` flag, larger default list | v0.4 | 🔲 | unassigned | httpbin.org showed only `/robots.txt` discovered with current 50-path wordlist. |
| TASK-090 | Real CVE coverage: pip-audit + npm audit + govulncheck primary; hardcoded list as offline fallback | v0.4 | 🔲 | unassigned | Replace the 10-package fallback that's currently the primary code path on most machines. |
| TASK-091 | Correlator: debug instrumentation, loosen matching predicate, e2e test asserting ≥1 correlated finding | v0.4 | 🔲 | unassigned | Petstore hybrid scan produced zero correlated findings despite both engines firing on the same endpoints. |

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
