# Fendix v0.1 → v1.0 production-readiness plan

Based on real-world testing of commit `5a8e299`. Tasks are ordered by **what blocks external evaluation today**, then coverage, then polish, then release.

## Test-derived context

This plan is grounded in a real test pass that built the binary, ran the existing suite, and exercised every major code path against:

- `httpbin.org` — minimal black-box surface, root-level paths
- Petstore v3 (live + 13-path OpenAPI 3 spec) — typical OpenAPI target
- GitHub's 12 MB OpenAPI spec — large-scale parsing
- A custom Swagger 2.0 sample — legacy spec format
- A deliberately vulnerable local server (SQLi, command injection, CRLF, exposed secrets, weak auth)
- A deliberately bad Python codebase (10 secret types, multiple injection patterns, EOL deps)

Results:

| Layer | Verdict |
|---|---|
| Build / unit tests | ✅ clean (race-clean Go, 138/140 Python — 2 fail due to a Makefile cwd bug) |
| Spec parser | ✅ handles OpenAPI 3, Swagger 2, 12 MB GitHub spec |
| Static secrets / deps / SQLi | ✅ catches AWS, JWT, RSA, DB strings, f-string SQLi, EOL deps |
| HTML report, ignore rules, exit codes | ✅ work cleanly |
| Active injection scanner | ❌ probes only `param="id"` — broken for any other param |
| `--save-baseline` flag | ❌ never wired into config; CLI dead-end |
| `--code`-only scans | ❌ early-exits on "no endpoints" |
| `--spec` URL input | ❌ silently falls back to brute-force |
| SARIF output | ❌ 1 unique rule per finding (should be 1 per check type) |
| Crawler discovery | ⚠️ 50-path wordlist, API-prefix biased |
| Findings dedup | ⚠️ same "missing CSP" reported 21× across endpoints |
| Correlator | ⚠️ never produced a correlated finding in any hybrid run |

---

## P0 — Broken user-facing flags (must-fix before any external use)

These are documented features that don't work. Each is small in scope; the cost of leaving them is reputation damage when external users hit them in the first hour.

### P0.1 Wire `--save-baseline` into config
- **Bug**: flag declared at `go/cmd/fendix/main.go:150`, never read; `cfg.SaveBaselinePath` always empty.
- **Task**: read flag at `main.go:80`, assign to `cfg.SaveBaselinePath` in the struct literal at line 92.
- **Acceptance**: integration test in `cmd/fendix/main_test.go` runs `fendix scan ... --save-baseline /tmp/x.json` and asserts file exists with expected schema. Existing unit test at `baseline_test.go:156` keeps passing.
- **Effort**: 30 min.

### P0.2 Allow `--code`-only scans
- **Bug**: `go/internal/engine/orchestrator.go:61` early-exits when no endpoints discovered, before the white-box branch at line 95 can run.
- **Task**: change the early-exit to only fire when `cfg.URL != "" && cfg.SpecPath == "" && cfg.CodePath == ""`. Add a separate warning when *both* code and endpoints are empty.
- **Acceptance**: `fendix scan --code ./somecode --output x.json` runs the Python engine and produces a non-empty findings file. Add e2e test in `orchestrator_test.go`.
- **Effort**: 1 hour.

### P0.3 Populate `endpoint.Params` from spec query parameters
- **Bug**: `go/internal/scanner/crawler.go:340` `extractPathParams` only extracts `{id}`-style path params; OpenAPI `parameters: [{name, in: query}]` entries are dropped. Active scanner falls back to a hardcoded `"id"` for every endpoint, making non-`id` injection probes a no-op.
- **Task**: in `fromSpec()` (around `crawler.go:159`), parse `parameters` array per operation, collect names where `in: query` or `in: path`, populate `Endpoint.Params`. Handle both Swagger 2 (per-operation `parameters`) and OpenAPI 3 (operation + path-level merge).
- **Acceptance**: e2e test that posts a spec with `parameters: [{name: host, in: query}]` and asserts the active scanner produces a probe with `param="host"`.
- **Effort**: 3-4 hours including tests.

### P0.4 Accept URL for `--spec`
- **Bug**: passing `--spec http://host/openapi.json` silently falls back to brute-force; users do this routinely.
- **Task**: detect `http://` / `https://` prefix in `crawler.go fromSpec()`, fetch with the existing HTTP client (with `--timeout`, no auth-leak in logs).
- **Acceptance**: e2e test with httptest server returning a spec.
- **Effort**: 1 hour.

### P0.5 Fix SARIF: one rule per check, not per finding
- **Bug**: 160 findings → 160 unique rule IDs. GitHub Code Scanning groups by `ruleId`, so the same vulnerability is scattered across 21 different "rules", destroying triage.
- **Task**: stop generating per-finding rule IDs. Define a stable rule registry (e.g., `missing-csp-header`, `cors-reflects-origin`) keyed by `category + checker_id`. SARIF results reference the shared rule.
- **Acceptance**: scan yielding N findings of M distinct check types produces exactly M rules. Validate with `sarif-multitool validate` in CI.
- **Effort**: 4-6 hours including CI integration.

### P0.6 Make `make test` actually pass from a clean checkout
- **Bug**: `cd python && pytest` breaks `test_self_audit.py` which assumes repo-root cwd.
- **Task**: in `Makefile` `test-python` target, drop the `cd $(PY_DIR) &&`; run `python3 -m pytest python/tests/` from repo root. Update CI accordingly.
- **Effort**: 15 min.

---

## P1 — Coverage and core-feature gaps (block "evaluation by external users")

External evaluators will compare against ZAP/Burp/Semgrep/gitleaks. These are the gaps where fendix obviously underperforms.

### P1.1 Expand secret patterns to industry baseline
- **Add patterns**: GitHub PAT (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`), Stripe (`sk_live_`, `pk_live_`, `rk_live_`), Slack (`xox[baprs]-...`), Google API keys (`AIza...`), GCP service-account JSON, npm tokens (`npm_...`), Anthropic (`sk-ant-...`), OpenAI (`sk-...`), JFrog/Datadog/PagerDuty/SendGrid as a stretch.
- **Fix `.env` handling**: in `python/analyzers/secrets.py`, the `HARDCODED_PASSWORD` regex requires quoted values; `.env` uses unquoted `KEY=value`. Add a `.env`-mode pass that splits by `=` and applies value-pattern matching.
- **Reduce FP**: add entropy heuristic (Shannon) for generic API key matches; allowlist obvious test fixtures (`AKIAIOSFODNN7EXAMPLE`).
- **Acceptance**: a fixture corpus under `python/tests/fixtures/secrets/` covering all patterns + `.env` cases, with a baseline of true/false detections.
- **Effort**: 1-2 days.

### P1.2 Active injection scanner: parameter awareness + technique breadth
- **Already covered by P0.3 for spec-driven params.** Add:
  - **Body params**: parse JSON request bodies from spec; probe each leaf string field. Currently only query-string is probed.
  - **Header injection**: probe `User-Agent`, `Referer`, `X-Forwarded-For`, custom headers from spec.
  - **SQLi techniques**: add error-based (look for DB error fingerprints in response: `SQL syntax`, `pg_query`, `ORA-`, `SQLite error`), and boolean-based (compare `' OR 1=1--` vs `' OR 1=2--` response sizes/codes).
  - **SQLi DBs**: add SQLite (`randomblob(100000000)` for delay), Oracle (`DBMS_PIPE.RECEIVE_MESSAGE`).
- **Per-finding limits**: add `--max-probes-per-endpoint` (default 50) and stop after first confirmed finding per (endpoint, param, type) to keep scan cost bounded.
- **Acceptance**: scan a juice-shop instance and detect at least: 1 SQLi (login bypass), 1 reflected XSS (search), 1 IDOR (basket).
- **Effort**: 4-5 days.

### P1.3 Static analyzer: cover the obvious patterns
- Add detectors:
  - String-concat SQLi (`"SELECT ..." + var`, `cur.execute("SELECT " + x)`).
  - Pickle/marshal/yaml.load deserialization sinks.
  - Weak hash for passwords (`hashlib.md5/sha1` proximate to `password` token).
  - Open redirect (`redirect(request.GET[...])`, Flask `redirect(target)` from request).
  - Auth-bypass anti-patterns (trusting `X-Forwarded-User`, `X-Admin`, JWT `alg:none`).
  - SSRF candidates (`requests.get(user_input)`, `urllib.urlopen(user_input)`).
- Use AST analysis (already scaffolded in `python/analyzers/ast_analyzer.py`) for taint-aware detection rather than regex.
- **Acceptance**: extend the deliberately-bad fixture and add it as `python/tests/fixtures/badcode/`. Track precision/recall vs Semgrep's default ruleset.
- **Effort**: 1 week.

### P1.4 Findings deduplication / aggregation
- **Bug**: 21 endpoints × 3 missing headers = 63 medium findings of "Missing CSP".
- **Task**: introduce a `Finding.AffectedEndpoints []Endpoint` field. After collection, group findings with identical `(category, rule_id, evidence_signature)` into one parent finding listing all affected endpoints. JSON/HTML/SARIF reporters render the aggregate.
- **Acceptance**: petstore scan that previously produced 160 findings produces ~10 with multi-endpoint lists, no information loss.
- **Effort**: 2-3 days.

### P1.5 Crawler depth + wordlist
- **Add**: parse `robots.txt`, `sitemap.xml`, follow links from HTML, recursive crawl with bounded depth (`--crawl-depth N`, default 2), respect `--delay`.
- **Wordlist**: the current 50-path list misses root-level APIs (httpbin, FastAPI defaults). Either ship a wordlist file (e.g., 500-1000 paths from SecLists `api/api-endpoints-mazen160.txt`) or make it user-supplyable via `--wordlist`.
- **Acceptance**: scan against an unspec'd FastAPI dev server discovers the docs route and at least one route from each common framework prefix.
- **Effort**: 2 days.

### P1.6 CVE coverage: real database, not hardcoded list
- **Task**: integrate `pip-audit` (already detected and used as fallback) as the primary path for Python deps. Add `npm audit --json` for `package-lock.json`. Add Go deps via `govulncheck` for `go.mod`. Keep the hardcoded list only as offline fallback.
- **Acceptance**: scanning a project with 100 deps surfaces all CVEs that pip-audit/npm-audit/govulncheck independently report, with normalized severity.
- **Effort**: 3-4 days.

### P1.7 Correlator: actually merge findings in real runs
- **Observed**: in every hybrid run, no correlated findings appeared. Either the matching predicate is too strict or never fires when both engines run.
- **Task**: instrument `go/internal/engine/correlator.go` with debug logs that print attempted matches; lower the matching bar to `(category, normalized_endpoint_path)`; add e2e test that asserts ≥1 correlated finding when scanning the vuln server with both `--url` and `--spec`.
- **Effort**: 1-2 days.

---

## P2 — Quality, performance, ops

### P2.1 Output schema cleanup
- Most JSON findings are missing the `endpoint` object I expected. Standardize a strict schema, generate from a Go struct, document it in `docs/schema.md`, and validate output with a JSON schema in tests.
- Drop `[Unconfirmed by live scan]` evidence suffix when no live scan was run; only attach when blackbox-correlation was attempted and failed.
- Resolve severity/confidence inconsistency (HIGH severity with MEDIUM confidence on the same finding).
- **Effort**: 2 days.

### P2.2 Crawler placeholder substitution
- Spec hosts with `/users/{id}` are currently hit as `/users/%7Bid%7D`. For each path parameter, derive a sample value from the schema (`type: integer` → `1`, `type: string` → `"test"`, enum → first value, format-specific examples).
- **Effort**: 1 day.

### P2.3 Logging hygiene
- HTTP failures during black-box checks emit one WARN per endpoint per check — for a 1145-endpoint scan, that's 4500 lines of noise. Aggregate "N endpoints unreachable" once per check, log the first 3 per check at WARN, rest at DEBUG.
- **Effort**: half a day.

### P2.4 Scan budget / rate-limit safety
- Currently no global request budget. A 1145-endpoint scan with 4 checks each = ~4600 requests minimum, plus active probes ×5 = up to 27,000 requests. Easy to get rate-limited or look like an attack.
- Add `--max-requests N`, `--max-duration 5m`, soft-stop checks gracefully when hit. Add an explicit `--respect-robots` flag.
- **Effort**: 1-2 days.

### P2.5 Auth profiles end-to-end
- `--profile` flag exists; the loader and tests look incomplete. Document auth-profile YAML schema, add e2e tests covering bearer, api-key (header + query), basic, cookie, and refresh-token-on-401 flow.
- **Effort**: 2-3 days.

### P2.6 Concurrency correctness review
- The race tests pass on tiny scans. Run `-race` against a 1000-endpoint scan in CI to catch contention. Also add a fuzz test for the worker pool's cancellation path.
- **Effort**: 1 day.

### P2.7 SARIF + JSON CI integration recipe
- Ship an `examples/github-actions/fendix-scan.yml` that uses fendix → SARIF → `github/codeql-action/upload-sarif`. Show baseline-diff usage in PRs. This is the #1 demo external evaluators look for.
- **Effort**: 1 day after P0.5 + P0.1.

---

## P3 — Release engineering & external trust

### P3.1 Reproducible release pipeline
- The Homebrew formula has `PLACEHOLDER_SHA256_*`. Wire the existing release workflow (`.github/workflows/release.yml`) to:
  - Build for linux/arm64 (currently missing) in addition to linux-amd64, darwin-amd64/arm64.
  - Compute SHA256 + sign with cosign.
  - Auto-update `Formula/fendix.rb` (commit with bot, or use a Tap repo).
  - Publish a Docker image to ghcr.io, signed.
- **Effort**: 2-3 days.

### P3.2 Distribution artifacts
- Add `.deb` / `.rpm` via `nfpm`. Add a one-line install: `curl -fsSL get.fendix.dev | sh` (referenced in README, doesn't exist yet).
- **Effort**: 2 days.

### P3.3 Documentation pass
- README has a working scan example, but external users will need:
  - "Scanning your first API in 5 minutes" — concrete walkthrough on juice-shop or DVWA.
  - "CI integration" page with GitHub Actions + GitLab CI + CircleCI snippets.
  - "Writing custom Semgrep rules" — current rules are 3 modest YAML files; document the format and contribute pattern.
  - "Triage workflow" — baseline + ignore + fail-on, with a real PR example.
  - Schema reference for JSON output.
- **Effort**: 3-4 days.

### P3.4 Telemetry/diagnostics
- `--debug` flag that dumps a redacted bundle (config, OS, Python version, all probe audit logs, slog-debug output) to a tarball — makes bug reports useful.
- **Effort**: 1 day.

### P3.5 Security & responsible-disclosure scaffolding
- Add `SECURITY.md` (you're shipping a security tool — this is mandatory for credibility).
- Threat-model the active scanner: what does fendix never do (no DoS, no destructive payloads, no exfiltration). Document explicit safety guarantees.
- Sign commits and releases.
- **Effort**: 1-2 days.

### P3.6 Performance benchmark suite
- Real benchmarks: scan time vs endpoint count on a controlled fixture; memory peak; goroutine count over time. Publish numbers in README. External evaluators want these.
- **Effort**: 2 days.

---

## Suggested milestones

| Milestone | Scope | ETA (1 dev FT) |
|---|---|---|
| **v0.2 — flags work** | All P0 (CLI wiring, SARIF rules, Makefile) | 1 week |
| **v0.3 — coverage parity** | P1.1, P1.3, P1.4, P1.5 (secrets + static + dedup + crawler) | 3 weeks |
| **v0.4 — active scan ready** | P1.2, P1.6, P1.7 (real injection scanner, real CVE DB, working correlator) | 3 weeks |
| **v0.5 — ops** | P2 cluster | 2 weeks |
| **v1.0 — release** | P3 cluster, full docs, signed artifacts, juice-shop benchmark in README | 2 weeks |

**Total**: ~11 weeks of focused work to v1.0. The first milestone (v0.2) is what unblocks "evaluation by external users" — without it, the very first thing a reviewer tries (`--save-baseline` for a CI gate, or `--code` for SAST-only) breaks silently.

---

## Cross-cutting recommendations

1. **End-to-end tests over unit tests**. The `--save-baseline` bug had a passing unit test. Every CLI flag needs an e2e test that runs the binary and asserts the externally-observable effect. Add a `tests/e2e/` directory with table-driven Go tests that shell out to the built binary.

2. **Adopt a vulnerable-app test corpus in CI**. Stand up juice-shop in a CI step and assert fendix finds a fixed list of known issues. This is the single best regression guard.

3. **Rule registry as a first-class concept**. Right now rules are scattered across Go check functions and Python analyzers. A central registry (id, title, category, severity, CWE, fix-guidance) loaded at startup, referenced everywhere, makes SARIF correct, makes ignore rules cleaner, and makes the "what does fendix detect" doc auto-generatable.

4. **Don't grow the scope before fixing the wiring**. The architecture is good. Resist adding new check types until P0 is done — half-wired flags are worse than missing features.

---

## Quick-reference: P0 task checklist

- [ ] P0.1 — Read `--save-baseline` flag and assign to `cfg.SaveBaselinePath` (`go/cmd/fendix/main.go`)
- [ ] P0.2 — Reorder early-exit so `--code`-only scans run (`go/internal/engine/orchestrator.go:61`)
- [ ] P0.3 — Parse spec `parameters` array into `Endpoint.Params` (`go/internal/scanner/crawler.go`)
- [ ] P0.4 — Detect URL prefix in `--spec` and fetch over HTTP
- [ ] P0.5 — Replace per-finding SARIF rules with shared rule registry
- [ ] P0.6 — Fix `make test-python` cwd in `Makefile`
