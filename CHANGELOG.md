# Changelog

All notable changes to Fendix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-04-29

Build-infrastructure-only release. **No behavior changes vs v0.4.0** — all
detection logic, CLI flags, and report output are identical. v0.4.0 users
should upgrade to v0.4.1 only if they want to install via Homebrew or curl;
the v0.4.0 binary itself remains correct.

### Fixed

- **Distribution: anonymous install paths now actually work.** v0.4.0's
  release artifacts lived on a private repo, so every install path the
  README claimed (`brew tap`, curl-pipe, `github.com/.../releases/...`)
  returned 404 for any non-authenticated user. v0.4.1 routes all
  user-facing distribution through a public mirror at
  [`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix):
  `brew tap Abdel-RahmanSaied/fendix && brew install fendix` and
  `curl -fsSL https://raw.githubusercontent.com/Abdel-RahmanSaied/homebrew-fendix/main/install.sh | sh`
  both work end-to-end without auth.
- **CI on `main` is green for the first time since 2026-03-20.** Three
  long-standing pre-existing failures fixed: Python Test job was only
  installing `pytest` (now installs `requirements.txt` + `hypothesis`);
  TASK-085's `.env` test fixture was gitignored and never committed (now
  tracked via a fixtures-scoped negation rule); TASK-086's longer field
  name had left 4 files with stale gofmt alignment.

### Added

- **Docker image publishing** — `release.yml` now builds and pushes
  `ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z` and `:latest` on every `v*`
  tag (linux/amd64). Image visibility must be flipped to public via
  GHCR package settings on first push.
- **Public install mirror automation** — `release.yml` now has a `mirror`
  job that auto-creates a matching release on the public mirror with
  binaries+sha256s, and auto-regenerates `Formula/fendix.rb` in the
  mirror's main branch with fresh SHA256 sums on every `v*` tag.
  Idempotent (re-runs upload with `--clobber`).

### Changed

- **SARIF `tool.driver.informationUri`** now points at the public install
  mirror (`https://github.com/Abdel-RahmanSaied/homebrew-fendix`) so
  consumers reading SARIF reports don't 404 on a private repo URL.

## [0.4.0] - 2026-04-29

This release ships **Phase 11 — P1 Coverage Parity**: secrets, static analysis,
active scanning, deduplication, crawler discovery, real CVE lookups, and
correlator finalization. The goal was to close the gap with industry-baseline
detection (gitleaks / semgrep / ZAP) on the obvious checks. Folds the planned
v0.3.0 batch (TASK-085 + TASK-086) into v0.4.0 since v0.3.0 was never tagged.

### Added
- **Provider-specific secret patterns** — secrets analyzer now covers GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), Stripe live secret keys (`sk_live_`), Slack tokens (`xoxa-`/`xoxb-`/`xoxp-`/`xoxr-`/`xoxs-`), Google API keys (`AIza...`), Anthropic API keys (`sk-ant-`), OpenAI API keys (legacy `sk-`/`sk-proj-`/`sk-svcacct-`), npm registry tokens (`npm_`), and GCP service-account JSON files (matched on the canonical `"type": "service_account"` signature). Total pattern count: 7 → 15. (TASK-085)
- **`.env` file scanning** — `.env`, `.env.local`, `.env.production` etc. are now properly walked and scanned with a dedicated unquoted-`KEY=value` pattern. Previously the file walker missed dotfiles whose `Path.suffix` is empty, and the generic `HARDCODED_PASSWORD` regex only matched quoted values, so `.env` files passed through silently. (TASK-085)
- **Active scanner: body-param probing on POST/PUT/PATCH** — `requestBody.content."application/json".schema.properties` (OpenAPI 3) and `parameters[in:body].schema.properties` (Swagger 2) now flow into a new `Endpoint.BodyParams` field. Body-location probes serialize a JSON body where the target field carries the payload and sibling fields get a `"fendix"` placeholder, so server-side validation doesn't reject the request before reaching the vulnerable code. (TASK-086)
- **Active scanner: header-param probing** — `in: header` parameters now flow into `Endpoint.Headers` (with standard auth headers `Authorization`/`Cookie`/`X-Api-Key` filtered out) and get probed with header-location requests. Custom headers like `X-Trace-Id` and `X-Tenant-Id` are exactly the surface where header-value injection bugs hide. (TASK-086)
- **Error-based SQL injection detection** — sends a single `'"`-class payload and matches the response body against compiled regex patterns for MySQL, Postgres, MSSQL, Oracle, and SQLite error signatures. Confirmed matches surface as HIGH-severity HIGH-confidence findings. (TASK-086)
- **Boolean-based SQL injection detection** — sends a true/false payload pair (`' OR '1'='1` vs `' AND '1'='2`) and flags status-code flips or response-body length deltas > 5% as MEDIUM-confidence findings. (TASK-086)
- **SQLite + Oracle time-based SQLi payloads** — total time-based DB types: 3 → 5. SQLite uses `randomblob(99999999)` gated on a CASE expression; Oracle uses `DBMS_PIPE.RECEIVE_MESSAGE`. (TASK-086)
- **`--max-probes-per-endpoint` flag** (default 20) — the per-endpoint probe budget is now configurable. Replaces the previously hardcoded `MaxProbesPerEndpoint` constant; `0` falls back to the default. (TASK-086)
- **Static analyzer: pickle deserialization (`PY_PICKLE_LOAD`)** — `pickle.load()` / `pickle.loads()` flagged as CRITICAL HIGH-confidence (CWE-502). Also catches `cPickle` and `_pickle` aliases. (TASK-087)
- **Static analyzer: unsafe yaml.load (`PY_YAML_UNSAFE_LOAD`)** — `yaml.load()` without `Loader=SafeLoader`, `yaml.unsafe_load()`, and `yaml.load_all()` flagged as HIGH HIGH-confidence (CWE-502). `yaml.safe_load()` and explicit `Loader=yaml.SafeLoader` correctly skipped. (TASK-087)
- **Static analyzer: weak crypto for passwords (`PY_WEAK_CRYPTO_PASSWORD`)** — `hashlib.md5()` / `hashlib.sha1()` / `hashlib.new('md5'/'sha1', ...)` flagged HIGH MEDIUM-confidence (CWE-916) when the input subtree contains a password-like identifier (`password`, `passwd`, `passphrase`, `secret`, or whole-token `pw` / `pwd`). Substring-match for long tokens; whole-token snake_case-aware match for short abbreviations to avoid false positives like `pw` matching `power`. (TASK-087)
- **Static analyzer: open redirect (`PY_OPEN_REDIRECT`)** — `redirect()` / `HttpResponseRedirect()` called with `request.args/GET/POST/...` data flagged HIGH MEDIUM-confidence (CWE-601). (TASK-087)
- **Static analyzer: SSRF (`PY_SSRF`)** — `requests.get/post/put/delete/head/patch/options/request()` with a non-literal first arg flagged HIGH MEDIUM-confidence (CWE-918). Variables resolved through scope tracking — a constant URL assigned to a variable doesn't trigger. (TASK-087)
- **Static analyzer: auth-header trust (`PY_AUTH_HEADER_TRUST`)** — `if request.headers.get('X-Admin') == 'true':` and `if req.headers['X-Role']:` patterns flagged HIGH MEDIUM-confidence (CWE-290) under `auth_bypass` category. Recognizes both the global `request` and Flask-style `req` handler-arg name. (TASK-087)
- **Static analyzer: multi-step SQL injection** — `cursor.execute(name)` where `name` was assigned a BinOp/JoinedStr/Call earlier in the same function is now flagged via intra-function scope tracking. Closes the "Bobby Tables" string-concat gap from the 2026-04-28 evaluation. (TASK-087)
- **Findings deduplication via `AffectedEndpoints []string`** — N findings sharing the same (Title, Category, Severity) collapse into one finding whose `affected_endpoints` array lists every endpoint where the issue was detected. The grouped finding promotes to the highest confidence in the group, the strongest source signal (`correlated > blackbox > whitebox`), and the union of all references. Singleton findings keep `affected_endpoints` omitted so the JSON shape stays clean. Real-world re-test on `petstore3.swagger.io`: 160 findings → 10 (16× reduction; 9 deduped findings collapsed 159 occurrences across 21 endpoints). HTML reporter shows a "+N more" badge in the finding header and an "Affected endpoints (N)" list in the body; SARIF reporter emits one `Location` per affected endpoint per result (matches SARIF 2.1.0 §3.27.12 "this issue applies to all of them" semantics). (TASK-088)
- **Crawler: robots.txt discovery** — fetches `/robots.txt`, parses `Disallow:` and `Allow:` directives as endpoint hints, and follows `Sitemap:` directives to enqueue child sitemaps. Disallow paths are some of the highest-value targets — they're often the URLs operators don't want indexed, like admin or staging interfaces. (TASK-089)
- **Crawler: sitemap.xml discovery** — fetches `/sitemap.xml` (and any `Sitemap:` URLs from robots.txt), parses `<url><loc>` entries from `<urlset>` documents and `<sitemap><loc>` entries from `<sitemapindex>` documents (one level of recursion). Cross-host links filtered out. (TASK-089)
- **Crawler: HTML link parsing with recursive depth** — extracts `<a href>` and `<form action>` targets from HTML responses and follows them via BFS up to `--crawl-depth` levels deep. Same-host only (cross-host links dropped); a visited set prevents loops. New `--crawl-depth` flag (default `1` = home-page links only; `0` disables; `2+` follows links from those pages too). Non-HTTP schemes (`mailto:`, `tel:`, `javascript:`, `data:`, `ftp:`, `file:`, `sms:`) are filtered out so the scanner doesn't try to GET phantom endpoints. (TASK-089)
- **Crawler: `--wordlist` flag** — pass a path to override the built-in `CommonPaths` brute-force list. Plain text format, one path per line, `#` comments and blank lines ignored, leading `/` auto-added. (TASK-089)
- **Crawler: `--max-endpoints` budget** (default `500`) — caps total endpoint count after dedupe so a chatty sitemap or a deep HTML crawl can't produce a runaway scan. `0` removes the cap. (TASK-089)
- **Larger built-in `CommonPaths`** — wordlist expanded from ~50 to ~117 entries with admin/dashboard surfaces (`/admin/login`, `/console`, `/dashboard`), source-control leakage (`/.git/config`, `/.svn/entries`, `/.env`), DevOps tooling (`/grafana`, `/prometheus`, `/jenkins`, `/phpmyadmin`), debug endpoints (`/debug/vars`, `/debug/pprof`), and modern API conventions (`/api/v1/auth/login`, `/api/me`). (TASK-089)
- **Real CVE coverage via primary tools (pip-audit / npm audit / govulncheck)** — the deps analyzer now invokes pip-audit for `requirements.txt`, npm audit for `package.json` (when a lockfile is present), and govulncheck for `go.mod` as primary detection paths. The hardcoded 14-package known-vuln list is now a true offline fallback that fires only when the primary tool is missing or fails. **Real-world impact**: scan of `/tmp/fendix-test/badcode/requirements.txt` produced **6 deps findings** with the offline fallback alone, **97 deps findings (16× coverage)** with pip-audit installed. govulncheck against a Go fixture using `golang.org/x/net@v0.10.0` produces 4 HIGH findings (XSS, infinite parsing loop, non-linear and quadratic parsing) — only the actually-called vulns; vendored-but-uncalled noise is dropped. (TASK-090)
- **Go module support in deps analyzer** — `go.mod` files in `--code` are now scanned by govulncheck when installed. New `_check_go_modules` + `_run_govulncheck` methods; new module-level `_parse_govulncheck_json` parses govulncheck's pretty-printed multi-line JSON via `json.JSONDecoder.raw_decode` (the NDJSON assumption was wrong — caught during in-session live testing). Govulncheck `finding` messages with at least one `function` in their trace become "called" findings; vendored-but-uncalled vulns are skipped to avoid supply-chain noise. (TASK-090)
- **Correlator: path-suffix matching** — when one normalized path is a `/`-bounded suffix of the other, the correlator merges blackbox + whitebox findings even with base-path skew. Closes the petstore-style case where the spec describes `/pet/findByStatus` and the live server hosts it under `/api/v3/pet/findByStatus` — pre-fix, no exact path match meant no correlation; now they merge. (TASK-091)
- **Correlator: HTTP method-prefix stripping in endpoint normalization** — whitebox spec_parser emits endpoints as `"GET /pet/findByStatus"`. Pre-fix, the leading method dropped the value into the file-path branch and produced `"get /pet/findbystatus"`, blocking exact match against URL-derived blackbox endpoints. Method tokens (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/CONNECT/TRACE) are now stripped via regex before path parsing. (TASK-091)
- **Correlator: debug instrumentation** — every match attempt (and every miss) is logged at DEBUG level with the normalized endpoints, related categories, and match kind. Successful matches log at INFO with `match_kind=exact|suffix|fuzzy` so users can trace which predicate fired in real-world hybrid scans. (TASK-091)

### Fixed

- **Correlator: blackbox findings consumed at most once** — the previous index lookup didn't filter against the `bbCorrelated` set, so two different whitebox findings could both merge with the same blackbox, producing duplicate correlated findings. The new `findCorrelationMatch` honours a `taken` set across all three match passes. (TASK-091)
- Pattern boundaries on provider-specific tokens (`(?<![A-Za-z0-9])` anchors) prevent the OpenAI `sk-` regex from matching Anthropic's `sk-ant-` keys or matching inside concatenated base64 strings. (TASK-085)
- HTML crawler dropping `mailto:`, `tel:`, `javascript:`, `data:` scheme links surfaced as a real-world bug on `httpbin.org` where the home-page contact link was being followed and produced "unsupported protocol scheme" warnings on every check. (TASK-089)
- **pip-audit JSON key mismatch** — the integration was reading `data.get("vulnerabilities")`, but modern pip-audit (≥2.x) emits findings under `data["dependencies"]`. The result: pip-audit "ran" silently and emitted zero findings, with no fallback to the local list. Fixed by accepting both keys, treating any non-success exit code as a tool error that triggers fallback, and parsing the `aliases` field in references. (TASK-090)
- **e2e suite flakiness on macOS** — the brute-force phase opened 117 sequential connections per URL-based test, didn't drain the response body before close (preventing keep-alive reuse), and accumulated TIME_WAIT sockets that exhausted ephemeral ports under parallel-test load. Fixed by (a) draining response bodies in `fromBruteForce` before close, (b) raising `MaxIdleConnsPerHost` to 32 on the crawler's HTTP transport for connection reuse, and (c) routing every URL-based e2e test through a 1-path `tinyWordlist` so they don't pay 117 probes for tests that don't exercise brute-force. Suite now passes 7/7 sequential runs. (TASK-090)

## [0.2.0] - 2026-04-29

This release closes six P0 user-facing bugs surfaced by the 2026-04-28 real-world test pass.
After this release, every documented CLI flag does what its `--help` text claims.

### Fixed
- **`--save-baseline` was dead code at the CLI** — flag was declared but never read into `ScanConfig`, so no file was written. Now wired through `main.go` to the orchestrator's existing baseline path. (TASK-079)
- **`--code`-only scans refused to run** — orchestrator early-exited on "no endpoints discovered" before reaching the white-box branch. The guard now fires only when both endpoints AND `--code` are absent. (TASK-080)
- **Active scanner ignored spec-defined query parameters** — every probe targeted a hardcoded `id` param, missing real vulnerabilities on `host`/`url`/`username`/etc. The crawler now extracts `in: query` and `in: path` parameters from OpenAPI 2.0 and 3.x specs (path-level + operation-level layered correctly). (TASK-081)
- **`--spec` did not accept HTTP/HTTPS URLs** — `--spec http://host/openapi.json` silently fell back to brute-force. Specs are now fetched over HTTP with format auto-detection (URL suffix → `Content-Type` → first-byte sniff), 50 MB size cap, and 4xx/5xx surfaced as errors. (TASK-082)
- **`make test` failed from a clean checkout** — `cd python/ && pytest` broke `test_self_audit.py` (paths are repo-root relative). Makefile now runs pytest from repo root; the test was also hardened with cwd-agnostic `Path(__file__).resolve().parents[2]`. (TASK-084)

### Changed
- **SARIF: 1 rule per check type, not 1 rule per finding** — previously, 160 findings produced 160 unique rule IDs (`SEC-001..SEC-160`), so GitHub Code Scanning scattered the same vuln across N "rules". Rule IDs are now stable `fendix.<category>.<title-slug>`. Per-finding `SEC-NNN` IDs remain in JSON output as instance IDs but no longer appear in SARIF. **This is a breaking change for any consumer that pinned to v0.1 SARIF rule IDs in baselines or suppressions.** (TASK-083)

### Added
- **End-to-end test infrastructure** — `go/internal/e2e/` gated behind `//go:build e2e` and run via `make e2e`. Each fixed Phase 10 flag now has an e2e regression test that runs the built binary and asserts the externally-observable effect (`TestSaveBaseline_WritesFile`, `TestCodeOnlyScan_ProducesFindings`, `TestActiveProbe_UsesSpecParam`, `TestSpecURL_FetchedAndParsed`). This closes the bug class where unit tests pass but the CLI flag is unreachable.

## [0.1.0] - 2026-04-11

### Added
- **Hybrid scanning engine** — Go black-box scanner + Python white-box analyzer communicating via newline-delimited JSON IPC
- **Black-box checks:** security headers, CORS misconfiguration, authentication bypass (JWT malformed/expired/alg:none), sensitive data exposure, rate limiting detection, IDOR two-account check
- **Active injection probes** (opt-in via `--enable-active`): time-based SQL injection (MySQL, PostgreSQL, MSSQL), command injection (echo canary), CRLF header injection
- **White-box checks:** secrets detection (7 pattern types), Semgrep rules (auth, injection, secrets), OpenAPI spec parser (2.0 + 3.x), AST analyzer (Python + JavaScript), dependency CVE checker (PyPI + npm)
- **Correlator** — cross-references black-box and white-box findings; correlated findings get elevated confidence
- **Three output formats:** JSON (default), self-contained HTML, SARIF 2.1.0
- **CI/CD integration:** `--fail-on` exit codes, `--baseline` / `--save-baseline` diff mode, SARIF upload for GitHub Code Scanning
- **`.fendix-ignore`** suppression file — suppress by ID, endpoint, category with optional expiry dates
- **Auth profiles** — `~/.fendix/profiles/<name>.yaml` for reusable auth configurations
- **Credential masking** — auth values always displayed as `[REDACTED]` in all output
- **Distribution:** embedded Python engine via `go:embed`, multi-stage Dockerfile, curl-pipe installer, Homebrew formula
- **`fendix report`** command — re-render saved JSON findings to HTML/SARIF without re-scanning
- **Active probe safety:** legal disclaimer, per-endpoint rate limit (20 probes max), full audit log
- **Severity scoring model** — multiplicative formula: ImpactBase x ConfidenceMult x SourceMult
- **Worker pool** — concurrent HTTP scanning with configurable `--workers`, `--timeout`, `--delay`
