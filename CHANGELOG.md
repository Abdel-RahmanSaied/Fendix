# Changelog

All notable changes to Fendix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
