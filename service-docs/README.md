# Fendix — Service documentation

This folder holds high-level service and architecture documentation for Fendix.

---

## What Fendix is and why it exists

**Fendix** is a **hybrid** security scanner:

- **Black-box (Go):** Sends real HTTP requests to a live API and infers issues from responses (e.g. missing auth, bad CORS, leaked data). No source code needed.
- **White-box (Python):** Analyzes source code and OpenAPI specs (secrets, auth in spec, Semgrep rules, etc.). No live target needed.
- **Hybrid (Phase 4, not built yet):** Go runs both; a **correlator** merges results. When black-box and white-box agree on the same issue, the finding becomes **correlated** and gets higher confidence. That’s the main differentiator.

So: one CLI, two engines, one shared “Finding” model and one report.

---

## Architecture decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Black-box | Go | Speed, concurrency, single binary, good HTTP/stdlib |
| White-box | Python | Semgrep, Bandit, detect-secrets, OpenAPI libs |
| Communication | Newline-delimited JSON over stdin/stdout | No extra services, easy to run `python engine.py` by hand, debuggable |
| CLI | Cobra | Standard in Go, good help and flags |
| Active probes | Off unless `--enable-active` | Safety: no injection tests without explicit opt-in |
| Credentials in reports | Always `[REDACTED]` | Reports can be shared safely |

**Go** = CLI, crawling, HTTP checks, orchestration, reporting. **Python** = static analysis only. They share only the **data contract** (JSON on stdin/stdout).

---

## Data contract (IPC)

### ScanRequest (Go → Python, one JSON line on stdin)

```json
{
  "mode": "whitebox",
  "spec": "./openapi.yaml",
  "code_path": "./src/",
  "language": "python",
  "checks": ["secrets", "auth", "injection", "semgrep", "deps"],
  "verbose": false
}
```

- **mode:** e.g. `"whitebox"`.
- **spec:** path to OpenAPI YAML/JSON (optional).
- **code_path:** directory to scan (optional).
- **language:** hint for analyzers (e.g. python, javascript).
- **checks:** which analyzers to run.
- **verbose:** extra log line at the end.

### Finding (Python → Go, one JSON object per line on stdout)

One finding = one line of JSON. Fields: `id`, `title`, `severity`, `source`, `category`, `endpoint`, `evidence`, `fix`, `references`, `confidence`, `line`.

- **Severity:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- **Source:** `blackbox` | `whitebox` | `correlated`
- **Confidence:** `HIGH`, `MEDIUM`, `LOW`
- **line:** `"file:line"` for white-box, `null` for black-box

### Stream terminator (Python → Go)

When Python is done:

```json
{"done": true, "total": 12}
```

---

## Go layer

### CLI (`go/cmd/fendix/main.go`)

- **Commands:** `fendix version`, `fendix scan`, `fendix report`, `fendix verify [id]`.
- **Scan flags:** `--url`, `--spec`, `--code`, `--auth`, `--auth-type`, `--auth-header`, `--auth-user2`, `--profile`, `--output`, `--format`, `--fail-on`, `--baseline`, `--save-baseline`, `--enable-active`, `--workers`, `--timeout`, `--delay`, `--ignore`, `--verbose`.
- Flow: parse flags → build `ScanConfig` → run `Orchestrator` → exit 0/1/2.

### Models (`go/internal/models/`)

- **finding.go:** `Finding` struct; `Severity`, `Confidence`, `Source`; `SeverityRank()`.
- **config.go:** `ScanConfig` (URL, paths, auth, workers, format, etc.); `AuthContext` (Type, Value, Header).
- **auth.go:** `ResolveAuth` (CLI → env → profile); `NormalizeAuth`, `DetectAuthType`, `Redacted()`, `ApplyToRequest`.
- **profiles.go:** `~/.fendix/profiles/<name>.yaml`; `LoadProfile`, `ProfileLoader`.
- **scoring.go:** `ImpactBase`, `ConfidenceMult`, `SourceMult`, `CalculateSeverity()`.

### Scanner (`go/internal/scanner/`)

- **Contract:** `Endpoint` (Method, Path, FullURL, Params); `CheckFn(ctx, cfg, endpoint) → []Finding`.
- **Crawler:** (1) OpenAPI spec paths, (2) JS files + path regex, (3) common path brute-force → deduplicated `[]Endpoint`.
- **Checks:** Headers, CORS, Exposure, RateLimit, Auth (unauthenticated + JWT bypasses), IDOR (two-account).

### Engine (`go/internal/engine/`)

- **Orchestrator:** Crawl → build check list → WorkerPool.Run → sort → assign SEC-001… → SanitizeFindings → render report → fail-on exit code.
- **WorkerPool:** Bounded goroutines; one job = (endpoint, check); delay between jobs.

### Reporters (`go/internal/reporters/`)

- **JSON:** `ScanMetadata` + `SeverityCounts` + findings array.
- **HTML:** Self-contained single file; summary, sortable table, color by severity.
- **Sanitize:** Replace auth values in Evidence/Fix/Title with `[REDACTED]`.

---

## Python layer

- **Standalone:** `echo '<ScanRequest JSON>' | python engine.py` — reads stdin, writes findings + `{"done":true,"total":N}` to stdout.
- **engine.py:** Parse one ScanRequest; run requested analyzers (secrets, semgrep, auth/spec); each analyzer calls `emit_finding(f)`; print terminator.
- **Analyzers:** `spec_parser` (OpenAPI auth checks), `secrets` (regex patterns), `semgrep_runner`, `ast_analyzer`, `deps`. Rules under `python/rules/`.

---

## Phases (summary)

| Phase | Name | Status |
|-------|------|--------|
| 0 | Foundation | ✅ Complete |
| 1 | Passive Scanner | ✅ Complete |
| 2 | Auth Scanner | ✅ Complete |
| 3 | Python Engine | In progress |
| 4 | Orchestration & Correlation | Not started |
| 5–9 | Active Scanner, Reporting, Distribution, Docs, Hardening | Planned |

---

## Constraints and safety

- Active probes only with `--enable-active`.
- Every HTTP request respects `--delay`.
- Credentials never in report output; always `[REDACTED]`.
- Python engine runnable without Go.
- Same input → same output (deterministic IDs).
- HTML report is a single self-contained file.
- `go build ./...`, `go test ./...`, `python -m pytest` must pass.

---

## End-to-end flow (current)

1. User runs `fendix scan --url ... --auth "Bearer token" --format html -o report.html`.
2. CLI builds `ScanConfig`, resolves auth.
3. Orchestrator: Crawler discovers endpoints.
4. Worker pool runs all checks on each endpoint.
5. Findings sorted, IDs assigned, sanitized, then rendered.
6. Exit 0 or 1 based on `--fail-on`.

**Phase 4 (future):** Orchestrator will spawn Python, send ScanRequest on stdin, read Finding lines until terminator, merge with black-box findings, run correlator, then assign IDs and render.
