# Security Audit — Fendix v0.20
Audited by: Security Agent
Date: 2026-06-28
Scope: only code ADDED in v0.20 (benchmark suite, metrics, tests, dashboard,
`baseline.yml`). Pre-existing engine issues are out of scope here (tracked in
`TASK_MANIFEST.md` → "Pre-existing issues found" for v0.21).

## Audited surface

| Area | Files |
|------|-------|
| Benchmark | `go/internal/benchmark/{runner,baseline}.go`, `go/internal/benchmark/targets/{target,docker,owasp,dvwa,juiceshop}.go`, `go/cmd/fendix/benchmark.go` |
| Metrics | `go/internal/metrics/{collector,reader}.go`, `go/cmd/fendix/metrics.go`, `orchestrator.go` hook |
| Tests | `go/tests/**` (+ fixtures) |
| Dashboard | `tools/dashboard/index.html` |
| CI | `.github/workflows/baseline.yml`, `ci.yml` comment |

## Findings

### CRITICAL (must fix before merge)
None.

### HIGH (must fix before v0.21)
None introduced by v0.20 code.

### MEDIUM (fix in v0.21 cleanup)
- **M-1 (forward-looking) — OWASP corpus download.** The OWASP target is
  currently a loud SKIP (no download happens). When Java support lands
  (v0.27) and the download is implemented, the corpus URL **must** be a
  hardcoded constant and the archive **must** be checksum-verified before
  use (supply-chain integrity). Captured now so it isn't forgotten. No live
  risk in v0.20.

### LOW (log for later)
- **L-1 — trust model of `exec`.** Benchmark targets exec the host `docker`
  CLI (`docker.go`) and re-exec the `fendix` binary via `os.Executable()`
  (`target.go`). All arguments are hardcoded constants or operator-set
  flags — **no attacker-controlled input** reaches either. The residual
  risk (a poisoned `docker` on PATH or a replaced fendix binary) is the
  standard "you already ran this binary" trust boundary, not a new hole.
- **L-2 — fixed host ports.** DAST targets bind 3000/8080. A port clash
  fails the run loudly (container start error), not silently — not a vuln.
- **L-3 — metrics log growth.** `FileCollector` rotates at 10 MiB to a
  single `.1` generation; bounded per file. `events.jsonl` is gitignored
  and contains no sensitive data (see Secrets audit).

## SSRF surface map (every outbound call in new code)
| Call site | Destination | Attacker-controllable? | Notes |
|-----------|-------------|------------------------|-------|
| `targets/docker.go` `waitForHTTP` | `http://localhost:<fixed port>` | No | Hardcoded loopback health check; `http.Client` has a per-try timeout |
| `targets/docker.go` `container.start` | local Docker daemon | No | Pinned image constants only |
| `tools/dashboard/index.html` | `cdn.jsdelivr.net` (Chart.js) | No | **SRI-pinned** (`sha384-…`) + `crossorigin`/`no-referrer` |
| OWASP corpus download | — | — | Not implemented (target skips); see M-1 |

No new code reaches a user-supplied URL. The scanner's existing SSRF
considerations are unchanged (no scan-logic edits in v0.20).

## Secrets audit
- No hardcoded secrets/tokens/keys in any new file.
- **Fixtures deliberately contain no secrets** — the planted finding is an
  unpinned Docker base image (IaC), specifically chosen to avoid committing
  realistic credentials that would trip secret scanning.
- `MetricEvent` has no field capable of carrying source code, paths, hosts,
  or finding content — verified by inspection and a functional run
  (`events.jsonl` lines contain only version/phase/counts/timings).

## Other checks
- [x] No `fmt.Sprintf` into SQL (no SQL in new code).
- [x] HTTP clients have timeouts (`waitForHTTP`).
- [x] Temp files via `os.CreateTemp` (random names): `baseline.go` Save,
      `target.go` scan output.
- [x] No unbounded goroutines (none spawned in v0.20 code).
- [x] No `exec.Command` with attacker-controlled input.
- [x] `.gitignore` covers generated/downloaded data: `metrics/*.jsonl`,
      `benchmarks/results/*`, `benchmarks/targets/owasp/`. Tracked on
      purpose: `baseline.json`, `*-known.json`.
- [x] Dashboard renders untrusted (dropped-file) data via Chart.js canvas +
      `textContent`/numeric formatting — no `innerHTML` of untrusted strings,
      so no DOM XSS.
- [x] Metrics opt-in: `FENDIX_METRICS` defaults OFF → `NoopCollector`.
- [x] `baseline.yml` actions SHA-pinned; `${{ github.ref_name }}` routed
      through `env:` (no run-step injection).

## Notable positive outcome
The v0.20 benchmark triage **discovered a real accuracy defect** in the
*existing* exposure scanner (config-file FPs on SPA catch-all servers,
5 false CRITICALs on Juice Shop). Logged for v0.21 in `TASK_MANIFEST.md`.
This is exactly the "benchmark before marketing" payoff (Constitution Rule 5).

## Sign-off
- [x] No CRITICAL findings unresolved
- [x] No new HIGH findings introduced by v0.20 code
- [x] All outbound calls documented (loopback only + SRI-pinned CDN)
