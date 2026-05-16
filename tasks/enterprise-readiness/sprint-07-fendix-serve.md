# Sprint 07 — `fendix serve` REST API (in-memory)

**Phase:** 3.1 | **Estimate:** 5 days | **Risk:** **High** | **Ships:** v0.12.1
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §13 (no server mode today)

---

## Why

Every Phase-5 integration (Jira, Slack/Teams, scheduled scans) needs an event loop that outlives a one-shot CLI invocation. This sprint adds `fendix serve` — a stdlib `net/http` REST API with an in-memory job queue. No router framework, no SQL, no SSO (Sprint 08 adds OIDC).

**Decision D1** (in PLAN.md): in-memory only for MVP. Jobs lost on restart. SQLite persistence layer is Sprint 07.5 if/when committed.

---

## Read first

- [`go/cmd/fendix-app/`](../../go/cmd/fendix-app/) — existing GitHub App binary. **Do NOT change it.** Use it as a reference for the HTTP server pattern but build a separate subcommand.
- [`go/cmd/fendix/main.go`](../../go/cmd/fendix/main.go) — see how other subcommands (`scan`, `verify`, `report`, `init`, `plugins`, `ignore`, `demo`) are wired with cobra.
- [`go/internal/engine/orchestrator.go`](../../go/internal/engine/orchestrator.go) — the `Orchestrator.Run(ctx)` you'll invoke per job.
- [`go/internal/models/scan_config.go`](../../go/internal/models/scan_config.go) — `ScanConfig` is what each scan job constructs.

---

## Routes

```
GET    /api/v1/health                          — liveness
POST   /api/v1/scans                           — create job
GET    /api/v1/scans/:id                       — job status + findings (if done)
GET    /api/v1/scans/:id/findings?page=N&limit=50  — paginated
```

All routes require `Authorization: Bearer <api_key>` middleware. `/api/v1/health` is the exception — public.

## ScanRequest body

```go
type ScanRequest struct {
    URL      string `json:"url,omitempty"`
    CodePath string `json:"code_path,omitempty"`
    Auth     string `json:"auth,omitempty"`
    Format   string `json:"format,omitempty"` // ignored — API always returns JSON
    // Optional per-job timeout. If unset, uses server default.
    TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}
```

Server default timeout: 30 minutes. Hard ceiling: 60 minutes.

## ScanJob response

```go
type ScanJob struct {
    ID         string         `json:"id"`            // UUID
    Status     string         `json:"status"`        // queued|running|done|failed
    CreatedAt  time.Time      `json:"created_at"`
    StartedAt  *time.Time     `json:"started_at,omitempty"`
    FinishedAt *time.Time     `json:"finished_at,omitempty"`
    Request    ScanRequest    `json:"request"`
    Findings   []models.Finding `json:"findings,omitempty"` // populated when done
    Error      string         `json:"error,omitempty"`   // populated when failed
}
```

## Job execution model

- `sync.Map` keyed by job UUID for storage
- Buffered channel `chan jobID` as the queue (capacity 100)
- Worker goroutines (count = `min(4, GOMAXPROCS)`) pull from the channel
- Each worker constructs an `Orchestrator` per job and calls `Run(ctx)`
- Per-job context with timeout from the request (or server default)
- Server-wide context that cancels all workers on SIGTERM

```go
package servecmd

type Server struct {
    cfg        Config
    jobs       sync.Map      // jobID → *ScanJob
    queue      chan string   // jobID
    workers    int
    drainCtx   context.Context
    drainCancel context.CancelFunc
}

func (s *Server) startWorkers() {
    for i := 0; i < s.workers; i++ {
        go s.workerLoop()
    }
}

func (s *Server) workerLoop() {
    for {
        select {
        case <-s.drainCtx.Done():
            return
        case jobID, ok := <-s.queue:
            if !ok {
                return
            }
            s.runJob(jobID)
        }
    }
}

func (s *Server) runJob(jobID string) {
    val, _ := s.jobs.Load(jobID)
    job := val.(*ScanJob)

    // Transition queued → running
    now := time.Now().UTC()
    job.Status = "running"
    job.StartedAt = &now

    // Per-job timeout
    timeout := time.Duration(job.Request.TimeoutSeconds) * time.Second
    if timeout == 0 {
        timeout = s.cfg.DefaultJobTimeout
    }
    if timeout > s.cfg.MaxJobTimeout {
        timeout = s.cfg.MaxJobTimeout
    }
    ctx, cancel := context.WithTimeout(s.drainCtx, timeout)
    defer cancel()

    // Build orchestrator + run
    scanCfg := buildScanConfig(job.Request)
    orch := engine.NewOrchestrator(&scanCfg, version)
    exitCode := orch.Run(ctx)
    fin := time.Now().UTC()
    job.FinishedAt = &fin

    if exitCode == 2 {
        job.Status = "failed"
        job.Error = "scan failed — see fendix logs"
    } else {
        job.Status = "done"
        // Pull findings from orchestrator output buffer (see deliverable 3)
    }
}
```

## Pagination

Default `limit=50`, max `limit=200`. `page` is 1-indexed. Response:

```json
{
  "job_id": "...",
  "page": 1,
  "limit": 50,
  "total": 137,
  "findings": [ ... ]
}
```

## Graceful shutdown

```go
// On SIGTERM:
// 1. http.Server.Shutdown(ctx) — stop accepting new requests
// 2. Mark drainCtx done — workers exit when current job finishes
// 3. /api/v1/health returns 503 while draining
// 4. Wait up to 60s for workers; force-exit after that
```

## Config (in `.fendix.yaml` + env vars)

```yaml
serve:
  api_key: ""                  # required; or FENDIX_API_KEY env
  port: 8080
  host: ""                     # bind addr
  workers: 4
  default_job_timeout: 1800    # seconds (30 min)
  max_job_timeout: 3600        # seconds (60 min)
  queue_size: 100
  cors_origin: ""              # empty = no CORS (server-to-server only)
```

If `serve.api_key` is unset AND `FENDIX_API_KEY` is unset, server **refuses to start** with:

```
fendix serve: no API key configured.
Set FENDIX_API_KEY env var or `serve.api_key` in .fendix.yaml.
This is intentional — fendix serve always requires authentication.
```

## CLI flags on `fendix serve`

```
--port           int     (default 8080, or .fendix.yaml serve.port)
--host           string  (default "", or .fendix.yaml serve.host)
--workers        int     (default min(4, GOMAXPROCS))
--config         string  (path to .fendix.yaml; same as scan)
--max-jobs       int     (default 100; in-flight queue capacity)
--cors-origin    string  (default ""; comma-separated list of allowed origins)
```

Workers > queue capacity is silly — log a warning and clamp.

## Tests — `servecmd/serve_test.go`

```go
// TestHealth_ReturnsOK
// TestUnauthenticatedRequest_Returns401
// TestPostScanWithBadAuth_Returns401
// TestPostScanCreatesQueuedJob
// TestGetScanReturnsQueuedThenRunningThenDone (uses a fake fast-scanning orchestrator)
// TestGetScanFindingsPagination
// TestScanWithoutURLOrCodePath_Returns400
// TestServerRefusesToStartWithoutAPIKey
// TestGracefulShutdownDrainsRunningJobs
// TestConcurrentScanLimitRespected (POST 10 jobs, assert at most `workers` run at once)
// TestPerJobTimeoutHonored (set TimeoutSeconds=1; orchestrator that sleeps 5s → status=failed)
// TestServerSideMaxTimeoutCapsRequest (TimeoutSeconds=999999 → capped to MaxJobTimeout)
```

E2E test in `go/internal/e2e/serve_e2e_test.go`:
- Start server in a goroutine, hit it with `net/http`, POST a real scan against a known-vulnerable fixture, poll until done, verify findings.

## CHANGELOG

```markdown
### Added (v0.12.1)

- **`fendix serve`** — REST API server mode for long-running deployment.
  In-memory job queue + worker pool, stdlib net/http (no router framework).
  Single static API key auth (OIDC in Sprint 08).

  Routes:
  - `GET  /api/v1/health`
  - `POST /api/v1/scans`
  - `GET  /api/v1/scans/:id`
  - `GET  /api/v1/scans/:id/findings?page=N&limit=50`

  Limits: workers default 4, queue capacity 100, per-job timeout 30 min
  (capped at 60). Graceful shutdown drains running jobs.

  **In-memory persistence only — jobs are lost on restart.** SQLite
  persistence is Sprint 07.5 in the enterprise-readiness plan.
```

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Auth middleware design coupled too tightly to static key — Sprint 08 OIDC refactors it | Med | Design the middleware as "any auth backend that produces a `principal`" from the start. OIDC adds one more backend; doesn't refactor. |
| Worker count too low under load → queue fills, POST returns 503 | Med | `--max-jobs` flag is the escape hatch. Document the trade-off. |
| Long-running scan holds a goroutine for 30 min — no way to cancel from API | Med | Add `DELETE /api/v1/scans/:id` that cancels the job's context. Out of scope for MVP — TODO in code. |
| Findings stored in memory — large scans (10k findings) eat RAM | Low | Per-job cap at 10k findings; truncate with a warning. |
| In-memory queue lost on restart = duplicate POSTs from clients | High by-design | Documented in CHANGELOG. Sprint 07.5 fixes with SQLite. |

---

## Definition of done

Standard DoD plus:
- 12+ unit tests + 1 e2e test
- `bin/fendix serve --help` shows all flags accurately
- Running `bin/fendix serve` against the Fendix repo at `--code .` succeeds; another shell can POST a scan and retrieve findings
- README updated with a brief "API mode" section

## Follow-ups

- **Sprint 07.5:** SQLite persistence layer (only if D1 = A)
- **Sprint 07.6:** `DELETE /api/v1/scans/:id` cancellation
- **Sprint 07.7:** Webhook callback URL — server POSTs to user-specified URL on job completion
- **Sprint 07.8:** Multi-tenant API (per-tenant API keys, per-tenant job isolation)

## Status

**Status:** **closed by reference** in the plan-finish session,
commit [`75a939a`](../../../../commit/75a939a) — `docs(plan): close Sprints 07/08 by reference + final hand-off`.

**Resolution:** the persistence and REST-API story moved to the
sibling [`fendix-backend`](../../../fendix-backend) Django + DRF
repo (Postgres 16 + Redis + Celery 5.4), per [`DECISIONS.md` D1
resolution](DECISIONS.md#L63-L79). The `fendix` CLI in this repo
stays a CLI — building a parallel in-memory `fendix serve` HTTP
surface here would have duplicated work the sibling repo already
does properly. If a customer specifically needs a single-binary
serve mode in the future (no fendix-backend dependency), this sprint
can be re-opened.

**Status section backfill (2026-05-16):** Section was empty at ship
time (DoD #7 not honored). The "closed by reference" decision is in
DECISIONS.md, but the sprint file itself wasn't updated.
