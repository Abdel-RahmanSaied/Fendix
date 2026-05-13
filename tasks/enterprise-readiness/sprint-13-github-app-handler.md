# Sprint 13 — GitHub App handler glue

**Phase:** 5.1 | **Estimate:** 4 days | **Risk:** Med | **Ships:** v0.13.1
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §15.1 — "GitHub App webhook handler is stubbed"

---

## Reality check vs. source brief

The brief says `ghapp/webhook.go:7` is stubbed. **Actual status:** `ghapp/` is ~2856 LOC across 12 files. `webhook.go` itself is 227 LOC of working signature verification + transport code. The stub is in `handler.go` (per the package doc comment in `webhook.go:7`, which the brief misread).

What ALREADY works in `ghapp/`:
- `webhook.go` — HMAC-SHA256 signature validation, request parsing
- `auth.go` — App JWT → installation token exchange (272 LOC)
- `comment.go` — PR review comment posting (208 LOC, tests pass)
- `sarif.go` — SARIF upload to GitHub Code Scanning (92 LOC)
- `scanner.go` — self-invocation of fendix scan via `exec.Command` (201 LOC)

What's MISSING — the focus of this sprint:
- `handler.go` business logic: parse webhook event → dispatch by action → clone repo → run scan → post comment → cleanup. The plumbing all exists; this is glue.

This is **much smaller** than the brief implies. Realistic: ~150 LOC of glue + tests.

---

## Read first

- [`go/internal/ghapp/webhook.go`](../../go/internal/ghapp/webhook.go) — the entry point. See `ParseWebhookEvent`, `VerifySignature`.
- [`go/internal/ghapp/handler.go`](../../go/internal/ghapp/handler.go) — what's stubbed. Replace the stub.
- [`go/internal/ghapp/auth.go`](../../go/internal/ghapp/auth.go) — `InstallationToken(installationID)` returns a token usable for `comment.go` and `sarif.go`.
- [`go/internal/ghapp/scanner.go`](../../go/internal/ghapp/scanner.go) — `RunScan(scanRoot)` shells out to fendix and returns `[]models.Finding`.
- [`go/internal/ghapp/comment.go`](../../go/internal/ghapp/comment.go) — `PostReviewComment(token, owner, repo, prNumber, findings)`.
- [`go/cmd/fendix-app/main.go`](../../go/cmd/fendix-app/main.go) — the HTTP server entry that routes webhooks to the handler.

---

## Concrete deliverables

### 1. Implement `handler.go`

```go
// Package ghapp comment block stays as-is — webhook.go's reference to
// "stubbed in handler.go" is now resolved.

func HandlePullRequestEvent(ctx context.Context, payload []byte, cfg Config) error {
    var event struct {
        Action string `json:"action"`
        Number int    `json:"number"`
        PullRequest struct {
            Head struct {
                SHA string `json:"sha"`
                Ref string `json:"ref"`
            } `json:"head"`
            User struct {
                Login string `json:"login"`
            } `json:"user"`
        } `json:"pull_request"`
        Repository struct {
            CloneURL string `json:"clone_url"`
            FullName string `json:"full_name"` // owner/repo
        } `json:"repository"`
        Installation struct {
            ID int64 `json:"id"`
        } `json:"installation"`
    }
    if err := json.Unmarshal(payload, &event); err != nil {
        return fmt.Errorf("parse PR event: %w", err)
    }

    // Only handle actions we care about
    if event.Action != "opened" && event.Action != "synchronize" && event.Action != "reopened" {
        slog.Debug("PR action ignored", "action", event.Action, "pr", event.Number)
        return nil
    }

    // Acquire installation token for this org
    token, err := cfg.AuthProvider.InstallationToken(ctx, event.Installation.ID)
    if err != nil {
        return fmt.Errorf("get installation token for org %s: %w", event.Repository.FullName, err)
    }

    // Clone to temp dir
    tmpdir, err := os.MkdirTemp("", "fendix-pr-*")
    if err != nil {
        return fmt.Errorf("create tmpdir: %w", err)
    }
    defer os.RemoveAll(tmpdir)

    // Acquire clone slot — concurrent clones are capped
    if err := cfg.CloneSem.Acquire(ctx, 1); err != nil {
        return fmt.Errorf("acquire clone slot: %w", err)
    }
    defer cfg.CloneSem.Release(1)

    cloneURL := withInstallationToken(event.Repository.CloneURL, token)
    cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", "--branch", event.PullRequest.Head.Ref, cloneURL, tmpdir)
    if out, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("git clone %s @ %s: %w (output: %s)", event.Repository.FullName, event.PullRequest.Head.SHA, err, string(out))
    }

    // Run scan
    findings, err := RunScan(ctx, tmpdir)
    if err != nil {
        return fmt.Errorf("scan PR %s#%d: %w", event.Repository.FullName, event.Number, err)
    }

    // Post review comment
    owner, repo := splitRepoFullName(event.Repository.FullName)
    if err := PostReviewComment(ctx, token, owner, repo, event.Number, findings, event.PullRequest.Head.SHA); err != nil {
        return fmt.Errorf("post review: %w", err)
    }

    // Optional: post SARIF to Code Scanning if enabled
    if cfg.UploadSARIF {
        if err := UploadSARIF(ctx, token, owner, repo, event.PullRequest.Head.SHA, findings); err != nil {
            slog.Warn("SARIF upload failed (non-fatal)", "err", err)
        }
    }

    // Optional: create check-run with pass/fail status
    if cfg.UseCheckRuns {
        if err := CreateCheckRun(ctx, token, owner, repo, event.PullRequest.Head.SHA, findings, cfg.FailOnSeverity); err != nil {
            slog.Warn("check-run create failed (non-fatal)", "err", err)
        }
    }

    return nil
}

func withInstallationToken(cloneURL, token string) string {
    // https://github.com/owner/repo.git → https://x-access-token:<token>@github.com/owner/repo.git
    return strings.Replace(cloneURL, "https://", "https://x-access-token:"+token+"@", 1)
}
```

### 2. Async dispatch — 10s webhook timeout

GitHub webhooks have a 10s response timeout. Cloning + scanning takes minutes. The HTTP handler in `cmd/fendix-app/main.go` must:

1. Validate signature (synchronous, fast)
2. Parse the event (synchronous, fast)
3. Respond 202 Accepted immediately
4. Dispatch `HandlePullRequestEvent` to a goroutine

```go
// In cmd/fendix-app/main.go HTTP handler:
go func() {
    bgCtx := context.Background() // detached from request context
    if err := ghapp.HandlePullRequestEvent(bgCtx, payload, cfg); err != nil {
        slog.Error("PR event handling failed", "err", err)
    }
}()
w.WriteHeader(http.StatusAccepted)
w.Write([]byte(`{"status":"accepted"}`))
```

### 3. Concurrent clone cap

Add to `Config`:

```go
type Config struct {
    AuthProvider   AuthProvider
    CloneSem       *semaphore.Weighted  // cap on concurrent clones
    UploadSARIF    bool
    UseCheckRuns   bool
    FailOnSeverity models.Severity
}

func NewConfig() Config {
    return Config{
        CloneSem: semaphore.NewWeighted(3), // default 3 concurrent clones
        // ...
    }
}
```

### 4. Check-run integration (the brief's "TODO" is wrong)

Brief says check-runs require an installation-token flow that "doesn't exist." It does — `ghapp/auth.go` already exchanges App JWT → installation token. Wire it.

New file `go/internal/ghapp/checkrun.go`:

```go
// CreateCheckRun posts a check-run for the PR head SHA. Status =
// "completed", conclusion = "failure" if any finding meets/exceeds
// failOnSeverity, else "success". Includes a summary of finding counts.
func CreateCheckRun(ctx context.Context, token, owner, repo, sha string,
                   findings []models.Finding, failOnSeverity models.Severity) error {
    // POST /repos/{owner}/{repo}/check-runs
    // body: {"name": "fendix", "head_sha": "...", "status": "completed",
    //        "conclusion": "success" | "failure",
    //        "output": {"title": "...", "summary": "..."}}
}
```

### 5. Tests

New + extend in `handler_test.go`, `checkrun_test.go`:

```go
// TestHandlePullRequestEvent_OpenedAction_RunsFullPipeline (mocked clone + scan + comment)
// TestHandlePullRequestEvent_ClosedAction_Ignored
// TestHandlePullRequestEvent_NonMainBranch_Handled (any branch is fine, since we use the PR head ref)
// TestHandlePullRequestEvent_CloneFails_LogsAndReturnsError
// TestHandlePullRequestEvent_ScanFails_LogsAndReturnsError
// TestHandlePullRequestEvent_ConcurrentCloneCapRespected (POST 10 events, max 3 clones at once)
// TestHandlePullRequestEvent_CleansUpTmpDirOnSuccess
// TestHandlePullRequestEvent_CleansUpTmpDirOnFailure
// TestCheckRun_FailureWhenCriticalFindingAndFailOnSeverityHigh
// TestCheckRun_SuccessWhenNoFindings
```

E2E test using a local git server (`http.FileServer` serving a bare repo) to avoid GitHub dependency.

### 6. README + docs update

Update README's "GitHub App" section: the app now actually works end-to-end for `pull_request` events. Add a 5-step install guide.

## CHANGELOG

```markdown
### Added (v0.13.1)

- **GitHub App handler completed.** On `pull_request` events (opened,
  synchronize, reopened), the app now:
  1. Validates the webhook signature
  2. Acquires an installation token for the org
  3. Clones the PR's head SHA to a temp dir
  4. Runs a fendix scan
  5. Posts findings as a PR review comment
  6. Optionally uploads SARIF to GitHub Code Scanning
  7. Optionally creates a check-run with pass/fail status

  Concurrent clones capped at 3 (configurable). Webhook responds with
  202 Accepted immediately; scan runs async. Webhook signature
  validation remains mandatory if `FENDIX_GITHUB_WEBHOOK_SECRET` is set.
```

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Large monorepo clones exceed temp disk | Med | `git clone --depth=1` + clone-slot cap. Monitor disk usage in a future sprint. |
| Concurrent webhooks from a single repo race on the same SHA | Low | Each event gets its own tmpdir; idempotent comment posting (check if comment already exists by marker). |
| GitHub rate-limits the App | Low | Installation tokens have 5000 req/hr per installation — generous. |
| Long-running scan exceeds the goroutine's background context lifetime | Med | Set a hard timeout on the per-PR context (e.g. 30 min); cancel and abandon if exceeded. |

## Definition of done

Standard DoD plus:
- Manual end-to-end test against a real GitHub App installation (record steps in PR)
- 10+ unit tests, 1 e2e test against local git server
- README's GitHub App section is no longer marked "preview" or "stubbed"

## Follow-ups

- **Sprint 13.5:** GitHub Marketplace listing prep (requires legal/billing setup)
- **Sprint 13.6:** Other webhook events: `push`, `release`, `repository_dispatch`
- **Sprint 13.7:** Per-org config — `.fendix.yaml` checked into the scanned repo, honored by the App handler

## Status

**Not started.**
