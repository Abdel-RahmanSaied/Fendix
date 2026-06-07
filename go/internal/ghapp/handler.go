package ghapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// HandlerScanTimeout caps total wall-clock time for a single PR scan
// (clone + scan + comment + SARIF upload). Long enough for a typical
// repo + Semgrep run; short enough that a stuck scan doesn't pin a
// goroutine for hours.
const HandlerScanTimeout = 15 * time.Minute

// Handler is the production EventRouter. It owns the App credentials
// (via TokenSource), the Scanner, an HTTP client + GitHub API base
// URL, and optional override hooks for tests. Production deployments
// instantiate it via NewHandler with sensible defaults.
type Handler struct {
	// Tokens supplies installation tokens (single-flighted + cached).
	Tokens *TokenSource

	// BaseURL is the GitHub REST API base. Default:
	// https://api.github.com. Override for GitHub Enterprise Server.
	BaseURL string

	// HTTPClient is reused for comment + SARIF API calls. Default:
	// http.DefaultClient.
	HTTPClient *http.Client

	// Scanner runs the actual fendix scan. Default: &FendixScanner{}.
	// Tests inject fakes.
	Scanner Scanner

	// PostComment posts a PR comment. Default: PostPRComment using
	// Handler.HTTPClient + Handler.BaseURL. Tests inject fakes.
	PostComment func(ctx context.Context, installationToken, owner, repo string, prNumber int, body string) error

	// UploadSARIF uploads a SARIF blob. Default: UploadSARIF using
	// Handler.HTTPClient + Handler.BaseURL. Tests inject fakes.
	UploadSARIF func(ctx context.Context, installationToken, owner, repo, commitSHA, ref string, sarif []byte) error

	// pool runs clone+scan on a bounded background worker pool so the
	// webhook request path returns immediately (F-H5a). Constructed by
	// NewHandler; nil only in tests that build a Handler literal, in
	// which case runScan executes synchronously (see enqueueScan).
	pool *scanPool
}

// NewHandler constructs a Handler with production defaults wired
// from the components passed in. baseURL may be empty (defaults to
// https://api.github.com). httpClient may be nil (defaults to
// http.DefaultClient). maxConcurrentScans bounds the background scan
// worker pool; values < 1 fall back to DefaultMaxConcurrentScans.
//
// The Handler starts a background worker pool (F-H5a). Call Shutdown
// during graceful shutdown to drain in-flight scans.
func NewHandler(tokens *TokenSource, baseURL string, httpClient *http.Client, maxConcurrentScans int) *Handler {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	h := &Handler{
		Tokens:     tokens,
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Scanner:    &FendixScanner{},
		pool:       newScanPool(maxConcurrentScans, DefaultScanQueueDepth, HandlerScanTimeout),
	}
	h.PostComment = func(ctx context.Context, installationToken, owner, repo string, prNumber int, body string) error {
		return PostPRComment(ctx, h.HTTPClient, h.BaseURL, installationToken, owner, repo, prNumber, body)
	}
	h.UploadSARIF = func(ctx context.Context, installationToken, owner, repo, commitSHA, ref string, sarif []byte) error {
		return UploadSARIF(ctx, h.HTTPClient, h.BaseURL, installationToken, owner, repo, commitSHA, ref, sarif)
	}
	return h
}

// Shutdown drains the background scan pool: it stops accepting new
// scans, cancels in-flight scan contexts, and waits (bounded by ctx)
// for outstanding scans to finish. Wire it into the server's graceful
// shutdown so a deploy/SIGTERM doesn't sever an in-progress scan
// abruptly. Safe to call on a Handler with no pool (no-op).
func (h *Handler) Shutdown(ctx context.Context) error {
	if h.pool == nil {
		return nil
	}
	return h.pool.Shutdown(ctx)
}

// pullRequestPayload is the minimal subset of GitHub's pull_request
// webhook payload the handler reads. Other fields decode silently.
type pullRequestPayload struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA  string `json:"sha"`
			Repo struct {
				CloneURL string `json:"clone_url"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
		Name     string `json:"name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

// HandlePullRequest is invoked on pull_request webhook events. The
// flow:
//
//  1. Decode the payload.
//  2. Filter to scan-worthy actions (opened / synchronize / reopened).
//  3. Get an installation token (cached + single-flighted).
//  4. Clone the head SHA + run the scan.
//  5. Post a PR comment summarising findings.
//  6. Upload SARIF to Code Scanning.
//
// Steps 5–6 are deliberately not fatal to each other: if SARIF upload
// fails (e.g. Code Scanning not enabled on the repo), the comment
// still posts and the operator can re-enable Code Scanning later.
// A failed comment post does fail the handler so GitHub retries —
// the comment is the user-visible signal that the App is alive.
func (h *Handler) HandlePullRequest(ctx Context, body []byte) error {
	var p pullRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("decode pull_request: %w", err)
	}

	switch p.Action {
	case "opened", "synchronize", "reopened":
		// scan-worthy actions; fall through
	default:
		ctx.Logger.Info("skipping pull_request action", "action", p.Action)
		return nil
	}

	if p.Installation.ID == 0 {
		// Acted-on-by-user PR webhooks don't include an installation
		// (the App wasn't installed in the source repo). Nothing to
		// do — we have no credentials to scan with.
		ctx.Logger.Info("pull_request without installation; skipping")
		return nil
	}

	cloneURL := p.PullRequest.Head.Repo.CloneURL
	if cloneURL == "" {
		cloneURL = p.Repository.CloneURL
	}

	// F-H5a: acknowledge immediately. Everything past signature verify
	// and decode runs on the bounded background pool so the webhook
	// request returns in milliseconds (GitHub disables endpoints that
	// respond slowly or time out).
	h.enqueueScan(ctx, scanInputs{
		InstallationID: p.Installation.ID,
		Owner:          p.Repository.Owner.Login,
		Repo:           p.Repository.Name,
		PRNumber:       p.Number,
		HeadSHA:        p.PullRequest.Head.SHA,
		CloneURL:       cloneURL,
		Ref:            "refs/pull/" + strconv.Itoa(p.Number) + "/head",
	})
	return nil
}

// scanInputs is the per-scan parameters extracted from a webhook
// payload. Centralising them lets HandlePullRequest and
// HandleCheckRun share a single runScan path.
type scanInputs struct {
	InstallationID int64
	Owner          string
	Repo           string
	PRNumber       int
	HeadSHA        string
	CloneURL       string
	Ref            string
}

// enqueueScan submits a scan to the background pool, returning
// immediately (F-H5a). It dedupes by X-GitHub-Delivery when present,
// else by (installation, repo, headSHA) so a redelivered webhook or a
// burst of synchronize events for the same head doesn't run the same
// scan twice concurrently. A full queue or a deduped/closed-pool
// submission is logged, not surfaced — the webhook was already
// acknowledged, so GitHub will redeliver if needed.
//
// When the Handler has no pool (a bare struct literal, used by some
// tests), the scan runs synchronously with its own timeout context so
// existing behaviour is preserved.
func (h *Handler) enqueueScan(ctx Context, in scanInputs) {
	if in.HeadSHA == "" || in.CloneURL == "" {
		ctx.Logger.Info("scan inputs incomplete; skipping",
			"have_sha", in.HeadSHA != "",
			"have_clone_url", in.CloneURL != "",
		)
		return
	}

	key := ctx.Delivery
	if key == "" {
		key = fmt.Sprintf("%d/%s/%s/%s", in.InstallationID, in.Owner, in.Repo, in.HeadSHA)
	}

	if h.pool == nil {
		// No pool (test literal): run inline with a bounded context.
		bgCtx, cancel := context.WithTimeout(context.Background(), HandlerScanTimeout)
		defer cancel()
		if err := h.runScan(bgCtx, ctx, in); err != nil {
			ctx.Logger.Error("scan failed", "err", err)
		}
		return
	}

	logger := ctx.Logger
	err := h.pool.submit(scanJob{
		key: key,
		run: func(bgCtx context.Context) {
			if err := h.runScan(bgCtx, ctx, in); err != nil {
				logger.Error("scan failed", "err", err, "repo", in.Owner+"/"+in.Repo, "sha", in.HeadSHA)
			}
		},
	})
	switch {
	case err == nil:
		logger.Info("scan enqueued", "repo", in.Owner+"/"+in.Repo, "sha", in.HeadSHA, "dedup_key", key)
	case errors.Is(err, errDuplicate):
		logger.Info("scan already in flight; deduped", "dedup_key", key)
	case errors.Is(err, errQueueFull):
		logger.Warn("scan queue full; dropping (GitHub will retry)", "dedup_key", key)
	case errors.Is(err, errPoolClosed):
		logger.Warn("scan pool closed; dropping", "dedup_key", key)
	}
}

func (h *Handler) runScan(bgCtx context.Context, ctx Context, in scanInputs) error {
	if in.HeadSHA == "" || in.CloneURL == "" {
		ctx.Logger.Info("scan inputs incomplete; skipping",
			"have_sha", in.HeadSHA != "",
			"have_clone_url", in.CloneURL != "",
		)
		return nil
	}

	tok, err := h.Tokens.Get(bgCtx, in.InstallationID)
	if err != nil {
		return fmt.Errorf("installation token: %w", err)
	}
	ctx.Logger.Info("installation token acquired",
		"installation_id", in.InstallationID,
		"expires_at", tok.ExpiresAt.Format(time.RFC3339),
	)

	scanner := h.Scanner
	if scanner == nil {
		scanner = &FendixScanner{}
	}
	result, err := scanner.Run(bgCtx, ScanRequest{
		CloneURL:          in.CloneURL,
		HeadSHA:           in.HeadSHA,
		InstallationToken: tok.Token,
	})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	ctx.Logger.Info("scan complete",
		"findings_bytes", len(result.FindingsJSON),
		"sarif_bytes", len(result.SARIF),
	)

	body, err := RenderPRComment(result.FindingsJSON)
	if err != nil {
		return fmt.Errorf("render comment: %w", err)
	}

	if h.PostComment != nil && in.PRNumber > 0 {
		if err := h.PostComment(bgCtx, tok.Token, in.Owner, in.Repo, in.PRNumber, body); err != nil {
			return fmt.Errorf("post comment: %w", err)
		}
		ctx.Logger.Info("PR comment posted", "pr", in.PRNumber)
	}

	if h.UploadSARIF != nil && len(result.SARIF) > 0 {
		// SARIF upload is best-effort — a misconfigured repo (Code
		// Scanning disabled, branch ref missing) shouldn't fail the
		// whole webhook. Log and continue.
		if err := h.UploadSARIF(bgCtx, tok.Token, in.Owner, in.Repo, in.HeadSHA, in.Ref, result.SARIF); err != nil {
			ctx.Logger.Warn("SARIF upload failed", "err", err)
		} else {
			ctx.Logger.Info("SARIF uploaded", "ref", in.Ref, "sha", in.HeadSHA)
		}
	}

	return nil
}

// HandlePush is the webhook entrypoint for push events. Push to the
// default branch will eventually trigger a baseline-refresh scan;
// pushes to feature branches are no-ops (the pull_request handler
// covers them). Currently a no-op acknowledgement — push-driven
// baseline refresh is a follow-up.
func (h *Handler) HandlePush(ctx Context, body []byte) error {
	var p struct {
		Ref string `json:"ref"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("decode push: %w", err)
	}
	ctx.Logger.Info("push received", "ref", p.Ref, "wired", false)
	return nil
}

// HandleCheckRun handles the "Re-run check" button click in the
// GitHub UI. GitHub sends action=rerequested with the check_run's
// head_sha; we re-run the scan against that SHA. Other actions
// (created/completed) are silently acknowledged.
func (h *Handler) HandleCheckRun(ctx Context, body []byte) error {
	var p struct {
		Action   string `json:"action"`
		CheckRun struct {
			Name         string `json:"name"`
			HeadSHA      string `json:"head_sha"`
			PullRequests []struct {
				Number int `json:"number"`
			} `json:"pull_requests"`
		} `json:"check_run"`
		Repository struct {
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
			Name     string `json:"name"`
			CloneURL string `json:"clone_url"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("decode check_run: %w", err)
	}

	if p.Action != "rerequested" {
		ctx.Logger.Info("check_run received",
			"action", p.Action,
			"name", p.CheckRun.Name,
			"head_sha", p.CheckRun.HeadSHA,
		)
		return nil
	}
	if p.Installation.ID == 0 {
		ctx.Logger.Info("check_run rerequested without installation; skipping")
		return nil
	}

	prNumber := 0
	if len(p.CheckRun.PullRequests) > 0 {
		prNumber = p.CheckRun.PullRequests[0].Number
	}
	ref := p.CheckRun.HeadSHA
	if prNumber > 0 {
		ref = "refs/pull/" + strconv.Itoa(prNumber) + "/head"
	}

	// F-H5a: acknowledge immediately; scan runs on the background pool.
	h.enqueueScan(ctx, scanInputs{
		InstallationID: p.Installation.ID,
		Owner:          p.Repository.Owner.Login,
		Repo:           p.Repository.Name,
		PRNumber:       prNumber,
		HeadSHA:        p.CheckRun.HeadSHA,
		CloneURL:       p.Repository.CloneURL,
		Ref:            ref,
	})
	return nil
}
