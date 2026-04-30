package ghapp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Handler is the production EventRouter. It owns the App credentials
// (via TokenSource), the scan-runner, and the GitHub API client. The
// scan-runner and SARIF uploader are stubs in this commit — pending
// the follow-up TASK-107b commit that wires up real clone + scan +
// PR-comment + SARIF upload.
//
// To exercise this skeleton end-to-end against a live App: register the
// App via app/manifest.yml, set FENDIX_APP_ID + FENDIX_APP_PRIVATE_KEY
// + FENDIX_WEBHOOK_SECRET, deploy cmd/fendix-app, point the App's
// webhook at the deployment, and watch logs — the App authenticates,
// fetches installation tokens, and acknowledges events without yet
// running scans.
type Handler struct {
	Tokens *TokenSource
	// CommentBackend is the function the handler calls to post a PR
	// comment. Defaults to a stub that just logs. Override in tests
	// or in TASK-107b.
	CommentBackend func(ctx context.Context, installationID int64, owner, repo string, prNumber int, body string) error
	// ScanRunner is the function the handler calls to run a fendix
	// scan against a checked-out PR. Defaults to a stub that returns
	// a synthetic empty-findings JSON. Override in tests or TASK-107b.
	ScanRunner func(ctx context.Context, repoCloneURL, headSHA string) (findingsJSON []byte, err error)
}

// HandlePullRequest is invoked on pull_request webhook events. The MVP
// flow:
//
//  1. Decode minimal fields from the payload (action, head SHA, owner,
//     repo, PR number, installation ID).
//  2. Filter to action ∈ {opened, synchronize, reopened} — the events
//     that warrant a scan.
//  3. Get installation token (cached/single-flighted via TokenSource).
//  4. Run a fendix scan (STUBBED — see ScanRunner).
//  5. Post PR comment summarising findings (STUBBED — see CommentBackend).
//  6. Upload SARIF (STUBBED — see TASK-107b).
//
// Steps 4–6 are stubs in this commit. The point of shipping the scaffold
// without them is to give operators a deployable Server they can
// point a real App at — they'll see steps 1–3 work end-to-end (events
// arrive, sigs verify, tokens fetch), with steps 4–6 obviously marked
// as not-yet-wired. That's a clearer testable surface than a monolithic
// commit nobody can incrementally validate.
func (h *Handler) HandlePullRequest(ctx Context, body []byte) error {
	var p struct {
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
			Name string `json:"name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
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
		// (the App wasn't installed in the source repo). Nothing to do.
		ctx.Logger.Info("pull_request without installation; skipping")
		return nil
	}

	bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tok, err := h.Tokens.Get(bgCtx, p.Installation.ID)
	if err != nil {
		return fmt.Errorf("installation token: %w", err)
	}
	ctx.Logger.Info("installation token acquired",
		"installation_id", p.Installation.ID,
		"expires_at", tok.ExpiresAt.Format(time.RFC3339),
	)

	scanRunner := h.ScanRunner
	if scanRunner == nil {
		scanRunner = stubScanRunner
	}
	findings, err := scanRunner(bgCtx, p.PullRequest.Head.Repo.CloneURL, p.PullRequest.Head.SHA)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	ctx.Logger.Info("scan complete (stub)", "findings_bytes", len(findings))

	commentBackend := h.CommentBackend
	if commentBackend == nil {
		commentBackend = stubCommentBackend
	}
	commentBody := fmt.Sprintf("Fendix scan placeholder for PR #%d at %s — TASK-107b not yet wired.",
		p.Number, p.PullRequest.Head.SHA)
	if err := commentBackend(bgCtx, p.Installation.ID,
		p.Repository.Owner.Login, p.Repository.Name, p.Number, commentBody); err != nil {
		return fmt.Errorf("post comment: %w", err)
	}

	// SARIF upload to Code Scanning API: TASK-107b.
	ctx.Logger.Info("SARIF upload stubbed — TASK-107b")

	return nil
}

// HandlePush is the webhook entrypoint for push events. Push to the
// default branch will eventually trigger a fresh baseline scan; pushes
// to feature branches are no-ops (the pull_request handler covers them).
// Currently stubbed.
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

// HandleCheckRun lets the App respond to "Re-run check" button clicks.
// Currently stubbed; will re-trigger the scan for the same head SHA in
// TASK-107b.
func (h *Handler) HandleCheckRun(ctx Context, body []byte) error {
	var p struct {
		Action   string `json:"action"`
		CheckRun struct {
			Name    string `json:"name"`
			HeadSHA string `json:"head_sha"`
		} `json:"check_run"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("decode check_run: %w", err)
	}
	ctx.Logger.Info("check_run received",
		"action", p.Action,
		"name", p.CheckRun.Name,
		"head_sha", p.CheckRun.HeadSHA,
		"wired", false,
	)
	return nil
}

func stubScanRunner(_ context.Context, cloneURL, sha string) ([]byte, error) {
	// Returns the shape of a real scan output but with no findings —
	// enough for the comment-rendering stub to produce a sensible
	// placeholder message without false positives.
	stub := fmt.Sprintf(`{"clone_url":%q,"head_sha":%q,"findings":[],"summary":{"critical":0,"high":0,"medium":0,"low":0,"info":0},"stub":true}`, cloneURL, sha)
	return []byte(stub), nil
}

func stubCommentBackend(_ context.Context, installID int64, owner, repo string, prNumber int, body string) error {
	// Real implementation will POST to
	//   /repos/{owner}/{repo}/issues/{pr_number}/comments
	// using the installation token. TASK-107b.
	return nil
}
