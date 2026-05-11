package ghapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// findingsReport mirrors the `fendix scan --format json` schema
// (docs/schema.md). Only the fields the PR-comment template reads
// are declared — extra fields decode silently.
type findingsReport struct {
	Metadata struct {
		Mode             string `json:"mode"`
		EndpointsScanned int    `json:"endpoints_scanned"`
		Duration         string `json:"duration"`
	} `json:"metadata"`
	Summary struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
		Info     int `json:"info"`
	} `json:"summary"`
	Sources struct {
		Blackbox   int `json:"blackbox"`
		Whitebox   int `json:"whitebox"`
		Correlated int `json:"correlated"`
	} `json:"sources"`
	Total    int `json:"total"`
	Findings []struct {
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Category string `json:"category"`
		Endpoint string `json:"endpoint"`
		Line     string `json:"line"`
	} `json:"findings"`
}

// findingHash returns a short stable hash of (title, category, endpoint).
// Used in the PR-comment suppression snippet so users can map a
// .fendix-ignore entry back to a specific finding even after SEC-NNN
// IDs reassign across scans. Truncated to 8 hex chars — collision-
// resistance over a single repo's finding set is fine at this length
// (2^32 unique values).
//
// TASK-124. The hash is documentary (a // comment in YAML); the actual
// suppression key is the (endpoint, category) pair, which is what the
// existing ignore.go matcher already uses.
func findingHash(title, category, endpoint string) string {
	h := sha256.Sum256([]byte(title + "|" + category + "|" + endpoint))
	return hex.EncodeToString(h[:4]) // 8 hex chars
}

// suppressionSnippet renders the one-line YAML the user copies into
// .fendix-ignore to suppress this finding. Format matches
// internal/engine/ignore.go::IgnoreRule (endpoint glob + category
// case-insensitive match). A trailing `# fp-<hash>` comment lets users
// search for the exact suppression they pasted later.
//
// TASK-124 / FP-corpus pattern P1 (test fixtures flagged as prod) is
// the highest-volume case this helps with — one paste per pattern,
// not one paste per instance, since the endpoint can be a glob.
func suppressionSnippet(title, category, endpoint string) string {
	if category == "" {
		category = "unknown"
	}
	if endpoint == "" {
		endpoint = "*"
	}
	// Quote the endpoint so a path with leading `/` or special chars
	// parses unambiguously as a string scalar in YAML.
	return fmt.Sprintf(`- {endpoint: %q, category: %q}  # fp-%s`,
		endpoint, category, findingHash(title, category, endpoint))
}

// RenderPRComment builds the Markdown body for a PR comment from a
// fendix findings JSON. The format mirrors the github-script template
// in examples/github-actions/fendix-scan.yml so PRs scanned via the
// GitHub App and PRs scanned via the reference workflow show
// identical output — users see the same wedge story regardless of
// installation path.
func RenderPRComment(findingsJSON []byte) (string, error) {
	var r findingsReport
	if err := json.Unmarshal(findingsJSON, &r); err != nil {
		return "", fmt.Errorf("parse findings JSON: %w", err)
	}

	mode := r.Metadata.Mode
	if mode == "" {
		mode = "unknown"
	}
	duration := r.Metadata.Duration
	if duration == "" {
		duration = "n/a"
	}

	total := r.Total
	if total == 0 && len(r.Findings) > 0 {
		total = len(r.Findings)
	}

	var b strings.Builder
	pluralS := "s"
	if total == 1 {
		pluralS = ""
	}
	fmt.Fprintf(&b, "## Fendix scan: %d finding%s\n\n", total, pluralS)
	fmt.Fprintf(&b, "Mode: `%s` · Endpoints scanned: %d · Duration: %s\n\n",
		mode, r.Metadata.EndpointsScanned, duration)

	b.WriteString("| Severity | Count | Source | Count |\n")
	b.WriteString("|---|---|---|---|\n")
	fmt.Fprintf(&b, "| Critical | %d | Blackbox | %d |\n", r.Summary.Critical, r.Sources.Blackbox)
	fmt.Fprintf(&b, "| High | %d | Whitebox | %d |\n", r.Summary.High, r.Sources.Whitebox)
	fmt.Fprintf(&b, "| Medium | %d | Correlated | %d |\n", r.Summary.Medium, r.Sources.Correlated)
	fmt.Fprintf(&b, "| Low | %d | _Total_ | **%d** |\n", r.Summary.Low, total)
	fmt.Fprintf(&b, "| Info | %d | | |\n\n", r.Summary.Info)

	if total == 0 {
		b.WriteString("_No new findings vs. baseline. ✅_\n\n")
	} else {
		b.WriteString("### Top findings\n")
		topN := len(r.Findings)
		if topN > 5 {
			topN = 5
		}
		for i := 0; i < topN; i++ {
			f := r.Findings[i]
			where := f.Endpoint
			if where == "" {
				where = f.Line
			}
			fmt.Fprintf(&b, "- **[%s]** %s — `%s`\n", f.Severity, f.Title, where)
			// TASK-124: one-click suppression snippet. Keyed on
			// (endpoint, category) — the (title, category, endpoint)
			// hash in the trailing comment lets users map back to the
			// originating finding after they paste.
			fmt.Fprintf(&b, "  ```yaml\n  %s\n  ```\n",
				suppressionSnippet(f.Title, f.Category, where))
		}
		if total > 5 {
			fmt.Fprintf(&b, "\n_…and %d more in the SARIF report._\n", total-5)
		}
		b.WriteString("\n")
		b.WriteString("<sub>Copy a `yaml` block into `.fendix-ignore` to suppress that finding. ")
		b.WriteString("The `# fp-<hash>` comment is stable across runs — search for it later.</sub>\n\n")
	}

	b.WriteString("<sub>Open the **Security** tab for inline annotations. ")
	b.WriteString("Re-run this workflow to refresh.</sub>\n")
	return b.String(), nil
}

// PostPRComment posts a comment on a pull request using the GitHub
// Issues API (PR comments are issue comments — the Issues endpoint
// is the canonical post path; the Pulls API is for review comments
// on specific lines, which we don't use).
//
// baseURL defaults to https://api.github.com when empty. The
// installation token is sent in the Authorization header as a
// Bearer token, the format GitHub recommends for App-installed
// tokens.
func PostPRComment(ctx context.Context, httpClient *http.Client, baseURL, installationToken, owner, repo string, prNumber int, body string) error {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	url := strings.TrimRight(baseURL, "/") +
		"/repos/" + owner + "/" + repo +
		"/issues/" + strconv.Itoa(prNumber) + "/comments"

	payload, err := json.Marshal(struct {
		Body string `json:"body"`
	}{Body: body})
	if err != nil {
		return fmt.Errorf("encode comment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+installationToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post comment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("post comment: %s: %s", resp.Status, string(responseBody))
	}
	return nil
}
