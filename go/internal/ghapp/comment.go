package ghapp

import (
	"bytes"
	"context"
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
		Endpoint string `json:"endpoint"`
		Line     string `json:"line"`
	} `json:"findings"`
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
		}
		if total > 5 {
			fmt.Fprintf(&b, "\n_…and %d more in the SARIF report._\n", total-5)
		}
		b.WriteString("\n")
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
