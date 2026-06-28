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
	"sort"
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
	Total     int `json:"total"`
	Decisions struct {
		Total         int `json:"total"`
		Confirmed     int `json:"confirmed"`
		Blocking      int `json:"blocking"`
		Warning       int `json:"warning"`
		Informational int `json:"informational"`
	} `json:"decisions"` // v0.24
	Findings []struct {
		Severity        string `json:"severity"`
		Title           string `json:"title"`
		Category        string `json:"category"`
		Endpoint        string `json:"endpoint"`
		Line            string `json:"line"`
		Status          string `json:"status"`           // v0.24
		ConfidenceScore int    `json:"confidence_score"` // v0.24
	} `json:"findings"`
}

// statusRank orders findings by decision verdict for the PR-comment top-N:
// BLOCK first (it fails the build), then WARN, then INFO, then anything
// unstamped. Lower is more urgent.
func statusRank(s string) int {
	switch s {
	case "BLOCK":
		return 0
	case "WARN":
		return 1
	case "INFO":
		return 2
	default:
		return 3
	}
}

// severityRank is the secondary triage key (within a decision band).
func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
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

	// v0.25 verdict banner — answer "can I merge?" at a glance, before any
	// table. Blocking is our own decision count, not attacker-controlled.
	switch {
	case r.Decisions.Blocking > 0:
		fmt.Fprintf(&b, "🔴 **%d blocking — this PR fails the Fendix gate.**\n\n", r.Decisions.Blocking)
	case total > 0:
		b.WriteString("🟢 **Gate passes — no blocking findings.**\n\n")
	}

	fmt.Fprintf(&b, "Mode: `%s` · Endpoints scanned: %d · Duration: %s\n\n",
		mode, r.Metadata.EndpointsScanned, duration)

	// v0.24 decision summary + the v0.25 collapsed counts matrix. The banner
	// and this line are the at-a-glance answer; the full severity/source table
	// is one click away for anyone who wants it (and skipped entirely when
	// there's nothing to count).
	if total > 0 {
		fmt.Fprintf(&b, "**Decisions:** %d blocking · %d warning · %d informational · %d high-confidence\n\n",
			r.Decisions.Blocking, r.Decisions.Warning, r.Decisions.Informational, r.Decisions.Confirmed)

		b.WriteString("<details><summary>Counts by severity &amp; source</summary>\n\n")
		b.WriteString("| Severity | Count | Source | Count |\n")
		b.WriteString("|---|---|---|---|\n")
		fmt.Fprintf(&b, "| Critical | %d | Blackbox | %d |\n", r.Summary.Critical, r.Sources.Blackbox)
		fmt.Fprintf(&b, "| High | %d | Whitebox | %d |\n", r.Summary.High, r.Sources.Whitebox)
		fmt.Fprintf(&b, "| Medium | %d | Correlated | %d |\n", r.Summary.Medium, r.Sources.Correlated)
		fmt.Fprintf(&b, "| Low | %d | _Total_ | **%d** |\n", r.Summary.Low, total)
		fmt.Fprintf(&b, "| Info | %d | | |\n", r.Summary.Info)
		b.WriteString("\n</details>\n\n")
	}

	if total == 0 {
		b.WriteString("_No new findings vs. baseline. ✅_\n\n")
	} else {
		b.WriteString("### Top findings\n")
		// v0.25: surface the build-failing findings first. Sort a COPY by
		// decision status (BLOCK>WARN>INFO) → severity → confidence so the
		// truncated top-5 is the most actionable set, not whatever sorts first
		// alphabetically by endpoint. The copy leaves the report's JSON order
		// (and SEC-NNN IDs) untouched.
		ranked := append(r.Findings[:0:0], r.Findings...)
		sort.SliceStable(ranked, func(i, j int) bool {
			if ri, rj := statusRank(ranked[i].Status), statusRank(ranked[j].Status); ri != rj {
				return ri < rj
			}
			if ri, rj := severityRank(ranked[i].Severity), severityRank(ranked[j].Severity); ri != rj {
				return ri < rj
			}
			return ranked[i].ConfidenceScore > ranked[j].ConfidenceScore
		})
		topN := len(ranked)
		if topN > 5 {
			topN = 5
		}
		for i := 0; i < topN; i++ {
			f := ranked[i]
			where := f.Endpoint
			if where == "" {
				where = f.Line
			}
			// F-L11: Title and endpoint are attacker-controlled (they
			// come from a fork PR's code/config). Escape Markdown
			// metacharacters in the title's text context and render the
			// location in a backtick-safe inline code span so a crafted
			// title can't inject Markdown, break out of the inline code,
			// or spoof a fake finding/heading.
			// v0.24: lead with the decision verdict + show the confidence
			// score. Status/score come from our own scanner JSON (a fixed
			// enum / int), not attacker-controlled, so they're badge-safe.
			badge := ""
			if f.Status != "" {
				// inlineCode escapes defensively — RenderPRComment is exported
				// and accepts arbitrary JSON, so don't trust the raw status.
				badge = inlineCode(f.Status) + " "
			}
			score := ""
			if f.ConfidenceScore > 0 {
				score = fmt.Sprintf(" _(%d/100)_", f.ConfidenceScore)
			}
			fmt.Fprintf(&b, "- %s**[%s]** %s — %s%s\n",
				badge, escapeSeverity(f.Severity), escapeMarkdown(f.Title), inlineCode(where), score)
			// TASK-124: one-click suppression snippet. Keyed on
			// (endpoint, category) — the (title, category, endpoint)
			// hash in the trailing comment lets users map back to the
			// originating finding after they paste. The fence is built
			// with a guarded helper so neither endpoint nor category can
			// close the code block and inject content after it.
			fmt.Fprintf(&b, "%s\n",
				fencedYAML(suppressionSnippet(f.Title, f.Category, where)))
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

// markdownMeta is the set of GitHub-Flavored-Markdown metacharacters
// that, left unescaped in a text context, let attacker-controlled
// content (a fork PR's finding title) inject formatting, headings,
// links, or list items into the rendered comment (F-L11).
const markdownMeta = "\\`*_{}[]()#+-.!|<>~"

// escapeMarkdown renders untrusted text safe to drop into a Markdown
// text context. It backslash-escapes GFM metacharacters and collapses
// newlines to spaces so a crafted multi-line title can't break the list
// item it sits in or forge a new heading / finding line.
func escapeMarkdown(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if strings.ContainsRune(markdownMeta, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// escapeSeverity escapes a severity label for use inside the bold
// "**[...]**" prefix. Severity originates from our own scanner JSON,
// but escaping it defensively costs nothing and keeps the rendering
// path uniformly safe against a malformed/forged findings file.
func escapeSeverity(s string) string {
	return escapeMarkdown(s)
}

// inlineCode wraps untrusted text in a Markdown inline code span that
// cannot be broken out of, no matter how many backticks the text
// contains. Per the GFM spec, a code span delimited by a run of N
// backticks can contain any shorter run; we pick a delimiter one longer
// than the longest backtick run in s, and pad with spaces when the
// content begins or ends with a backtick (otherwise the delimiter would
// merge with the content). Newlines are collapsed so the span stays on
// one line.
func inlineCode(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	fence := strings.Repeat("`", longestBacktickRun(s)+1)
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") || s == "" {
		pad = " "
	}
	return fence + pad + s + pad + fence
}

// fencedYAML emits a fenced code block tagged `yaml` containing content,
// indented two spaces to nest under its list item (matching the
// existing layout). The fence length is chosen longer than any backtick
// run in content so attacker-controlled endpoint/category values inside
// the snippet cannot close the block early and inject Markdown after it
// (F-L11). Newlines in content are collapsed defensively — the
// suppression snippet is single-line by construction.
func fencedYAML(content string) string {
	content = strings.NewReplacer("\r", " ", "\n", " ").Replace(content)
	fenceLen := longestBacktickRun(content) + 1
	if fenceLen < 3 {
		fenceLen = 3
	}
	fence := strings.Repeat("`", fenceLen)
	return "  " + fence + "yaml\n  " + content + "\n  " + fence
}

// longestBacktickRun returns the length of the longest consecutive run
// of backtick characters in s (0 if none). Used to size code-span and
// code-fence delimiters so content can never close them prematurely.
func longestBacktickRun(s string) int {
	longest, cur := 0, 0
	for _, r := range s {
		if r == '`' {
			cur++
			if cur > longest {
				longest = cur
			}
		} else {
			cur = 0
		}
	}
	return longest
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
		// F-I2: the transport error can echo the request URL/headers in
		// some clients; redact the token to match scanner.go's handling
		// so a logged error never leaks the installation token.
		return fmt.Errorf("post comment: %s", redactToken(err.Error(), installationToken))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		// F-I2: GitHub error bodies can reflect request material; redact
		// the token from the embedded response body before surfacing it.
		return fmt.Errorf("post comment: %s: %s",
			resp.Status, redactToken(string(responseBody), installationToken))
	}
	return nil
}
