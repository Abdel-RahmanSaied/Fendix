package ghapp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderPRComment_NoFindings(t *testing.T) {
	body, err := RenderPRComment([]byte(`{
		"metadata":{"mode":"hybrid","endpoints_scanned":12,"duration":"3.4s"},
		"summary":{"critical":0,"high":0,"medium":0,"low":0,"info":0},
		"sources":{"blackbox":0,"whitebox":0,"correlated":0},
		"total":0,
		"findings":[]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}
	if !strings.Contains(body, "Fendix scan: 0 findings") {
		t.Errorf("expected zero-finding heading, got: %s", body)
	}
	if !strings.Contains(body, "_No new findings vs. baseline. ✅_") {
		t.Errorf("expected no-findings checkmark, got: %s", body)
	}
	if !strings.Contains(body, "Mode: `hybrid`") {
		t.Errorf("expected mode=hybrid, got: %s", body)
	}
	if !strings.Contains(body, "Duration: 3.4s") {
		t.Errorf("expected duration=3.4s, got: %s", body)
	}
	if strings.Contains(body, "### Top findings") {
		t.Errorf("should not list top findings on empty scan, got: %s", body)
	}
}

func TestRenderPRComment_WithFindings(t *testing.T) {
	body, err := RenderPRComment([]byte(`{
		"metadata":{"mode":"hybrid","endpoints_scanned":4,"duration":"2.0s"},
		"summary":{"critical":1,"high":2,"medium":0,"low":0,"info":0},
		"sources":{"blackbox":1,"whitebox":2,"correlated":0},
		"total":3,
		"findings":[
			{"severity":"CRITICAL","title":"Hardcoded API key","endpoint":"src/config.py:14","line":"src/config.py:14"},
			{"severity":"HIGH","title":"Missing auth on /admin","endpoint":"GET /admin","line":""},
			{"severity":"HIGH","title":"Time-based SQLi","endpoint":"GET /search","line":""}
		]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}
	if !strings.Contains(body, "Fendix scan: 3 findings") {
		t.Errorf("expected count=3 heading: %s", body)
	}
	if !strings.Contains(body, "**[CRITICAL]** Hardcoded API key — `src/config.py:14`") {
		t.Errorf("expected first finding entry: %s", body)
	}
	if !strings.Contains(body, "Critical | 1") {
		t.Errorf("expected critical=1 in table: %s", body)
	}
	if !strings.Contains(body, "Whitebox | 2") {
		t.Errorf("expected whitebox=2 in table: %s", body)
	}
	if strings.Contains(body, "and 0 more") || strings.Contains(body, "and -") {
		t.Errorf("should not show 'and N more' below threshold: %s", body)
	}
}

func TestRenderPRComment_TruncatesAtFive(t *testing.T) {
	body, err := RenderPRComment([]byte(`{
		"metadata":{"mode":"blackbox","endpoints_scanned":7,"duration":"1s"},
		"summary":{"critical":0,"high":7,"medium":0,"low":0,"info":0},
		"sources":{"blackbox":7,"whitebox":0,"correlated":0},
		"total":7,
		"findings":[
			{"severity":"HIGH","title":"f1","endpoint":"e1"},
			{"severity":"HIGH","title":"f2","endpoint":"e2"},
			{"severity":"HIGH","title":"f3","endpoint":"e3"},
			{"severity":"HIGH","title":"f4","endpoint":"e4"},
			{"severity":"HIGH","title":"f5","endpoint":"e5"},
			{"severity":"HIGH","title":"f6","endpoint":"e6"},
			{"severity":"HIGH","title":"f7","endpoint":"e7"}
		]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}
	if !strings.Contains(body, "f5") {
		t.Errorf("expected f5 in top 5: %s", body)
	}
	if strings.Contains(body, "f6") {
		t.Errorf("did not expect f6 (>5): %s", body)
	}
	if !strings.Contains(body, "_…and 2 more in the SARIF report._") {
		t.Errorf("expected 'and 2 more' overflow line: %s", body)
	}
}

// TASK-124: every top finding gets a one-click suppression snippet.
func TestRenderPRComment_SuppressionSnippetPerFinding(t *testing.T) {
	body, err := RenderPRComment([]byte(`{
		"metadata":{"mode":"blackbox","endpoints_scanned":2,"duration":"1s"},
		"summary":{"critical":0,"high":0,"medium":2,"low":0,"info":0},
		"sources":{"blackbox":2,"whitebox":0,"correlated":0},
		"total":2,
		"findings":[
			{"severity":"MEDIUM","title":"Missing CSP header","category":"headers","endpoint":"GET /.env.local"},
			{"severity":"MEDIUM","title":"CORS allows any origin","category":"cors","endpoint":"GET /.env.local"}
		]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}

	// Each finding's snippet is a fenced yaml block with the
	// (endpoint, category) tuple and a fp-<hash> comment.
	expected := []string{
		`endpoint: "GET /.env.local", category: "headers"`,
		`endpoint: "GET /.env.local", category: "cors"`,
		"# fp-",
		"```yaml",
	}
	for _, want := range expected {
		if !strings.Contains(body, want) {
			t.Errorf("snippet missing %q in body:\n%s", want, body)
		}
	}

	// Two findings → two snippets → two yaml fences (the body also
	// has a fp-<hash> reference in the trailing prose explaining the
	// feature, so we count the fence opener instead).
	if got := strings.Count(body, "```yaml"); got != 2 {
		t.Errorf("expected 2 ```yaml fences, got %d", got)
	}
	// Same fields but different category should produce different
	// hashes — locks in that the hash actually keys on all three
	// inputs, not just the endpoint.
	h1 := findingHash("Missing CSP header", "headers", "GET /.env.local")
	h2 := findingHash("CORS allows any origin", "cors", "GET /.env.local")
	if h1 == h2 {
		t.Errorf("hashes should differ for different (title,category) pairs, both = %s", h1)
	}
}

func TestRenderPRComment_NoSnippetWhenZeroFindings(t *testing.T) {
	// The snippet is only useful next to a finding; the no-findings
	// case shouldn't render a stray hint about copying YAML.
	body, err := RenderPRComment([]byte(`{
		"metadata":{"mode":"blackbox","endpoints_scanned":4,"duration":"0.5s"},
		"summary":{"critical":0,"high":0,"medium":0,"low":0,"info":0},
		"sources":{"blackbox":0,"whitebox":0,"correlated":0},
		"total":0,
		"findings":[]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}
	if strings.Contains(body, "```yaml") {
		t.Errorf("zero-findings body should not contain yaml snippet: %s", body)
	}
	if strings.Contains(body, "Copy a `yaml` block") {
		t.Errorf("zero-findings body should not advertise the snippet feature: %s", body)
	}
}

func TestSuppressionSnippet_StableAcrossRuns(t *testing.T) {
	// The hash must be deterministic — a developer who pastes the
	// fp-abc12345 from one PR should be able to find it later by
	// grep, even if SEC-NNN ids reshuffle.
	a := suppressionSnippet("Missing CSP header", "headers", "GET /api/v1/users")
	b := suppressionSnippet("Missing CSP header", "headers", "GET /api/v1/users")
	if a != b {
		t.Errorf("snippet should be deterministic:\n  %s\n  %s", a, b)
	}
}

func TestSuppressionSnippet_HandlesMissingFields(t *testing.T) {
	// Defensive: if category or endpoint are empty in the JSON, the
	// snippet should still parse as valid YAML.
	s := suppressionSnippet("orphan title", "", "")
	if !strings.Contains(s, `category: "unknown"`) {
		t.Errorf("empty category should fall back to 'unknown', got: %s", s)
	}
	if !strings.Contains(s, `endpoint: "*"`) {
		t.Errorf("empty endpoint should fall back to '*', got: %s", s)
	}
}

func TestFindingHash_Length(t *testing.T) {
	// 8 hex chars (4 bytes) — enough to disambiguate within a single
	// repo's finding set. Larger would clutter the comment.
	h := findingHash("t", "c", "e")
	if len(h) != 8 {
		t.Errorf("expected 8-char hash, got %d (%q)", len(h), h)
	}
}

func TestRenderPRComment_MalformedJSON(t *testing.T) {
	_, err := RenderPRComment([]byte("{not json"))
	if err == nil {
		t.Fatal("expected parse error on malformed JSON")
	}
}

func TestPostPRComment_Success(t *testing.T) {
	var captured struct {
		Auth        string
		Accept      string
		APIVersion  string
		ContentType string
		Path        string
		Body        struct {
			Body string `json:"body"`
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Auth = r.Header.Get("Authorization")
		captured.Accept = r.Header.Get("Accept")
		captured.APIVersion = r.Header.Get("X-GitHub-Api-Version")
		captured.ContentType = r.Header.Get("Content-Type")
		captured.Path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":1}`)
	}))
	defer srv.Close()

	err := PostPRComment(context.Background(), srv.Client(), srv.URL,
		"ghs_token", "octocat", "hello-world", 42, "## Fendix scan: 0 findings")
	if err != nil {
		t.Fatalf("PostPRComment: %v", err)
	}
	if captured.Auth != "Bearer ghs_token" {
		t.Errorf("auth header: %q", captured.Auth)
	}
	if captured.Accept != "application/vnd.github+json" {
		t.Errorf("accept header: %q", captured.Accept)
	}
	if captured.APIVersion != "2022-11-28" {
		t.Errorf("api version: %q", captured.APIVersion)
	}
	if captured.ContentType != "application/json" {
		t.Errorf("content-type: %q", captured.ContentType)
	}
	if captured.Path != "/repos/octocat/hello-world/issues/42/comments" {
		t.Errorf("path: %q", captured.Path)
	}
	if !strings.HasPrefix(captured.Body.Body, "## Fendix scan: 0 findings") {
		t.Errorf("body: %q", captured.Body.Body)
	}
}

func TestPostPRComment_Non201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"resource not accessible"}`)
	}))
	defer srv.Close()

	err := PostPRComment(context.Background(), srv.Client(), srv.URL,
		"tok", "o", "r", 1, "x")
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 in err: %v", err)
	}
	if !strings.Contains(err.Error(), "resource not accessible") {
		t.Errorf("expected response body in err: %v", err)
	}
}

// F-I2: an error built from a GitHub response body must not echo the
// installation token even if GitHub reflects it back. (GitHub doesn't
// normally do this, but scanner.go redacts defensively and comment.go
// must be consistent.)
func TestPostPRComment_RedactsTokenInError(t *testing.T) {
	const token = "ghs_should_not_leak"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// Reflect the bearer token back in the body to simulate a
		// misbehaving proxy / verbose error.
		_, _ = io.WriteString(w, `{"message":"bad credentials: `+token+`"}`)
	}))
	defer srv.Close()

	err := PostPRComment(context.Background(), srv.Client(), srv.URL,
		token, "o", "r", 1, "x")
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaked the installation token: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("expected redaction marker in error: %v", err)
	}
}

// F-L11: a crafted finding title must not break out of the rendered
// Markdown — no raw heading injection, no list-item forgery, no inline
// HTML/markup leaking through unescaped.
func TestRenderPRComment_MaliciousTitleNeutralized(t *testing.T) {
	body, err := RenderPRComment([]byte(`{
		"metadata":{"mode":"blackbox","endpoints_scanned":1,"duration":"1s"},
		"summary":{"critical":1,"high":0,"medium":0,"low":0,"info":0},
		"sources":{"blackbox":1,"whitebox":0,"correlated":0},
		"total":1,
		"findings":[
			{"severity":"CRITICAL","title":"pwn\n## Fake heading\n- **[CRITICAL]** spoofed finding","category":"x","endpoint":"GET /a"}
		]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}
	// The injected newline must be collapsed so the title can't forge a
	// second heading or a fake finding line of its own.
	if strings.Contains(body, "\n## Fake heading") {
		t.Errorf("title injected a raw heading:\n%s", body)
	}
	// The '#' that begins the fake heading must be backslash-escaped in
	// the title's text context.
	if !strings.Contains(body, `\#\# Fake heading`) {
		t.Errorf("heading metacharacters not escaped:\n%s", body)
	}
	// Exactly one genuine finding line — the spoofed one is neutralised
	// (escaped + on the same line), so the "- **[" finding prefix still
	// appears only once at the start of a line.
	if got := strings.Count(body, "\n- **["); got != 1 {
		t.Errorf("expected exactly one finding line, got %d:\n%s", got, body)
	}
}

// F-L11: a title containing a code fence must not close the suppression
// snippet's ```yaml block early and inject content after it.
func TestRenderPRComment_TitleCannotBreakCodeFence(t *testing.T) {
	body, err := RenderPRComment([]byte(`{
		"metadata":{"mode":"blackbox","endpoints_scanned":1,"duration":"1s"},
		"summary":{"critical":0,"high":0,"medium":1,"low":0,"info":0},
		"sources":{"blackbox":1,"whitebox":0,"correlated":0},
		"total":1,
		"findings":[
			{"severity":"MEDIUM","title":"x","category":"c","endpoint":"GET /a ` + "```" + ` echo pwned ` + "```" + `"}
		]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}
	// The yaml fence the renderer opens must be a longer backtick run
	// than anything inside the snippet, so the snippet's embedded ```
	// can't terminate it. Verify a >=4-backtick fence is used.
	if !strings.Contains(body, "````yaml") {
		t.Errorf("expected an escaped (>=4 backtick) yaml fence when content holds ```:\n%s", body)
	}
}

// F-L11: an endpoint full of backticks must render inside a code span
// that still closes correctly (the span delimiter is longer than any
// run inside it).
func TestInlineCode_BacktickSafe(t *testing.T) {
	got := inlineCode("a``b")
	// Longest internal run is 2, so the fence must be 3 backticks, with
	// space padding because the content doesn't start/end with a tick.
	if got != "```a``b```" {
		t.Errorf("inlineCode(a``b) = %q", got)
	}
	// Content that begins/ends with a backtick gets space padding.
	got = inlineCode("`x`")
	if got != "`` `x` ``" {
		t.Errorf("inlineCode(`+\"`x`\"+`) = %q", got)
	}
}

func TestEscapeMarkdown(t *testing.T) {
	in := "a*b_c`d[e](f)#g"
	got := escapeMarkdown(in)
	for _, meta := range []string{`\*`, `\_`, "\\`", `\[`, `\]`, `\(`, `\)`, `\#`} {
		if !strings.Contains(got, meta) {
			t.Errorf("escapeMarkdown(%q) missing %q: %q", in, meta, got)
		}
	}
}

// TestRenderPRComment_DecisionStatus covers the v0.24 PR-comment surfacing:
// a Decisions summary line + a per-finding status badge + confidence score.
func TestRenderPRComment_DecisionStatus(t *testing.T) {
	body, err := RenderPRComment([]byte(`{
		"metadata": {"mode": "whitebox", "endpoints_scanned": 0, "duration": "1s"},
		"summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
		"sources": {"blackbox": 0, "whitebox": 1, "correlated": 0},
		"total": 1,
		"decisions": {"total": 1, "confirmed": 1, "blocking": 1, "warning": 0, "informational": 0},
		"findings": [{"severity": "HIGH", "title": "SQLi", "category": "injection", "endpoint": "app.py:10", "line": "app.py:10", "status": "BLOCK", "confidence_score": 90}]
	}`))
	if err != nil {
		t.Fatalf("RenderPRComment: %v", err)
	}
	for _, want := range []string{"**Decisions:**", "1 blocking", "`BLOCK`", "(90/100)"} {
		if !strings.Contains(body, want) {
			t.Errorf("PR comment missing %q:\n%s", want, body)
		}
	}
}
