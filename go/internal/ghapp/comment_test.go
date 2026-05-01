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
