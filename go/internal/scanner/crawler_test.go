package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestFromSpec_OpenAPI3(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: https://api.example.com/v1
paths:
  /users:
    get:
      summary: List users
    post:
      summary: Create user
  /users/{id}:
    get:
      summary: Get user
    put:
      summary: Update user
    delete:
      summary: Delete user
  /health:
    get:
      summary: Health check
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if len(endpoints) != 6 {
		t.Fatalf("expected 6 endpoints, got %d", len(endpoints))
	}

	found := make(map[string]bool)
	for _, ep := range endpoints {
		found[ep.Method+" "+ep.Path] = true
	}

	expected := []string{
		"GET /users", "POST /users",
		"GET /users/{id}", "PUT /users/{id}", "DELETE /users/{id}",
		"GET /health",
	}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("missing endpoint: %s", e)
		}
	}
}

func TestFromSpec_Swagger2(t *testing.T) {
	spec := `
swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: api.example.com
basePath: /v1
schemes:
  - https
paths:
  /users:
    get:
      summary: List users
  /orders:
    post:
      summary: Create order
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "swagger.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}

	if endpoints[0].FullURL != "https://api.example.com/v1/users" && endpoints[1].FullURL != "https://api.example.com/v1/users" {
		t.Errorf("expected base URL from swagger host+basePath, got %s and %s", endpoints[0].FullURL, endpoints[1].FullURL)
	}
}

func TestFromSpec_JSON(t *testing.T) {
	spec := map[string]interface{}{
		"openapi": "3.0.0",
		"info":    map[string]interface{}{"title": "JSON API", "version": "1.0"},
		"paths": map[string]interface{}{
			"/items": map[string]interface{}{
				"get":  map[string]interface{}{"summary": "list"},
				"post": map[string]interface{}{"summary": "create"},
			},
		},
	}
	data, _ := json.Marshal(spec)
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.json")
	if err := os.WriteFile(specPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}
}

func TestFromSpec_URLOverridesServerURL(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: https://api.example.com
paths:
  /test:
    get:
      summary: test
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		URL:      "https://custom.example.com",
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if endpoints[0].FullURL != "https://custom.example.com/test" {
		t.Errorf("expected --url to override spec server, got %s", endpoints[0].FullURL)
	}
}

func TestFromJS(t *testing.T) {
	jsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `var BASE="/api/v1"; fetch("/api/v1/users"); fetch("/api/v2/orders");`)
	}))
	defer jsServer.Close()

	htmlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><script src="%s/app.js"></script></html>`, jsServer.URL)
	}))
	defer htmlServer.Close()

	crawler := NewCrawler(&models.ScanConfig{
		URL:     htmlServer.URL,
		Timeout: 10,
	})

	endpoints, err := crawler.fromJS(context.Background())
	if err != nil {
		t.Fatalf("fromJS failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatal("expected at least one endpoint from JS discovery")
	}

	found := false
	for _, ep := range endpoints {
		if ep.Path == "/api/v1/users" || ep.Path == "/api/v2/orders" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find /api/v1/users or /api/v2/orders in JS-discovered endpoints")
	}
}

func TestFromBruteForce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/users", "/health", "/api/health":
			w.WriteHeader(200)
			fmt.Fprint(w, `{"status":"ok"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	crawler := NewCrawler(&models.ScanConfig{
		URL:     server.URL,
		Timeout: 10,
		DelayMs: 0,
	})

	endpoints, err := crawler.fromBruteForce(context.Background())
	if err != nil {
		t.Fatalf("fromBruteForce failed: %v", err)
	}

	if len(endpoints) < 3 {
		t.Fatalf("expected at least 3 discovered endpoints, got %d", len(endpoints))
	}

	found := make(map[string]bool)
	for _, ep := range endpoints {
		found[ep.Path] = true
	}

	for _, path := range []string{"/api/v1/users", "/health", "/api/health"} {
		if !found[path] {
			t.Errorf("missing discovered endpoint: %s", path)
		}
	}
}

func TestCrawlEndpoints_Dedup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /health:
    get:
      summary: health
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		URL:      server.URL,
		SpecPath: specPath,
		Timeout:  10,
		DelayMs:  0,
	})

	endpoints, err := crawler.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatalf("CrawlEndpoints failed: %v", err)
	}

	healthCount := 0
	for _, ep := range endpoints {
		if ep.Path == "/health" && ep.Method == "GET" {
			healthCount++
		}
	}
	if healthCount != 1 {
		t.Errorf("expected /health GET to appear exactly once, found %d times", healthCount)
	}
}

func TestCrawlEndpoints_Sorted(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
paths:
  /zebra:
    get:
      summary: z
  /alpha:
    get:
      summary: a
    post:
      summary: a
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatalf("CrawlEndpoints failed: %v", err)
	}

	if len(endpoints) < 3 {
		t.Fatalf("expected at least 3 endpoints, got %d", len(endpoints))
	}

	for i := 1; i < len(endpoints); i++ {
		if endpoints[i].Path < endpoints[i-1].Path {
			t.Errorf("endpoints not sorted: %s before %s", endpoints[i-1].Path, endpoints[i].Path)
		}
	}
}

func TestExtractPathParams(t *testing.T) {
	tests := []struct {
		path   string
		params []string
	}{
		{"/users/{id}", []string{"id"}},
		{"/orgs/{org}/repos/{repo}", []string{"org", "repo"}},
		{"/health", nil},
		{"/users/{userId}/posts/{postId}", []string{"userId", "postId"}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			params := extractPathParams(tt.path)
			if len(params) != len(tt.params) {
				t.Fatalf("expected %d params, got %d", len(tt.params), len(params))
			}
			for i, p := range params {
				if p != tt.params[i] {
					t.Errorf("param[%d] = %s, want %s", i, p, tt.params[i])
				}
			}
		})
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		base     string
		ref      string
		expected string
	}{
		{"https://example.com", "https://cdn.example.com/app.js", "https://cdn.example.com/app.js"},
		{"https://example.com/page", "/static/app.js", "https://example.com/static/app.js"},
		{"https://example.com/sub/page", "app.js", "https://example.com/sub/app.js"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			result := resolveURL(tt.base, tt.ref)
			if result != tt.expected {
				t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.base, tt.ref, result, tt.expected)
			}
		})
	}
}

func TestFromSpec_InvalidFile(t *testing.T) {
	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: "/nonexistent/file.yaml",
		Timeout:  10,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// TestFromSpec_PopulatesParamsFromOperation is the regression test for TASK-081.
// Pre-fix, only URL-template path params (`{id}`) populated Endpoint.Params;
// the OpenAPI `parameters: [{name, in: query}]` block was dropped. This made
// the active scanner blind to non-`id` query parameters — every probe used
// the hardcoded "id" fallback in injection.go.
func TestFromSpec_PopulatesParamsFromOperation(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
servers: [{url: "https://api.example.com"}]
paths:
  /widgets:
    get:
      parameters:
        - name: limit
          in: query
        - name: offset
          in: query
        - name: X-Trace-Id
          in: header
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].Params
	want := map[string]bool{"limit": true, "offset": true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected param %q in %v (header param leaked through?)", p, got)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing params %v from %v", want, endpoints[0].Params)
	}
}

// TestFromSpec_PathLevelParamsMergeWithOperation: path-level `parameters` apply
// to every operation under that path. Plus URL-template params should always
// appear regardless of whether the spec lists them. Dedupe across all sources.
func TestFromSpec_PathLevelParamsMergeWithOperation(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
      - name: tenant
        in: query
    get:
      parameters:
        - name: include
          in: query
    delete: {}
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}

	getParams, deleteParams := map[string]bool{}, map[string]bool{}
	for _, ep := range endpoints {
		set := getParams
		if ep.Method == "DELETE" {
			set = deleteParams
		}
		for _, p := range ep.Params {
			set[p] = true
		}
	}

	// GET should have id (path template + spec path-level), tenant (path-level), include (operation-level)
	for _, want := range []string{"id", "tenant", "include"} {
		if !getParams[want] {
			t.Errorf("GET missing param %q (got %v)", want, getParams)
		}
	}
	// DELETE has no operation-level parameters but inherits path-level + URL template
	for _, want := range []string{"id", "tenant"} {
		if !deleteParams[want] {
			t.Errorf("DELETE missing inherited param %q (got %v)", want, deleteParams)
		}
	}
	if deleteParams["include"] {
		t.Errorf("DELETE should not inherit GET-only param 'include' (got %v)", deleteParams)
	}
}

// TestFromSpec_RefParameterSkipped verifies $ref entries don't crash the parser.
// Resolving them is out of scope for v0.2 (TASK-086); for now we just skip.
func TestFromSpec_RefParameterSkipped(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /things:
    get:
      parameters:
        - $ref: "#/components/parameters/Limit"
        - name: cursor
          in: query
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 || len(endpoints[0].Params) != 1 || endpoints[0].Params[0] != "cursor" {
		t.Fatalf("expected single endpoint with [cursor], got %+v", endpoints)
	}
}

// TestFromSpec_URL_JSON exercises TASK-082: --spec accepts an HTTP URL.
// Before the fix, a URL was passed to os.ReadFile and silently failed;
// the crawler then fell back to brute-force discovery.
func TestFromSpec_URL_JSON(t *testing.T) {
	specBody := `{
	  "openapi": "3.0.0",
	  "info": {"title": "Remote", "version": "1.0"},
	  "servers": [{"url": "https://api.remote.example/v1"}],
	  "paths": {
	    "/widgets": {"get": {"summary": "List"}, "post": {"summary": "Create"}},
	    "/widgets/{id}": {"get": {"summary": "Get"}}
	  }
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(specBody))
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: srv.URL + "/openapi.json",
		Timeout:  5,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}
	if len(endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d: %+v", len(endpoints), endpoints)
	}
}

// TestFromSpec_URL_YAML covers Content-Type-based format detection (URL has
// no .yaml suffix, server returns text/yaml — must still parse as YAML).
func TestFromSpec_URL_YAML(t *testing.T) {
	specBody := `openapi: "3.0.0"
info:
  title: Remote YAML
  version: "1.0"
servers:
  - url: https://api.remote.example/v1
paths:
  /things:
    get:
      summary: List things
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(specBody))
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		// No suffix on the URL — exercises Content-Type fallback.
		SpecPath: srv.URL + "/spec",
		Timeout:  5,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
}

// TestFromSpec_URL_HTTPError surfaces 4xx/5xx as errors instead of silently
// falling back. The pre-fix bug masked URL typos as "no endpoints found".
func TestFromSpec_URL_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: srv.URL + "/missing.json",
		Timeout:  5,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 404 response, got nil")
	}
	if !contains(err.Error(), "404") {
		t.Errorf("expected error to mention status code, got: %v", err)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFromSpec_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(specPath, []byte(":::invalid:::yaml:::"), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// TestFromSpec_PopulatesHeaderParams covers TASK-086 — `in: header` params now
// land in Endpoint.Headers, with standard auth headers (Authorization, Cookie,
// X-Api-Key) filtered out so the active scanner doesn't scribble payloads into
// real auth values.
func TestFromSpec_PopulatesHeaderParams(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /widgets:
    get:
      parameters:
        - name: X-Trace-Id
          in: header
        - name: X-Tenant-Id
          in: header
        - name: Authorization
          in: header
        - name: Cookie
          in: header
        - name: limit
          in: query
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].Headers
	wantSet := map[string]bool{"X-Trace-Id": true, "X-Tenant-Id": true}
	for _, h := range got {
		if !wantSet[h] {
			t.Errorf("unexpected header %q (auth headers should be skipped); got Headers=%v", h, got)
		}
		delete(wantSet, h)
	}
	if len(wantSet) != 0 {
		t.Errorf("missing headers %v from %v", wantSet, got)
	}
	// Query param still flows through Params, not Headers.
	if len(endpoints[0].Params) != 1 || endpoints[0].Params[0] != "limit" {
		t.Errorf("expected Params=[limit], got %v", endpoints[0].Params)
	}
}

// TestFromSpec_PopulatesBodyParams_OAS3 covers TASK-086 — OpenAPI 3 JSON
// requestBody schemas surface their property names in Endpoint.BodyParams so
// the active scanner can probe POST/PUT/PATCH body fields.
func TestFromSpec_PopulatesBodyParams_OAS3(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /users:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                email:
                  type: string
                age:
                  type: integer
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].BodyParams
	want := map[string]bool{"username": true, "email": true, "age": true}
	for _, b := range got {
		if !want[b] {
			t.Errorf("unexpected body param %q in %v", b, got)
		}
		delete(want, b)
	}
	if len(want) != 0 {
		t.Errorf("missing body params %v from %v", want, got)
	}
}

// TestFromSpec_PopulatesBodyParams_Swagger2 covers Swagger 2.0 bodies, which
// live in `parameters` with `in: body` rather than the OAS 3 `requestBody`.
func TestFromSpec_PopulatesBodyParams_Swagger2(t *testing.T) {
	spec := `
swagger: "2.0"
info: {title: t, version: "1"}
host: api.example.com
basePath: /v1
paths:
  /users:
    post:
      parameters:
        - name: body
          in: body
          schema:
            type: object
            properties:
              username:
                type: string
              password:
                type: string
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "swagger.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].BodyParams
	want := map[string]bool{"username": true, "password": true}
	for _, b := range got {
		if !want[b] {
			t.Errorf("unexpected body param %q in %v", b, got)
		}
		delete(want, b)
	}
	if len(want) != 0 {
		t.Errorf("missing body params %v from %v", want, got)
	}
}

// TestFromSpec_BodyParams_RefSchemaSkipped — schemas with $ref are not
// dereferenced in v0.3, so they yield no body params (rather than crashing).
func TestFromSpec_BodyParams_RefSchemaSkipped(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/User"
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if len(endpoints[0].BodyParams) != 0 {
		t.Errorf("expected no body params for $ref schema, got %v", endpoints[0].BodyParams)
	}
}

func TestFromSpec_NoPaths(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(specPath, []byte("openapi: '3.0.0'\ninfo:\n  title: empty\n  version: '1.0'\n"), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for spec with no paths")
	}
}

func TestCrawlEndpoints_SpecOnly(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
paths:
  /users:
    get:
      summary: List
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatalf("CrawlEndpoints failed: %v", err)
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint from spec-only crawl, got %d", len(endpoints))
	}
	if endpoints[0].Method != "GET" || endpoints[0].Path != "/users" {
		t.Errorf("unexpected endpoint: %s %s", endpoints[0].Method, endpoints[0].Path)
	}
}
