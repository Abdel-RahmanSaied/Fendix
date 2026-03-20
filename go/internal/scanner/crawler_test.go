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
