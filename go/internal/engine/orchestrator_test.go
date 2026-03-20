package engine

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
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// newVulnerableServer creates a mock API server with deliberate security issues
// for integration testing the full scan pipeline.
func newVulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		// Missing security headers, password in response, no rate limiting
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Server", "nginx/1.21.3")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"id":1,"username":"admin","password":"hunter2","email":"admin@test.com"}]`)
	})

	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		// Wildcard CORS with credentials
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api_key":"sk-live-1234567890abcdef","debug":true}`)
	})

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		// Properly secured endpoint
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/api/v1/debug", func(w http.ResponseWriter, r *http.Request) {
		// Stack trace and internal IP
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"Traceback (most recent call last):\n  File \"app.py\"","server":"10.0.1.42"}`)
	})

	return httptest.NewServer(mux)
}

func TestOrchestrator_IntegrationScan(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: List users
  /api/v1/config:
    get:
      summary: Get config
  /api/v1/health:
    get:
      summary: Health check
  /api/v1/debug:
    get:
      summary: Debug info
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	outputPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &models.ScanConfig{
		URL:        server.URL,
		SpecPath:   specPath,
		Workers:    2,
		Timeout:    10,
		DelayMs:    0,
		Format:     "json",
		OutputPath: outputPath,
	}

	orch := NewOrchestrator(cfg)
	exitCode := orch.Run(context.Background())
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// Read and parse output
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}

	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parsing report: %v", err)
	}

	// Verify findings exist
	if report.Total == 0 {
		t.Fatal("expected findings from vulnerable server, got 0")
	}

	// Check for expected finding types
	findingTitles := make(map[string]bool)
	for _, f := range report.Findings {
		findingTitles[f.Title] = true
	}

	expectedFindings := []string{
		"Password exposed in API response",
		"X-Powered-By header discloses technology",
		"Server version disclosed in header",
	}
	for _, title := range expectedFindings {
		if !findingTitles[title] {
			t.Errorf("missing expected finding: %s", title)
		}
	}

	// Verify sequential IDs
	for i, f := range report.Findings {
		expectedID := fmt.Sprintf("SEC-%03d", i+1)
		if f.ID != expectedID {
			t.Errorf("finding %d: expected ID %s, got %s", i, expectedID, f.ID)
		}
	}

	// Verify metadata
	if report.Metadata.Target != server.URL {
		t.Errorf("unexpected target: %s", report.Metadata.Target)
	}
}

func TestOrchestrator_HTMLOutput(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: test
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	outputPath := filepath.Join(dir, "report.html")
	os.WriteFile(specPath, []byte(spec), 0644)

	cfg := &models.ScanConfig{
		URL:        server.URL,
		SpecPath:   specPath,
		Workers:    2,
		Timeout:    10,
		DelayMs:    0,
		Format:     "html",
		OutputPath: outputPath,
	}

	orch := NewOrchestrator(cfg)
	exitCode := orch.Run(context.Background())
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading HTML report: %v", err)
	}

	html := string(data)
	if len(html) < 100 {
		t.Fatal("HTML report too short")
	}
}

func TestOrchestrator_FailOnThreshold(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: test
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	os.WriteFile(specPath, []byte(spec), 0644)

	cfg := &models.ScanConfig{
		URL:        server.URL,
		SpecPath:   specPath,
		Workers:    2,
		Timeout:    10,
		DelayMs:    0,
		Format:     "json",
		OutputPath: filepath.Join(dir, "report.json"),
		FailOn:     "CRITICAL",
	}

	orch := NewOrchestrator(cfg)
	exitCode := orch.Run(context.Background())
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for --fail-on CRITICAL (password in response), got %d", exitCode)
	}
}

func TestOrchestrator_NoEndpoints(t *testing.T) {
	cfg := &models.ScanConfig{
		Timeout: 10,
		Workers: 1,
	}

	orch := NewOrchestrator(cfg)
	exitCode := orch.Run(context.Background())
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for no endpoints, got %d", exitCode)
	}
}
