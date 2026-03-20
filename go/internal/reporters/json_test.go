package reporters

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func sampleFindings() []models.Finding {
	return []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Severity: models.SeverityMedium, Source: models.SourceBlackbox, Category: "headers", Endpoint: "GET /api/users", Confidence: models.ConfidenceHigh, References: []string{"CWE-319"}},
		{ID: "SEC-002", Title: "CORS wildcard", Severity: models.SeverityCritical, Source: models.SourceBlackbox, Category: "cors", Endpoint: "GET /api/data", Confidence: models.ConfidenceHigh, References: []string{"CWE-942"}},
		{ID: "SEC-003", Title: "No rate limiting", Severity: models.SeverityMedium, Source: models.SourceBlackbox, Category: "headers", Endpoint: "POST /api/login", Confidence: models.ConfidenceMedium, References: []string{"CWE-770"}},
		{ID: "SEC-004", Title: "Server version", Severity: models.SeverityInfo, Source: models.SourceBlackbox, Category: "headers", Endpoint: "GET /api/health", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
		{ID: "SEC-005", Title: "Password in response", Severity: models.SeverityCritical, Source: models.SourceBlackbox, Category: "data_exposure", Endpoint: "GET /api/users/1", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
		{ID: "SEC-006", Title: "Internal IP", Severity: models.SeverityLow, Source: models.SourceBlackbox, Category: "data_exposure", Endpoint: "GET /api/debug", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
		{ID: "SEC-007", Title: "Token exposed", Severity: models.SeverityHigh, Source: models.SourceBlackbox, Category: "data_exposure", Endpoint: "POST /api/auth", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
	}
}

func TestRenderJSON_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "dev",
	}

	err := RenderJSON(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if report.Total != 7 {
		t.Errorf("expected total 7, got %d", report.Total)
	}
	if report.Summary.Critical != 2 {
		t.Errorf("expected 2 critical, got %d", report.Summary.Critical)
	}
	if report.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", report.Summary.High)
	}
	if report.Summary.Medium != 2 {
		t.Errorf("expected 2 medium, got %d", report.Summary.Medium)
	}
	if report.Summary.Low != 1 {
		t.Errorf("expected 1 low, got %d", report.Summary.Low)
	}
	if report.Summary.Info != 1 {
		t.Errorf("expected 1 info, got %d", report.Summary.Info)
	}
	if report.Metadata.Target != "https://api.example.com" {
		t.Errorf("unexpected target: %s", report.Metadata.Target)
	}
}

func TestRenderJSON_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderJSON(&buf, nil, meta)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if report.Total != 0 {
		t.Errorf("expected total 0, got %d", report.Total)
	}
}

func TestRenderJSON_PrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderJSON(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	output := buf.String()
	if len(output) < 50 {
		t.Fatal("output too short to be pretty-printed")
	}
	if output[0] != '{' {
		t.Error("expected JSON object output")
	}
}

func TestCountSeverities(t *testing.T) {
	findings := sampleFindings()
	counts := CountSeverities(findings)

	if counts.Critical != 2 || counts.High != 1 || counts.Medium != 2 || counts.Low != 1 || counts.Info != 1 {
		t.Errorf("unexpected counts: %+v", counts)
	}
}

func TestCountSeverities_Empty(t *testing.T) {
	counts := CountSeverities(nil)
	if counts.Critical != 0 || counts.High != 0 || counts.Medium != 0 || counts.Low != 0 || counts.Info != 0 {
		t.Errorf("expected all zeros, got %+v", counts)
	}
}
