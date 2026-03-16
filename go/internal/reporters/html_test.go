package reporters

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/fendix/fendix/internal/models"
)

func TestRenderHTML_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "dev",
	}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE declaration")
	}
	if !strings.Contains(html, "Fendix Security Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(html, "api.example.com") {
		t.Error("missing target URL")
	}
}

func TestRenderHTML_ContainsSeverityCounts(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()

	checks := []string{
		`<div class="stat critical">`,
		`<div class="stat high">`,
		`<div class="stat medium">`,
		`<div class="stat low">`,
		`<div class="stat info">`,
	}
	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Errorf("missing severity stat: %s", check)
		}
	}
}

func TestRenderHTML_ContainsFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	findings := sampleFindings()
	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	for _, f := range findings {
		if !strings.Contains(html, f.Title) {
			t.Errorf("missing finding title in HTML: %s", f.Title)
		}
	}
}

func TestRenderHTML_SelfContained(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()

	if strings.Contains(html, `<link rel="stylesheet"`) {
		t.Error("HTML report should not have external CSS links")
	}
	if strings.Contains(html, `<script src=`) {
		t.Error("HTML report should not have external JS scripts")
	}
	if !strings.Contains(html, "<style>") {
		t.Error("HTML report should contain inline CSS")
	}
}

func TestRenderHTML_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderHTML(&buf, nil, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "Total findings: 0") {
		t.Error("expected total findings to be 0")
	}
}

func TestRenderHTML_SeverityBadges(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev"}

	findings := []models.Finding{
		{ID: "SEC-001", Title: "Critical Issue", Severity: models.SeverityCritical, Source: models.SourceBlackbox, References: []string{"CWE-1"}},
		{ID: "SEC-002", Title: "Low Issue", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{"CWE-2"}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, `class="badge CRITICAL"`) {
		t.Error("missing CRITICAL badge class")
	}
	if !strings.Contains(html, `class="badge LOW"`) {
		t.Error("missing LOW badge class")
	}
}

func TestRenderHTML_WithLineField(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev"}
	line := "src/app.py:42"
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Secret found", Severity: models.SeverityHigh, Source: models.SourceWhitebox, Line: &line, References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	if !strings.Contains(buf.String(), "src/app.py:42") {
		t.Error("expected line reference in HTML output")
	}
}
