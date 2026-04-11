package reporters

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestRenderHTML_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "dev",
		Mode:      "blackbox",
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

func TestRenderHTML_ContainsSortButtons(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "sortFindings") {
		t.Error("missing sortFindings JavaScript function")
	}
	if !strings.Contains(html, `sortFindings('severity'`) {
		t.Error("missing severity sort button")
	}
	if !strings.Contains(html, `sortFindings('endpoint'`) {
		t.Error("missing endpoint sort button")
	}
	if !strings.Contains(html, `sortFindings('source'`) {
		t.Error("missing source sort button")
	}
}

func TestRenderHTML_ContainsExpandCollapseButtons(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "toggleAll") {
		t.Error("missing toggleAll JavaScript function")
	}
	if !strings.Contains(html, "Expand All") {
		t.Error("missing Expand All button")
	}
	if !strings.Contains(html, "Collapse All") {
		t.Error("missing Collapse All button")
	}
}

func TestRenderHTML_ContainsSeverityDataAttributes(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	findings := []models.Finding{
		{ID: "SEC-001", Title: "Critical Issue", Severity: models.SeverityCritical, Source: models.SourceBlackbox, References: []string{}},
		{ID: "SEC-002", Title: "Low Issue", Severity: models.SeverityLow, Source: models.SourceWhitebox, References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, `data-severity="4"`) {
		t.Error("missing severity rank data attribute for CRITICAL (4)")
	}
	if !strings.Contains(html, `data-severity="1"`) {
		t.Error("missing severity rank data attribute for LOW (1)")
	}
	if !strings.Contains(html, `data-source="blackbox"`) {
		t.Error("missing source data attribute")
	}
}

func TestRenderHTML_PrintCSS(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "@media print") {
		t.Error("missing print media query")
	}
	if !strings.Contains(html, "display:block !important") {
		t.Error("print CSS should force finding bodies to display:block")
	}
	if !strings.Contains(html, ".toolbar{display:none}") {
		t.Error("print CSS should hide toolbar")
	}
}

func TestRenderHTML_ContainsMode(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "hybrid"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "hybrid scan") {
		t.Error("missing scan mode in subtitle")
	}
	if !strings.Contains(html, "Mode: hybrid") {
		t.Error("missing mode in metadata footer")
	}
}

func TestRenderHTML_ContainsFindingID(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test Finding", Severity: models.SeverityHigh, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	if !strings.Contains(buf.String(), "SEC-001") {
		t.Error("expected finding ID in HTML output")
	}
}

func TestRenderHTML_ContainsCategory(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test", Severity: models.SeverityHigh, Source: models.SourceBlackbox, Category: "injection", References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	if !strings.Contains(buf.String(), "injection") {
		t.Error("expected category in finding body")
	}
}
