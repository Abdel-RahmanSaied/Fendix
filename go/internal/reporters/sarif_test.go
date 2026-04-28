package reporters

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestRenderSARIF_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "1.0.0",
		Mode:      "hybrid",
	}

	err := RenderSARIF(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
	if log.Schema == "" {
		t.Error("missing $schema")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "Fendix" {
		t.Errorf("expected tool name Fendix, got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.0.0" {
		t.Errorf("expected tool version 1.0.0, got %s", run.Tool.Driver.Version)
	}
	if len(run.Results) != 7 {
		t.Errorf("expected 7 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 7 {
		t.Errorf("expected 7 rules, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestRenderSARIF_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity models.Severity
		level    string
	}{
		{models.SeverityCritical, "error"},
		{models.SeverityHigh, "error"},
		{models.SeverityMedium, "warning"},
		{models.SeverityLow, "note"},
		{models.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := sarifLevel(tt.severity)
			if got != tt.level {
				t.Errorf("sarifLevel(%s) = %s, want %s", tt.severity, got, tt.level)
			}
		})
	}
}

func TestRenderSARIF_HelpURI(t *testing.T) {
	tests := []struct {
		name string
		refs []string
		want string
	}{
		{"CWE reference", []string{"CWE-89"}, "https://cwe.mitre.org/data/definitions/89.html"},
		{"URL reference", []string{"https://owasp.org/api-security"}, "https://owasp.org/api-security"},
		{"CWE + URL prefers URL", []string{"https://example.com", "CWE-89"}, "https://example.com"},
		{"empty references", []string{}, ""},
		{"nil references", nil, ""},
		{"empty string", []string{""}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sarifHelpURI(tt.refs)
			if got != tt.want {
				t.Errorf("sarifHelpURI(%v) = %q, want %q", tt.refs, got, tt.want)
			}
		})
	}
}

func TestRenderSARIF_ParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     *string
		wantFile string
		wantLine int
	}{
		{"file:line", strPtr("src/app.py:42"), "src/app.py", 42},
		{"file only", strPtr("src/app.py"), "src/app.py", 0},
		{"nil", nil, "", 0},
		{"empty", strPtr(""), "", 0},
		{"deep path", strPtr("src/pkg/handler.go:100"), "src/pkg/handler.go", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, line := parseLine(tt.line)
			if file != tt.wantFile {
				t.Errorf("parseLine() file = %q, want %q", file, tt.wantFile)
			}
			if line != tt.wantLine {
				t.Errorf("parseLine() line = %d, want %d", line, tt.wantLine)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}

func TestRenderSARIF_WhiteboxLocation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	line := "src/config.py:14"
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Hardcoded secret", Severity: models.SeverityCritical,
			Source: models.SourceWhitebox, Category: "secrets", Endpoint: "src/config.py:14",
			Evidence: "API_KEY = 'sk-live-...'", Fix: "Use env var", Confidence: models.ConfidenceHigh,
			References: []string{"CWE-798"}, Line: &line,
		},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	result := log.Runs[0].Results[0]
	if len(result.Locations) == 0 {
		t.Fatal("expected location for whitebox finding")
	}
	loc := result.Locations[0]
	if loc.PhysicalLocation == nil {
		t.Fatal("expected physical location for whitebox finding")
	}
	if loc.PhysicalLocation.ArtifactLocation.URI != "src/config.py" {
		t.Errorf("expected URI src/config.py, got %s", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	if loc.PhysicalLocation.Region == nil || loc.PhysicalLocation.Region.StartLine != 14 {
		t.Error("expected start line 14")
	}
}

func TestRenderSARIF_BlackboxLocation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Missing auth", Severity: models.SeverityCritical,
			Source: models.SourceBlackbox, Category: "auth", Endpoint: "GET /api/users",
			Evidence: "200 without auth", Fix: "Add auth", Confidence: models.ConfidenceHigh,
			References: []string{"CWE-306"},
		},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	result := log.Runs[0].Results[0]
	if len(result.Locations) == 0 {
		t.Fatal("expected location for blackbox finding")
	}
	loc := result.Locations[0]
	if len(loc.LogicalLocations) == 0 {
		t.Fatal("expected logical location for blackbox finding")
	}
	if loc.LogicalLocations[0].Name != "GET /api/users" {
		t.Errorf("expected endpoint name, got %s", loc.LogicalLocations[0].Name)
	}
	if loc.LogicalLocations[0].Kind != "endpoint" {
		t.Errorf("expected kind endpoint, got %s", loc.LogicalLocations[0].Kind)
	}
}

// TestRenderSARIF_AffectedEndpointsAsMultipleLocations covers TASK-088:
// a deduplicated finding should serialize each affected endpoint as its
// own SARIFLocation under the result. Per SARIF 2.1.0 §3.27.12, multiple
// locations on a result mean "this issue applies to all of them" — exactly
// the semantics we want.
func TestRenderSARIF_AffectedEndpointsAsMultipleLocations(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Missing CSP", Severity: models.SeverityMedium,
			Source: models.SourceBlackbox, Category: "headers",
			Endpoint:          "GET /api/users",
			AffectedEndpoints: []string{"GET /api/users", "GET /api/posts", "POST /api/login"},
			Evidence:          "no CSP header observed", Fix: "Add Content-Security-Policy",
			Confidence: models.ConfidenceHigh, References: []string{"CWE-693"},
		},
	}
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	results := log.Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	locs := results[0].Locations
	if len(locs) != 3 {
		t.Fatalf("expected 3 SARIFLocation entries (one per affected endpoint), got %d", len(locs))
	}
	gotNames := []string{
		locs[0].LogicalLocations[0].Name,
		locs[1].LogicalLocations[0].Name,
		locs[2].LogicalLocations[0].Name,
	}
	wantSet := map[string]bool{"GET /api/users": true, "GET /api/posts": true, "POST /api/login": true}
	for _, n := range gotNames {
		if !wantSet[n] {
			t.Errorf("unexpected endpoint name in SARIFLocation: %q (got names: %v)", n, gotNames)
		}
	}
}

func TestRenderSARIF_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}

	err := RenderSARIF(&buf, nil, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(log.Runs[0].Results))
	}
}

func TestRenderSARIF_RuleProperties(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "SQL Injection", Severity: models.SeverityCritical,
			Source: models.SourceBlackbox, Category: "injection", Endpoint: "POST /api/search",
			Evidence: "Response delayed", Fix: "Use parameterized queries", Confidence: models.ConfidenceHigh,
			References: []string{"CWE-89"},
		},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.Properties.Category != "injection" {
		t.Errorf("expected category injection, got %s", rule.Properties.Category)
	}
	if rule.Properties.Confidence != "HIGH" {
		t.Errorf("expected confidence HIGH, got %s", rule.Properties.Confidence)
	}
	if rule.Help.Text != "Use parameterized queries" {
		t.Errorf("expected fix text in help, got %s", rule.Help.Text)
	}
}

// TestRenderSARIF_RulesDedupedByCheckType is the regression test for TASK-083.
// Pre-fix, the rule dedup keyed on Finding.ID (per-instance, never duplicates),
// so 21 findings of "Missing CSP header" produced 21 distinct rules. After
// the fix, identical (category, title) collapse into one rule referenced N
// times — which is what GitHub Code Scanning expects for grouping.
func TestRenderSARIF_RulesDedupedByCheckType(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}

	// Same check fired across three endpoints — should yield 1 rule, 3 results.
	findings := []models.Finding{
		{ID: "SEC-001", Category: "headers", Title: "Missing Content-Security-Policy header",
			Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Endpoint: "GET /api/users", References: []string{}},
		{ID: "SEC-002", Category: "headers", Title: "Missing Content-Security-Policy header",
			Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Endpoint: "GET /api/orders", References: []string{}},
		{ID: "SEC-003", Category: "headers", Title: "Missing Content-Security-Policy header",
			Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Endpoint: "POST /api/orders", References: []string{}},
		// A different check; should produce a second rule.
		{ID: "SEC-004", Category: "cors", Title: "CORS reflects arbitrary origin",
			Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Endpoint: "GET /api/users", References: []string{}},
	}

	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}

	rules := log.Runs[0].Tool.Driver.Rules
	results := log.Runs[0].Results

	if len(rules) != 2 {
		t.Fatalf("expected 2 unique rules (1 headers + 1 cors), got %d:\n%s",
			len(rules), buf.String())
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// All three "headers" findings should share the same ruleId, and that ruleId
	// must match the rule's stable ID (not a per-finding SEC-NNN).
	headersRuleID := ""
	for _, r := range results[:3] {
		if headersRuleID == "" {
			headersRuleID = r.RuleID
		}
		if r.RuleID != headersRuleID {
			t.Errorf("expected identical ruleId across same-check findings, got %q vs %q",
				r.RuleID, headersRuleID)
		}
	}
	if headersRuleID == "SEC-001" || headersRuleID == "SEC-002" {
		t.Errorf("ruleId %q looks like per-finding ID — TASK-083 regressed", headersRuleID)
	}
	if headersRuleID == "" || results[3].RuleID == headersRuleID {
		t.Errorf("cors finding should have a different ruleId from headers; got %q vs %q",
			results[3].RuleID, headersRuleID)
	}

	// Result.ruleIndex must point to the dedup'd rule.
	for i, r := range results[:3] {
		if r.RuleIndex < 0 || r.RuleIndex >= len(rules) || rules[r.RuleIndex].ID != headersRuleID {
			t.Errorf("result[%d].ruleIndex=%d does not point to headers rule", i, r.RuleIndex)
		}
	}
}

func TestRenderSARIF_RuleIndex(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Issue 1", Severity: models.SeverityHigh, Source: models.SourceBlackbox, References: []string{}},
		{ID: "SEC-002", Title: "Issue 2", Severity: models.SeverityMedium, Source: models.SourceBlackbox, References: []string{}},
		{ID: "SEC-003", Title: "Issue 3", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	for i, result := range log.Runs[0].Results {
		if result.RuleIndex != i {
			t.Errorf("result %d: expected ruleIndex %d, got %d", i, i, result.RuleIndex)
		}
	}
}

func TestRenderSARIF_Invocation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}

	err := RenderSARIF(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	if len(log.Runs[0].Invocations) == 0 {
		t.Fatal("expected invocation")
	}
	if !log.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("expected executionSuccessful to be true")
	}
}

func TestRenderSARIF_PrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	output := buf.String()
	// Pretty-printed JSON should contain newlines and indentation
	if len(output) < 50 {
		t.Error("output too short to be pretty-printed")
	}
}

// TestRenderSARIF_SchemaValidation validates the SARIF output against
// the key structural requirements of SARIF 2.1.0 schema:
// - Required top-level fields: version, $schema, runs
// - Required run fields: tool, results
// - Required tool fields: driver with name, rules
// - Required result fields: ruleId, ruleIndex, level, message
// - Level values: "error", "warning", or "note"
// - Rules match results by index
func TestRenderSARIF_SchemaValidation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "1.0.0",
		Mode:      "hybrid",
	}

	line := "src/app.py:42"
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Critical Auth", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Category: "auth", Endpoint: "GET /api/users", Evidence: "200 without auth", Fix: "Add auth",
			Confidence: models.ConfidenceHigh, References: []string{"CWE-306", "OWASP-A01"}},
		{ID: "SEC-002", Title: "Hardcoded Secret", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Category: "secrets", Endpoint: "src/app.py:42", Evidence: "secret=...", Fix: "Use env var",
			Confidence: models.ConfidenceMedium, References: []string{"CWE-798"}, Line: &line},
		{ID: "SEC-003", Title: "Missing HSTS", Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Category: "headers", Endpoint: "GET /api/health", Evidence: "No HSTS header", Fix: "Add HSTS",
			Confidence: models.ConfidenceHigh, References: []string{"CWE-319"}},
		{ID: "SEC-004", Title: "Server Version", Severity: models.SeverityInfo, Source: models.SourceBlackbox,
			Category: "info_disclosure", Endpoint: "GET /", Evidence: "Server: nginx/1.21", Fix: "Remove version",
			Confidence: models.ConfidenceLow, References: []string{}},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	// Parse as raw JSON to validate structure
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// 1. Top-level required fields
	if raw["version"] != "2.1.0" {
		t.Errorf("version must be 2.1.0, got %v", raw["version"])
	}
	schema, ok := raw["$schema"].(string)
	if !ok || schema == "" {
		t.Error("$schema must be a non-empty string")
	}
	runs, ok := raw["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("runs must be a non-empty array")
	}

	// 2. Run structure
	run := runs[0].(map[string]interface{})
	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		t.Fatal("run.tool must be an object")
	}
	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		t.Fatal("run.tool.driver must be an object")
	}
	if driver["name"] != "Fendix" {
		t.Errorf("driver.name must be Fendix, got %v", driver["name"])
	}
	if _, ok := driver["version"].(string); !ok {
		t.Error("driver.version must be a string")
	}
	if _, ok := driver["informationUri"].(string); !ok {
		t.Error("driver.informationUri must be a string")
	}

	// 3. Rules array
	rules, ok := driver["rules"].([]interface{})
	if !ok {
		t.Fatal("driver.rules must be an array")
	}
	if len(rules) != len(findings) {
		t.Errorf("expected %d rules, got %d", len(findings), len(rules))
	}

	// Validate each rule has required fields
	validLevels := map[string]bool{"error": true, "warning": true, "note": true}
	for i, r := range rules {
		rule := r.(map[string]interface{})
		if _, ok := rule["id"].(string); !ok {
			t.Errorf("rule[%d].id must be a string", i)
		}
		if _, ok := rule["shortDescription"].(map[string]interface{}); !ok {
			t.Errorf("rule[%d].shortDescription must be an object", i)
		}
		help, ok := rule["help"].(map[string]interface{})
		if !ok {
			t.Errorf("rule[%d].help must be an object", i)
		}
		if _, ok := help["text"].(string); !ok {
			t.Errorf("rule[%d].help.text must be a string", i)
		}
		cfg := rule["defaultConfiguration"].(map[string]interface{})
		level := cfg["level"].(string)
		if !validLevels[level] {
			t.Errorf("rule[%d].defaultConfiguration.level = %q is not a valid SARIF level", i, level)
		}
	}

	// 4. Results array
	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatal("run.results must be an array")
	}
	if len(results) != len(findings) {
		t.Errorf("expected %d results, got %d", len(findings), len(results))
	}

	for i, r := range results {
		result := r.(map[string]interface{})
		ruleID, ok := result["ruleId"].(string)
		if !ok || ruleID == "" {
			t.Errorf("result[%d].ruleId must be a non-empty string", i)
		}
		ruleIndex, ok := result["ruleIndex"].(float64)
		if !ok {
			t.Errorf("result[%d].ruleIndex must be a number", i)
		}
		if int(ruleIndex) < 0 || int(ruleIndex) >= len(rules) {
			t.Errorf("result[%d].ruleIndex %d out of range", i, int(ruleIndex))
		}
		level, ok := result["level"].(string)
		if !ok || !validLevels[level] {
			t.Errorf("result[%d].level = %q is not a valid SARIF level", i, level)
		}
		msg, ok := result["message"].(map[string]interface{})
		if !ok {
			t.Errorf("result[%d].message must be an object", i)
		}
		if _, ok := msg["text"].(string); !ok {
			t.Errorf("result[%d].message.text must be a string", i)
		}
	}

	// 5. Verify invocations
	invocations, ok := run["invocations"].([]interface{})
	if !ok || len(invocations) == 0 {
		t.Error("run.invocations must be a non-empty array")
	} else {
		inv := invocations[0].(map[string]interface{})
		if inv["executionSuccessful"] != true {
			t.Error("invocation.executionSuccessful must be true")
		}
	}

	// 6. Verify severity level mapping for each finding
	expectedLevels := []string{"error", "error", "warning", "note"}
	for i, r := range results {
		result := r.(map[string]interface{})
		if result["level"] != expectedLevels[i] {
			t.Errorf("result[%d] level = %q, expected %q", i, result["level"], expectedLevels[i])
		}
	}
}
