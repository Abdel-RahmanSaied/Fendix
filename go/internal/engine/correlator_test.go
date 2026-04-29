package engine

import (
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func linePtr(s string) *string { return &s }

func TestCorrelate_MatchingFindings(t *testing.T) {
	bb := models.Finding{
		Title:      "Missing authentication",
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "http://example.com/api/v1/users",
		Evidence:   "200 OK without auth",
		Fix:        "Add authentication",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Missing auth decorator",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "routes/users.py:42",
		Evidence:   "No @login_required",
		Fix:        "Add @login_required",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
		Line:       linePtr("routes/users.py:42"),
	}

	result := Correlate([]models.Finding{bb, wb})

	// Should produce 1 correlated finding
	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}

	f := result[0]
	if f.Source != models.SourceCorrelated {
		t.Errorf("expected source correlated, got %s", f.Source)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected confidence HIGH, got %s", f.Confidence)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected severity CRITICAL (escalated from CRITICAL stays CRITICAL), got %s", f.Severity)
	}
	if f.Line == nil {
		t.Error("expected line from whitebox finding to be preserved")
	}
}

// TASK-092: a file:line whitebox finding cannot be confirmed by a live HTTP
// scan, so the [Unconfirmed by live scan] suffix is misleading there. The
// finding should pass through unchanged (confidence, evidence, source).
func TestCorrelate_FilePathWhiteboxNotMarkedUnconfirmed(t *testing.T) {
	wb := models.Finding{
		Title:      "SQL injection pattern",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "injection",
		Endpoint:   "db/queries.py:15",
		Evidence:   "cursor.execute(f\"SELECT...\")",
		Fix:        "Use parameterized queries",
		References: []string{"CWE-89"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	f := result[0]
	if f.Source != models.SourceWhitebox {
		t.Errorf("expected source whitebox, got %s", f.Source)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected confidence HIGH (file:line endpoint, no live-scan confirmation possible), got %s", f.Confidence)
	}
	if f.Evidence != "cursor.execute(f\"SELECT...\")" {
		t.Errorf("expected unchanged evidence, got %q", f.Evidence)
	}
}

// TASK-092: a URL-endpoint whitebox finding with no matching blackbox finding
// (live scan ran clean for that endpoint) still gets the suffix and confidence
// downgrade — that's the case the suffix is designed for.
func TestCorrelate_URLWhiteboxMarkedUnconfirmed(t *testing.T) {
	wb := models.Finding{
		Title:      "Endpoint missing security",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "GET /api/v1/admin",
		Evidence:   "No security defined in spec",
		Fix:        "Add a security requirement",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	f := result[0]
	if f.Confidence != models.ConfidenceMedium {
		t.Errorf("expected confidence MEDIUM (URL endpoint, downgraded), got %s", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "[Unconfirmed by live scan]") {
		t.Errorf("expected unconfirmed suffix on URL-endpoint finding, got %q", f.Evidence)
	}
}

func TestCorrelate_BlackboxOnly(t *testing.T) {
	bb := models.Finding{
		Title:      "Missing HSTS header",
		Severity:   models.SeverityMedium,
		Source:     models.SourceBlackbox,
		Category:   "headers",
		Endpoint:   "http://example.com/api/users",
		Evidence:   "HSTS header not present",
		Fix:        "Add HSTS header",
		References: []string{"CWE-319"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{bb})

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	f := result[0]
	if f.Source != models.SourceBlackbox {
		t.Errorf("expected source blackbox (unchanged), got %s", f.Source)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected severity MEDIUM (unchanged), got %s", f.Severity)
	}
}

func TestCorrelate_NoFindings(t *testing.T) {
	result := Correlate(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestCorrelate_MixedWithUncorrelated(t *testing.T) {
	findings := []models.Finding{
		{
			Title:      "Missing HSTS",
			Severity:   models.SeverityMedium,
			Source:     models.SourceBlackbox,
			Category:   "headers",
			Endpoint:   "http://example.com/api/v1/users",
			Evidence:   "No HSTS header",
			Fix:        "Add HSTS",
			References: []string{},
			Confidence: models.ConfidenceHigh,
		},
		{
			Title:      "Hardcoded secret",
			Severity:   models.SeverityHigh,
			Source:     models.SourceWhitebox,
			Category:   "secrets",
			Endpoint:   "config/settings.py:8",
			Evidence:   "API_KEY = 'sk-...'",
			Fix:        "Use env var",
			References: []string{"CWE-798"},
			Confidence: models.ConfidenceHigh,
		},
		{
			Title:      "Password in response",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "data_exposure",
			Endpoint:   "http://example.com/api/v1/users",
			Evidence:   "password field in JSON",
			Fix:        "Remove sensitive fields",
			References: []string{"CWE-200"},
			Confidence: models.ConfidenceHigh,
		},
	}

	result := Correlate(findings)

	// "Hardcoded secret" (whitebox, secrets) should NOT correlate with blackbox "headers"
	// but should try to correlate with "data_exposure" on /users — endpoint segments differ
	// so it stays unconfirmed.
	// Total: 3 findings (no correlation expected since endpoints don't match)
	hasBlackbox := false
	hasWhitebox := false
	for _, f := range result {
		if f.Source == models.SourceBlackbox {
			hasBlackbox = true
		}
		if f.Source == models.SourceWhitebox {
			hasWhitebox = true
		}
	}

	if !hasBlackbox {
		t.Error("expected blackbox findings to be present")
	}
	if !hasWhitebox {
		t.Error("expected whitebox finding to be present (unconfirmed)")
	}
}

func TestCorrelate_SeverityEscalation(t *testing.T) {
	// When correlated, severity escalates by one level
	bb := models.Finding{
		Title:      "No auth required",
		Severity:   models.SeverityHigh,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "http://example.com/api/v1/admin",
		Evidence:   "200 without auth",
		Fix:        "Add auth",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Missing auth check",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "handlers/admin.py:10",
		Evidence:   "No auth decorator",
		Fix:        "Add decorator",
		References: []string{"CWE-862"},
		Confidence: models.ConfidenceHigh,
		Line:       linePtr("handlers/admin.py:10"),
	}

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(result))
	}

	// HIGH escalated = CRITICAL
	if result[0].Severity != models.SeverityCritical {
		t.Errorf("expected severity CRITICAL (escalated from HIGH), got %s", result[0].Severity)
	}
}

func TestCorrelate_ReferencesMerged(t *testing.T) {
	bb := models.Finding{
		Title:      "Auth bypass",
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "http://example.com/api/v1/config",
		Evidence:   "200 no auth",
		Fix:        "Fix",
		References: []string{"CWE-306", "OWASP-A01"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Missing auth",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "routes/config.py:5",
		Evidence:   "No decorator",
		Fix:        "Fix",
		References: []string{"CWE-306", "CWE-862"},
		Confidence: models.ConfidenceHigh,
	}

	result := Correlate([]models.Finding{bb, wb})
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	refs := result[0].References
	// Should have CWE-306, OWASP-A01, CWE-862 (deduplicated)
	if len(refs) != 3 {
		t.Errorf("expected 3 merged references, got %d: %v", len(refs), refs)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"full URL", "http://example.com/api/v1/users", "/api/v1/users"},
		{"URL with trailing slash", "http://example.com/api/v1/users/", "/api/v1/users"},
		{"URL with query", "http://example.com/api/v1/users?page=1", "/api/v1/users"},
		{"URL root", "http://example.com/", "/"},
		{"file path", "src/config.py:14", "src/config.py"},
		{"file path no line", "routes/users.py", "routes/users.py"},
		{"bare path", "/api/v1/users", "/api/v1/users"},
		{"empty", "", ""},
		// TASK-091: spec-parser endpoints have a "<METHOD> <PATH>" prefix.
		{"method prefix GET", "GET /pet/findByStatus", "/pet/findbystatus"},
		{"method prefix POST", "POST /users", "/users"},
		{"method prefix lowercase", "delete /api/v1/items/42", "/api/v1/items/42"},
		{"method prefix with full URL", "GET http://example.com/pet", "/pet"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeEndpoint(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeEndpoint(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestEndpointsRelated(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"exact match", "/api/v1/users", "/api/v1/users", true},
		{"path vs file", "/api/v1/users", "routes/users.py", true},
		{"path vs handler", "/api/v1/admin", "handlers/admin.py", true},
		{"unrelated", "/api/v1/users", "config/settings.py", false},
		{"short segments ignored", "/a", "/a", true}, // exact match
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := endpointsRelated(tc.a, tc.b)
			if got != tc.expected {
				t.Errorf("endpointsRelated(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

func TestEscalateSeverity(t *testing.T) {
	tests := []struct {
		input    models.Severity
		expected models.Severity
	}{
		{models.SeverityInfo, models.SeverityLow},
		{models.SeverityLow, models.SeverityMedium},
		{models.SeverityMedium, models.SeverityHigh},
		{models.SeverityHigh, models.SeverityCritical},
		{models.SeverityCritical, models.SeverityCritical},
	}

	for _, tc := range tests {
		t.Run(string(tc.input), func(t *testing.T) {
			got := escalateSeverity(tc.input)
			if got != tc.expected {
				t.Errorf("escalateSeverity(%s) = %s, want %s", tc.input, got, tc.expected)
			}
		})
	}
}

func TestHigherSeverity(t *testing.T) {
	tests := []struct {
		a, b     models.Severity
		expected models.Severity
	}{
		{models.SeverityHigh, models.SeverityMedium, models.SeverityHigh},
		{models.SeverityMedium, models.SeverityCritical, models.SeverityCritical},
		{models.SeverityLow, models.SeverityLow, models.SeverityLow},
	}

	for _, tc := range tests {
		t.Run(string(tc.a)+"_vs_"+string(tc.b), func(t *testing.T) {
			got := higherSeverity(tc.a, tc.b)
			if got != tc.expected {
				t.Errorf("higherSeverity(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

func TestMergeRefs(t *testing.T) {
	a := []string{"CWE-306", "OWASP-A01"}
	b := []string{"CWE-306", "CWE-862"}

	result := mergeRefs(a, b)
	if len(result) != 3 {
		t.Errorf("expected 3 refs, got %d: %v", len(result), result)
	}

	expected := map[string]bool{"CWE-306": true, "OWASP-A01": true, "CWE-862": true}
	for _, r := range result {
		if !expected[r] {
			t.Errorf("unexpected ref: %s", r)
		}
	}
}

// TASK-091: Real-world petstore3 case — whitebox spec parser emits endpoint
// "GET /pet/findByStatus", blackbox emits the full URL with the server's
// /api/v3 base path. The pre-fix correlator returned 0 correlated findings
// here. Now must merge via path-suffix match.
func TestCorrelate_PathSuffixMatch_PetstoreStyle(t *testing.T) {
	bb := models.Finding{
		Title:      "No auth required",
		Severity:   models.SeverityHigh,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   "https://petstore3.swagger.io/api/v3/pet/findByStatus",
		Evidence:   "200 without auth",
		Fix:        "Add auth",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceHigh,
	}

	wb := models.Finding{
		Title:      "Endpoint has no authentication requirement",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "auth",
		Endpoint:   "GET /pet/findByStatus",
		Evidence:   "GET /pet/findByStatus has no security defined.",
		Fix:        "Add a security requirement.",
		References: []string{"CWE-306"},
		Confidence: models.ConfidenceMedium,
	}

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding (suffix match), got %d", len(result))
	}
	if result[0].Source != models.SourceCorrelated {
		t.Errorf("expected source correlated, got %s", result[0].Source)
	}
}

// TASK-091: blackbox path /api/v1/users contains whitebox path /users on a
// `/` boundary. Suffix match should fire even when there's no method prefix
// in the whitebox finding.
func TestCorrelate_PathSuffixMatch_BarePath(t *testing.T) {
	bb := models.Finding{
		Title:    "Sensitive data exposed",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "data_exposure",
		Endpoint: "http://example.com/api/v1/users",
	}

	wb := models.Finding{
		Title:    "Hardcoded API key",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		Category: "secrets",
		Endpoint: "/users",
		Evidence: "API_KEY = 'sk-...'",
	}

	result := Correlate([]models.Finding{bb, wb})

	if len(result) != 1 {
		t.Fatalf("expected 1 correlated finding via suffix, got %d", len(result))
	}
	if result[0].Source != models.SourceCorrelated {
		t.Errorf("expected source correlated, got %s", result[0].Source)
	}
}

// TASK-091: each blackbox finding can correlate with at most one whitebox
// finding. Without the `taken` set, two different whitebox findings could
// both merge with the same blackbox.
func TestCorrelate_BlackboxConsumedAtMostOnce(t *testing.T) {
	bb := models.Finding{
		Title:    "No auth required",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "auth_bypass",
		Endpoint: "http://example.com/api/v1/users",
	}

	wb1 := models.Finding{
		Title:    "Missing auth decorator",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		Category: "auth",
		Endpoint: "GET /users",
	}

	wb2 := models.Finding{
		Title:    "Different auth bug",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		Category: "auth",
		Endpoint: "POST /users",
	}

	result := Correlate([]models.Finding{bb, wb1, wb2})

	correlatedCount := 0
	unconfirmedCount := 0
	for _, f := range result {
		if f.Source == models.SourceCorrelated {
			correlatedCount++
		}
		if f.Source == models.SourceWhitebox {
			unconfirmedCount++
		}
	}

	if correlatedCount != 1 {
		t.Errorf("expected exactly 1 correlated finding (blackbox consumed once), got %d", correlatedCount)
	}
	if unconfirmedCount != 1 {
		t.Errorf("expected 1 unconfirmed whitebox (the second wf had no available bb), got %d", unconfirmedCount)
	}
}

func TestPathSuffixMatch(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"exact match", "/api/v1/users", "/api/v1/users", true},
		{"suffix match", "/users", "/api/v1/users", true},
		{"suffix match reversed args", "/api/v1/users", "/users", true},
		{"deeper suffix", "/pet/findbystatus", "/api/v3/pet/findbystatus", true},
		{"mid-segment boundary rejected", "/3/pet", "/api/v3/pet", false},
		{"trivial root rejected", "/", "/api/v1/users", false},
		{"non-path inputs rejected", "src/config.py", "/api/v1/users", false},
		{"no shared suffix", "/items", "/api/v1/users", false},
		{"empty inputs rejected", "", "/users", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pathSuffixMatch(tc.a, tc.b)
			if got != tc.expected {
				t.Errorf("pathSuffixMatch(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

func TestRelatedCategories(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"auth", "auth_bypass"},
		{"secrets", "data_exposure"},
		{"injection", "injection"},
		{"auth_bypass", "auth"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			cats := relatedCategories(tc.input)
			found := false
			for _, c := range cats {
				if c == tc.contains {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("relatedCategories(%q) should contain %q, got %v", tc.input, tc.contains, cats)
			}
		})
	}
}
