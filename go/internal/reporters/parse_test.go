package reporters

import (
	"strings"
	"testing"
)

const validJSONReport = `{
  "metadata": {
    "target": "https://api.example.com",
    "started_at": "2026-04-29T17:00:00Z",
    "duration": "1.2s",
    "version": "v0.4.1",
    "mode": "blackbox",
    "endpoints_scanned": 12,
    "active_probes": false
  },
  "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
  "sources": {"blackbox": 1, "whitebox": 0, "correlated": 0},
  "total": 1,
  "findings": []
}`

func TestParseJSONReport_Valid(t *testing.T) {
	got, err := ParseJSONReport([]byte(validJSONReport))
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if got.Metadata.Version != "v0.4.1" {
		t.Errorf("Metadata.Version = %q, want v0.4.1", got.Metadata.Version)
	}
	if got.Metadata.Mode != "blackbox" {
		t.Errorf("Metadata.Mode = %q, want blackbox", got.Metadata.Mode)
	}
	if got.Total != 1 {
		t.Errorf("Total = %d, want 1", got.Total)
	}
}

func TestParseJSONReport_RejectsSARIFWithSchemaURL(t *testing.T) {
	sarif := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{"tool": {"driver": {"name": "Fendix"}}, "results": []}]
	}`
	_, err := ParseJSONReport([]byte(sarif))
	if err == nil {
		t.Fatal("expected error on SARIF input, got nil")
	}
	if !strings.Contains(err.Error(), "SARIF") {
		t.Errorf("expected SARIF in error message, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "--format json") {
		t.Errorf("expected actionable hint with --format json, got %q", err.Error())
	}
}

func TestParseJSONReport_RejectsSARIFWithoutSchemaURL(t *testing.T) {
	// Some SARIF emitters omit $schema. The runs+version heuristic should
	// still catch them.
	sarif := `{
		"version": "2.1.0",
		"runs": [{"tool": {"driver": {"name": "Fendix"}}, "results": []}]
	}`
	_, err := ParseJSONReport([]byte(sarif))
	if err == nil {
		t.Fatal("expected error on SARIF-shaped input, got nil")
	}
	if !strings.Contains(err.Error(), "SARIF") {
		t.Errorf("expected SARIF in error message, got %q", err.Error())
	}
}

func TestParseJSONReport_RejectsRandomJSON(t *testing.T) {
	random := `{"foo": "bar", "baz": [1, 2, 3]}`
	_, err := ParseJSONReport([]byte(random))
	if err == nil {
		t.Fatal("expected error on random JSON, got nil")
	}
	if !strings.Contains(err.Error(), "JSONReport") {
		t.Errorf("expected JSONReport in error message, got %q", err.Error())
	}
}

func TestParseJSONReport_RejectsMalformedJSON(t *testing.T) {
	bad := `{"metadata": {malformed`
	_, err := ParseJSONReport([]byte(bad))
	if err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing JSON") {
		t.Errorf("expected parse error, got %q", err.Error())
	}
}

func TestParseJSONReport_RejectsJSONReportMissingMetadata(t *testing.T) {
	// Findings array but no metadata.version/mode — looks like someone tried
	// to feed the script a partial report.
	stripped := `{"findings": [], "total": 0}`
	_, err := ParseJSONReport([]byte(stripped))
	if err == nil {
		t.Fatal("expected error on report missing metadata, got nil")
	}
	if !strings.Contains(err.Error(), "metadata") {
		t.Errorf("expected metadata-missing hint in error, got %q", err.Error())
	}
}

// TestIsSARIF_Heuristics covers the edge cases of isSARIF() directly so we
// don't need to spin up full reports for each one.
func TestIsSARIF_Heuristics(t *testing.T) {
	tests := []struct {
		name string
		json map[string]any
		want bool
	}{
		{
			name: "schema URL with sarif",
			json: map[string]any{"$schema": "https://example.com/sarif-2.1.0.json"},
			want: true,
		},
		{
			name: "schema URL case-insensitive",
			json: map[string]any{"$schema": "https://EXAMPLE.com/SARIF.json"},
			want: true,
		},
		{
			name: "runs + version (SARIF without schema URL)",
			json: map[string]any{"version": "2.1.0", "runs": []any{}},
			want: true,
		},
		{
			name: "runs alone (insufficient)",
			json: map[string]any{"runs": []any{}},
			want: false,
		},
		{
			name: "version alone (insufficient — JSONReport doesn't have top-level version)",
			json: map[string]any{"version": "v0.4.1"},
			want: false,
		},
		{
			name: "JSONReport shape",
			json: map[string]any{"metadata": map[string]any{"version": "v0.4.1", "mode": "blackbox"}},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isSARIF(tc.json)
			if got != tc.want {
				t.Errorf("isSARIF(%v) = %v, want %v", tc.json, got, tc.want)
			}
		})
	}
}

// preSchemaVersionJSONReport is a verbatim report body from a build that
// predates `metadata.schema_version`. It is duplicated rather than derived
// from validJSONReport on purpose: its whole job is to be frozen, and a
// future edit that adds schema_version to the shared const would silently
// stop exercising the thing this asserts.
const preSchemaVersionJSONReport = `{
  "metadata": {
    "target": "https://api.example.com",
    "started_at": "2026-04-29T17:00:00Z",
    "duration": "1.2s",
    "version": "v0.4.1",
    "mode": "blackbox",
    "endpoints_scanned": 12,
    "active_probes": false
  },
  "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
  "sources": {"blackbox": 1, "whitebox": 0, "correlated": 0},
  "total": 1,
  "findings": []
}`

// TestParseJSONReport_PreSchemaVersionStillParses is the backward-compat
// guard for the schema_version field. Adding it must not invalidate a
// single archived report: the key is absent, so it decodes to 0, and the
// report is still accepted — the shape check reads version+mode only.
func TestParseJSONReport_PreSchemaVersionStillParses(t *testing.T) {
	got, err := ParseJSONReport([]byte(preSchemaVersionJSONReport))
	if err != nil {
		t.Fatalf("a pre-schema_version report must still parse, got error: %v", err)
	}
	if got.Metadata.SchemaVersion != 0 {
		t.Errorf("Metadata.SchemaVersion = %d, want 0 for an absent key", got.Metadata.SchemaVersion)
	}
	// The rest of the metadata must be untouched by the new field.
	if got.Metadata.Version != "v0.4.1" {
		t.Errorf("Metadata.Version = %q, want v0.4.1", got.Metadata.Version)
	}
	if got.Metadata.Mode != "blackbox" {
		t.Errorf("Metadata.Mode = %q, want blackbox", got.Metadata.Mode)
	}
	if got.Total != 1 {
		t.Errorf("Total = %d, want 1", got.Total)
	}
}

// TestParseJSONReport_UnknownSchemaVersionStillParses is the forward half:
// a value this build does not know is not a parse failure. Deciding what to
// do about an unrecognised contract belongs to the consumer, not the reader.
func TestParseJSONReport_UnknownSchemaVersionStillParses(t *testing.T) {
	future := strings.Replace(
		validJSONReport,
		`"target": "https://api.example.com"`,
		`"schema_version": 99, "target": "https://api.example.com"`,
		1,
	)
	got, err := ParseJSONReport([]byte(future))
	if err != nil {
		t.Fatalf("an unknown schema_version must still parse, got error: %v", err)
	}
	if got.Metadata.SchemaVersion != 99 {
		t.Errorf("Metadata.SchemaVersion = %d, want 99 (decoded verbatim)", got.Metadata.SchemaVersion)
	}
}
