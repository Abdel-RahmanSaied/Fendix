package reporters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// docs/schema.json is the contract consumers validate against, and it sets
// "additionalProperties": false — so a field added to the Go struct without a
// matching entry there does not merely go undocumented, it makes every real
// report FAIL validation for anyone who checks.
//
// That is not hypothetical. Nine fields from the decision-integrity release —
// decision_reason, decision_policy, policy_override, independent_signals,
// self_evident_signals, auth_expectation, applicability,
// cross_tool_corroborated, corroborating_tools — reached production without
// reaching the schema, so the published contract rejected the engine's own
// output until v3.0.0 caught it.
//
// The hand-rolled validator in schema_test.go checks SHAPE, which is a
// different job: it cannot notice a field nobody told it about. This walks the
// structs instead, so a new field fails here the moment it is added.

func loadSchemaProperties(t *testing.T, definition string) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "..", "docs", "schema.json")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var schema struct {
		Definitions map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(blob, &schema); err != nil {
		t.Fatalf("parsing schema.json: %v", err)
	}
	def, ok := schema.Definitions[definition]
	if !ok {
		t.Fatalf("schema.json has no definition %q", definition)
	}
	return def.Properties
}

// jsonFieldNames returns the wire names of every serialised field on a struct.
func jsonFieldNames(t *testing.T, v any) []string {
	t.Helper()
	typ := reflect.TypeOf(v)
	names := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func assertNoDrift(t *testing.T, definition string, v any) {
	t.Helper()
	props := loadSchemaProperties(t, definition)
	for _, name := range jsonFieldNames(t, v) {
		if _, ok := props[name]; !ok {
			t.Errorf("%s.%s is serialised but absent from docs/schema.json — "+
				"additionalProperties is false there, so every report carrying it "+
				"fails validation for any consumer who checks", definition, name)
		}
	}
}

func TestFindingHasNoSchemaDrift(t *testing.T) {
	assertNoDrift(t, "Finding", models.Finding{})
}

func TestScanMetadataHasNoSchemaDrift(t *testing.T) {
	assertNoDrift(t, "ScanMetadata", ScanMetadata{})
}

// The reverse direction: a property documented in the schema that no longer
// exists on the struct is a promise the engine has stopped keeping.
func TestSchemaDocumentsNoFieldsTheEngineDroppedFromFinding(t *testing.T) {
	live := map[string]bool{}
	for _, n := range jsonFieldNames(t, models.Finding{}) {
		live[n] = true
	}
	for name := range loadSchemaProperties(t, "Finding") {
		if !live[name] {
			t.Errorf("docs/schema.json documents Finding.%s, which the struct no longer has", name)
		}
	}
}

// The mode enum has to list every mode the orchestrator actually stamps, or an
// import run's report fails validation.
func TestSchemaModeEnumCoversEveryScanMode(t *testing.T) {
	props := loadSchemaProperties(t, "ScanMetadata")
	mode, ok := props["mode"].(map[string]any)
	if !ok {
		t.Fatal("schema.json has no ScanMetadata.mode")
	}
	raw, ok := mode["enum"].([]any)
	if !ok {
		t.Fatal("ScanMetadata.mode has no enum")
	}
	got := map[string]bool{}
	for _, v := range raw {
		got[v.(string)] = true
	}
	for _, want := range []string{"blackbox", "whitebox", "hybrid", "import"} {
		if !got[want] {
			t.Errorf("scan mode %q is stamped by the orchestrator but missing from the schema enum", want)
		}
	}
}
