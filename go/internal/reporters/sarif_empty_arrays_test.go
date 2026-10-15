package reporters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// SARIF 2.1.0 types these properties as arrays. A nil Go slice marshals to
// null, which the schema rejects: with zero findings v3.6.0 wrote
// "rules": null and GitHub's upload-sarif refused the whole file, so every
// clean scan failed at upload. Each must be [] when empty, never null.
var sarifArrayKeys = map[string]bool{
	"runs": true, "results": true, "rules": true, "codeFlows": true,
	"threadFlows": true, "locations": true, "logicalLocations": true,
	"invocations": true, "toolExecutionNotifications": true, "tags": true,
}

func TestRenderSARIF_ZeroFindingsEmitsEmptyArrays(t *testing.T) {
	_, raw := renderOccSARIF(t, nil)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %#v, want one run", doc["runs"])
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	for name, value := range map[string]any{"results": run["results"], "rules": driver["rules"]} {
		arr, ok := value.([]any)
		if !ok {
			t.Errorf("%s = %#v, want an empty JSON array", name, value)
			continue
		}
		if len(arr) != 0 {
			t.Errorf("%s has %d entries, want none", name, len(arr))
		}
	}
}

// No array-typed key is ever null, with or without findings.
func TestRenderSARIF_NoNullArrays(t *testing.T) {
	cases := map[string][]models.Finding{
		"zero findings":   nil,
		"grouped finding": {groupedSecret()},
	}
	for name, findings := range cases {
		_, raw := renderOccSARIF(t, findings)
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, path := range nullArrayPaths(doc, "$") {
			t.Errorf("%s: %s is null, want a JSON array", name, path)
		}
	}
}

func nullArrayPaths(node any, path string) []string {
	var out []string
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if child == nil && sarifArrayKeys[key] {
				out = append(out, path+"."+key)
			}
			out = append(out, nullArrayPaths(child, path+"."+key)...)
		}
	case []any:
		for _, child := range v {
			out = append(out, nullArrayPaths(child, path+"[]")...)
		}
	}
	return out
}

// Golden contract for a scan with no findings. python/tests/test_sarif_schema.py
// validates every golden SARIF file against the official SARIF 2.1.0 schema.
func TestSARIF_ZeroFindingsGolden(t *testing.T) {
	_, got := renderOccSARIF(t, nil)
	golden := filepath.Join("testdata", "sarif_zero_findings.golden.sarif")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_GOLDEN=1 after reviewing the contract)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SARIF for zero findings changed; review and run UPDATE_GOLDEN=1 go test ./internal/reporters -run TestSARIF_ZeroFindingsGolden\n%s", got)
	}
}
