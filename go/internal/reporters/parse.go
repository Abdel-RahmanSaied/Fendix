package reporters

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseJSONReport parses raw bytes into a JSONReport and validates that the
// input actually looks like a Fendix scan report, not some other JSON
// document that happens to be syntactically valid (the most common
// confusion: feeding a SARIF file to `fendix report --input`).
//
// The previous implementation used `json.Unmarshal` directly, which silently
// accepted any JSON object — SARIF files would deserialize into a
// zero-valued JSONReport and produce an empty HTML report with no error.
// This helper catches that case and returns an actionable message.
//
// Detection layers, in order:
//  1. SARIF-shape detection (`$schema` containing "sarif" or top-level
//     `runs` + `version` keys). Returns a SARIF-specific error.
//  2. JSONReport-shape sanity check (metadata.version and metadata.mode
//     populated). A real report always has these; SARIF and random JSON
//     don't.
//  3. Successful path: returns the parsed JSONReport.
func ParseJSONReport(data []byte) (*JSONReport, error) {
	// Stage 1: parse into a generic shape so we can sniff the structure
	// before committing to the JSONReport schema.
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w (ensure the file was produced by 'fendix scan --format json')", err)
	}

	if isSARIF(generic) {
		return nil, fmt.Errorf("input looks like a SARIF file, not a Fendix JSONReport — re-scan with `fendix scan --format json --output scan.json`, then run `fendix report --input scan.json`")
	}

	// Stage 2: parse into the real schema.
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing JSON report — ensure it was produced by 'fendix scan --format json': %w", err)
	}

	// Stage 3: shape sanity check. A real Fendix JSONReport always has a
	// non-empty metadata.version (set from the binary's `main.Version`) and
	// a non-empty metadata.mode (`blackbox` / `whitebox` / `hybrid`).
	// Random JSON without those fields would render an empty report.
	if report.Metadata.Version == "" && report.Metadata.Mode == "" {
		return nil, fmt.Errorf("input is valid JSON but does not look like a Fendix JSONReport (missing `metadata.version` and `metadata.mode`) — produce one with `fendix scan --format json`")
	}

	// `metadata.schema_version` is deliberately NOT part of that check and
	// must never be added to it. Every report written before the field
	// existed omits the key and decodes to 0, so requiring it would reject
	// the whole archive. An UNKNOWN (future) value is not this reader's
	// call to reject either — the engine parses permissively and leaves
	// "I don't recognise this contract" to the consumer that has to act
	// on it. TestParseJSONReport_PreSchemaVersionStillParses and
	// TestParseJSONReport_UnknownSchemaVersionStillParses pin both halves.

	return &report, nil
}

// isSARIF returns true if the parsed JSON looks like a SARIF document.
// Two independent signals are checked because real-world SARIF emitters
// vary on whether they include the $schema URL.
func isSARIF(generic map[string]any) bool {
	if schema, ok := generic["$schema"].(string); ok {
		if strings.Contains(strings.ToLower(schema), "sarif") {
			return true
		}
	}
	// SARIF 2.1.0 documents always have a top-level `runs` array and a
	// top-level `version` string. JSONReport has neither at the top level.
	_, hasRuns := generic["runs"]
	_, hasVersion := generic["version"]
	return hasRuns && hasVersion
}
