package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The --deescalate-tests flag is the last hop of the B3 wiring
// (CLI → ScanConfig → orchestrator → stampDecisions → decision.DecideWithOptions).
// These tests cover the CLI end: the flag exists, defaults to ON, and is
// documented — the orchestrator-side wiring is covered by the pipeline tests in
// internal/engine.

func TestDeescalateTestsFlagDefaultsToOn(t *testing.T) {
	scan := newScanCmd()
	f := scan.Flags().Lookup("deescalate-tests")
	if f == nil {
		t.Fatal("scan has no --deescalate-tests flag; the B3 policy is unreachable from the CLI")
	}
	if f.DefValue != "true" {
		t.Errorf("--deescalate-tests default = %q, want \"true\" — BENCHMARKS.md documents the\n"+
			"test-fixture demotion as shipped behaviour, so the flag must default ON", f.DefValue)
	}
	if f.Value.Type() != "bool" {
		t.Errorf("--deescalate-tests type = %q, want bool", f.Value.Type())
	}
}

func TestDeescalateTestsFlagIsDocumented(t *testing.T) {
	f := newScanCmd().Flags().Lookup("deescalate-tests")
	if f == nil {
		t.Fatal("missing --deescalate-tests flag")
	}
	for _, want := range []string{"test", "INFO"} {
		if !strings.Contains(f.Usage, want) {
			t.Errorf("--deescalate-tests usage should mention %q: %q", want, f.Usage)
		}
	}
	// The safety carve-out must be discoverable from --help: a team that gates
	// on --fail-on needs to know the demotion cannot disarm their gate.
	if !strings.Contains(strings.ToLower(f.Usage), "fail-on") {
		t.Errorf("--deescalate-tests usage should state that --fail-on still blocks: %q", f.Usage)
	}
}

// TestDeescalateTestsFlagReachesScanConfig closes the CLI -> ScanConfig hop by
// running the REAL scan command and reading the emitted report.
//
// A mutation audit showed that inverting main.go's
// `DeescalateTests: deescalateTestsFlag` left the entire suite green: the flag
// existed, the orchestrator consumed a ScanConfig field, but nothing observed
// the two being connected. Only an end-to-end assertion on the produced JSON
// catches a mis-wired assignment.
func TestDeescalateTestsFlagReachesScanConfig(t *testing.T) {
	code := t.TempDir()
	if err := os.MkdirAll(filepath.Join(code, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A hardcoded credential the native (Python-free) secrets scanner detects,
	// in a test-path file.
	secret := "api_key = \"" + strings.Repeat("A", 32) + "\"\n"
	if err := os.WriteFile(filepath.Join(code, "tests", "test_conf.py"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, args ...string) []map[string]any {
		t.Helper()
		out := filepath.Join(t.TempDir(), "report.json")
		root := newRootCmd()
		base := []string{
			"scan", "--code", code, "--format", "json", "--output", out,
			// --fast keeps this hermetic: native scanners only, no semgrep
			// subprocess and no dep-CVE network calls.
			"--fast", "--python-engine=false", "--no-plugins",
		}
		root.SetArgs(append(base, args...))
		root.SetOut(new(strings.Builder))
		root.SetErr(new(strings.Builder))
		if err := root.Execute(); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("reading report: %v", err)
		}
		var rep struct {
			Findings []map[string]any `json:"findings"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("parsing report: %v\n%s", err, raw)
		}
		if len(rep.Findings) == 0 {
			t.Fatal("no findings produced — the fixture secret was not detected")
		}
		return rep.Findings
	}

	t.Run("default (flag omitted) de-escalates", func(t *testing.T) {
		for _, f := range run(t) {
			if f["status"] != "INFO" {
				t.Errorf("finding %v status = %v, want INFO by default", f["endpoint"], f["status"])
			}
		}
	})

	t.Run("--deescalate-tests=false does not", func(t *testing.T) {
		var sawWarn bool
		for _, f := range run(t, "--deescalate-tests=false") {
			if f["status"] == "WARN" {
				sawWarn = true
			}
			if f["status"] == "INFO" && f["severity"] != "LOW" && f["severity"] != "INFO" {
				t.Errorf("finding %v is INFO with --deescalate-tests=false: %v", f["endpoint"], f)
			}
		}
		if !sawWarn {
			t.Error("expected at least one WARN with --deescalate-tests=false")
		}
	})
}

// TestDeescalateTestsFlagIsOverridable proves the opt-out parses; a bool flag
// with a true default is only useful if `=false` works.
func TestDeescalateTestsFlagIsOverridable(t *testing.T) {
	scan := newScanCmd()
	if err := scan.Flags().Parse([]string{"--deescalate-tests=false"}); err != nil {
		t.Fatalf("parsing --deescalate-tests=false: %v", err)
	}
	got, err := scan.Flags().GetBool("deescalate-tests")
	if err != nil {
		t.Fatalf("GetBool: %v", err)
	}
	if got {
		t.Error("--deescalate-tests=false did not turn the policy off")
	}
	if !scan.Flags().Changed("deescalate-tests") {
		t.Error("flags.Changed(\"deescalate-tests\") = false; policy precedence relies on it")
	}
}
