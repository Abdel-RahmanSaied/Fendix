package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// scan.deescalate_tests is the committable half of the B3 test-fixture policy:
// "do we gate on test-code findings?" is a team triage decision, so it belongs
// in .fendix.yaml alongside fail_on, not only in a per-invocation flag.

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".fendix.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestLoad_DeescalateTests(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want *bool
	}{
		{"absent", "version: 1\n", nil},
		{"false", "version: 1\nscan:\n  deescalate_tests: false\n", boolPtr(false)},
		{"true", "version: 1\nscan:\n  deescalate_tests: true\n", boolPtr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Load(writePolicy(t, tc.body))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			var got *bool
			if p != nil && p.Scan != nil {
				got = p.Scan.DeescalateTests
			}
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("expected the field to be absent, got %v", *got)
			case tc.want != nil && got == nil:
				t.Errorf("expected %v, got absent", *tc.want)
			case tc.want != nil && got != nil && *got != *tc.want:
				t.Errorf("deescalate_tests = %v, want %v", *got, *tc.want)
			}
		})
	}
}

// TestApplyTo_DeescalateTestsRespectsCLIPrecedence locks the documented
// 3-level precedence: cobra default < policy file < explicit CLI flag.
func TestApplyTo_DeescalateTestsRespectsCLIPrecedence(t *testing.T) {
	p := &Policy{Version: 1, Scan: &ScanSection{DeescalateTests: boolPtr(false)}}

	t.Run("policy applies when the flag was not passed", func(t *testing.T) {
		captured := map[string]any{}
		if n := captureSetters(captured).Run(p, CLISet{}); n != 1 {
			t.Errorf("expected 1 field applied, got %d (captured: %v)", n, captured)
		}
		if captured["deescalate-tests"] != false {
			t.Errorf("deescalate-tests = %v, want false from the policy file", captured["deescalate-tests"])
		}
	})

	t.Run("explicit CLI flag wins over the policy", func(t *testing.T) {
		captured := map[string]any{}
		if n := captureSetters(captured).Run(p, CLISet{"deescalate-tests": true}); n != 0 {
			t.Errorf("expected 0 fields applied, got %d (captured: %v)", n, captured)
		}
		if _, ok := captured["deescalate-tests"]; ok {
			t.Error("policy overrode an explicitly-passed --deescalate-tests flag")
		}
	})
}

func TestApplyTo_DeescalateTestsNilSetterIsSkipped(t *testing.T) {
	p := &Policy{Version: 1, Scan: &ScanSection{DeescalateTests: boolPtr(true)}}
	if n := (ApplyTo{}).Run(p, CLISet{}); n != 0 {
		t.Errorf("expected 0 fields applied with no setters, got %d", n)
	}
}

func boolPtr(b bool) *bool { return &b }
