package policy

import (
	"testing"
)

// scan.enforce_confidence is the committable half of the FIX-08 gate, admitted
// on the same grounds as deescalate_tests: "how much corroboration do we demand
// before failing a build?" is a team triage decision that belongs next to
// fail_on in .fendix.yaml, not only in a per-invocation flag.

func TestLoad_EnforceConfidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want *bool
	}{
		{"absent", "version: 1\n", nil},
		{"false", "version: 1\nscan:\n  enforce_confidence: false\n", boolPtr(false)},
		{"true", "version: 1\nscan:\n  enforce_confidence: true\n", boolPtr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Load(writePolicy(t, tc.body))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			var got *bool
			if p != nil && p.Scan != nil {
				got = p.Scan.EnforceConfidence
			}
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("expected the field to be absent, got %v", *got)
			case tc.want != nil && got == nil:
				t.Errorf("expected %v, got absent", *tc.want)
			case tc.want != nil && got != nil && *got != *tc.want:
				t.Errorf("enforce_confidence = %v, want %v", *got, *tc.want)
			}
		})
	}
}

// TestApplyTo_EnforceConfidenceRespectsCLIPrecedence locks the documented
// 3-level precedence: cobra default < policy file < explicit CLI flag.
func TestApplyTo_EnforceConfidenceRespectsCLIPrecedence(t *testing.T) {
	p := &Policy{Version: 1, Scan: &ScanSection{EnforceConfidence: boolPtr(false)}}

	t.Run("policy applies when the flag was not passed", func(t *testing.T) {
		captured := map[string]any{}
		if n := captureSetters(captured).Run(p, CLISet{}); n != 1 {
			t.Errorf("expected 1 field applied, got %d (captured: %v)", n, captured)
		}
		if captured["enforce-confidence"] != false {
			t.Errorf("enforce-confidence = %v, want false from the policy file", captured["enforce-confidence"])
		}
	})

	t.Run("explicit CLI flag wins over the policy", func(t *testing.T) {
		captured := map[string]any{}
		if n := captureSetters(captured).Run(p, CLISet{"enforce-confidence": true}); n != 0 {
			t.Errorf("expected 0 fields applied, got %d (captured: %v)", n, captured)
		}
		if _, ok := captured["enforce-confidence"]; ok {
			t.Error("policy overrode an explicitly-passed --enforce-confidence flag")
		}
	})
}

func TestApplyTo_EnforceConfidenceNilSetterIsSkipped(t *testing.T) {
	p := &Policy{Version: 1, Scan: &ScanSection{EnforceConfidence: boolPtr(true)}}
	if n := (ApplyTo{}).Run(p, CLISet{}); n != 0 {
		t.Errorf("expected 0 fields applied with no setters, got %d", n)
	}
}
