package scanner

import (
	"strings"
	"testing"
)

// ProbeExcerpt bounds and sanitizes what an active probe stores on
// Evidence.Response. The excerpt feeds confidence.payloadValidated and the
// decision layer's "payload-validated probe" independent signal, so it must be
// deterministic: the same body always yields the same excerpt, or the same scan
// would produce different confidence scores on different runs.
func TestProbeExcerptIsBoundedSanitizedAndDeterministic(t *testing.T) {
	t.Run("bounds oversized bodies", func(t *testing.T) {
		got := ProbeExcerpt(strings.Repeat("A", probeResponseLimit*3))
		if len(got) != probeResponseLimit {
			t.Errorf("len = %d, want %d", len(got), probeResponseLimit)
		}
	})

	t.Run("strips control characters", func(t *testing.T) {
		got := ProbeExcerpt("SQL error\x00near\x07 'x'")
		if strings.ContainsAny(got, "\x00\x07") {
			t.Errorf("ProbeExcerpt = %q, still carries control bytes", got)
		}
		if !strings.Contains(got, "SQL error") {
			t.Errorf("ProbeExcerpt = %q, dropped the signal along with the noise", got)
		}
	})

	t.Run("folds newlines and tabs to spaces", func(t *testing.T) {
		got := ProbeExcerpt("line one\nline two\tend")
		if strings.ContainsAny(got, "\n\t") {
			t.Errorf("ProbeExcerpt = %q, want newlines/tabs folded", got)
		}
		if !strings.Contains(got, "line one line two end") {
			t.Errorf("ProbeExcerpt = %q, want the words preserved", got)
		}
	})

	t.Run("is deterministic", func(t *testing.T) {
		body := "You have an error in your SQL syntax near '\x01'"
		first := ProbeExcerpt(body)
		for i := 0; i < 100; i++ {
			if got := ProbeExcerpt(body); got != first {
				t.Fatalf("iteration %d: %q != %q", i, got, first)
			}
		}
	})

	t.Run("empty stays empty", func(t *testing.T) {
		if got := ProbeExcerpt(""); got != "" {
			t.Errorf("ProbeExcerpt(\"\") = %q, want empty — absence must not become a value", got)
		}
	})
}

// The corroboration contract: an active-probe finding must record BOTH what it
// SENT and what came BACK.
//
// Before this change NEITHER was recorded on production evidence. Every
// `Payload:` site in the scanner package populated a ProbeRecord (the audit
// log), not an ev.Evidence — so confidence.payloadValidated, which requires
// both, could never fire, and its own doc comment ("every active-probe scanner
// sets Payload, none sets Response") was wrong in both halves.
//
// That mattered because the decision layer had been substituting a tautology
// ("Source is blackbox") for this signal. With the tautology gone (RC-1), these
// findings gate on the real differential or not at all.
//
// This drives the PRODUCTION entry points against fixtures that make each check
// fire, so it observes what the scanners actually emit.
func TestActiveProbeEvidenceAlwaysPairsPayloadWithResponse(t *testing.T) {
	for _, tc := range activeProbeCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.run()
			if len(got) == 0 {
				t.Fatalf("%s produced no evidence; the fixture no longer triggers it", tc.name)
			}
			for _, e := range got {
				if e.Payload == "" {
					t.Errorf("%q: Payload is empty — an active probe must record what it sent", e.Title)
				}
				if e.Response == "" {
					t.Errorf("%q: Response is empty — payloadValidated can never fire "+
						"and this finding cannot gate", e.Title)
				}
				if len(e.Response) > probeResponseLimit {
					t.Errorf("%q: Response is %d bytes, want <= %d",
						e.Title, len(e.Response), probeResponseLimit)
				}
			}
		})
	}
}
