package benchmark

import (
	"strings"
	"testing"
)

// TestEveryFPClassNamesItsMechanism is the taxonomy-honesty guard.
//
// The FP taxonomy is a public claim: BENCHMARKS.md §5 prints a per-class table
// asserting each class was eliminated by a specific fix. Before v1.1's wiring
// pass two of those rows were not backed by reachable code — `test-fixture`
// (decision.DecideWithOptions was never called by the orchestrator) and
// `static-asset-context` (no scanner ever produced the tag). Both were still
// scored, labelled, and documented.
//
// A class with no mechanism is therefore not a cosmetic gap; it is a
// documentation claim the binary does not honour. This test makes that state
// unreachable.
func TestEveryFPClassNamesItsMechanism(t *testing.T) {
	for class := range validFPClasses {
		t.Run(string(class), func(t *testing.T) {
			mech := class.Mechanism()
			if strings.TrimSpace(mech) == "" {
				t.Fatalf("FP class %q has no enforcement mechanism recorded.\n"+
					"Either wire the behaviour and name the code in fpClassMechanism, or retire\n"+
					"the class — a taxonomy entry with no implementation makes BENCHMARKS.md\n"+
					"claim behaviour the binary does not have.", class)
			}
			// The pointer has to be followable, not prose.
			if !strings.Contains(mech, "/") && !strings.Contains(mech, ".") {
				t.Errorf("FP class %q mechanism %q does not name a file or symbol", class, mech)
			}
		})
	}
}

// TestNoOrphanMechanisms is the reverse direction: a mechanism entry for a
// class that is not in the taxonomy means the two drifted apart.
func TestNoOrphanMechanisms(t *testing.T) {
	for class := range fpClassMechanism {
		if !class.Valid() {
			t.Errorf("fpClassMechanism names %q, which is not a valid FPClass", class)
		}
	}
	if len(fpClassMechanism) != len(validFPClasses) {
		t.Errorf("mechanism count %d != taxonomy count %d", len(fpClassMechanism), len(validFPClasses))
	}
}

// TestUnknownFPClassHasNoMechanism keeps Mechanism() honest for junk input.
func TestUnknownFPClassHasNoMechanism(t *testing.T) {
	if got := FPClass("made-up").Mechanism(); got != "" {
		t.Errorf(`FPClass("made-up").Mechanism() = %q, want ""`, got)
	}
}
