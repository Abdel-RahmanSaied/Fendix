package models

import (
	"strings"
	"testing"
)

// The final invariant audit, executable rather than asserted in a document.
// Each subtest is one line of the audit, and the whole thing is the evidence
// behind the verdict on this branch.
//
// The properties that need volume (determinism, collision resistance) are
// proved over the generated corpus in fingerprint_property_test.go; this file
// states each invariant once, in the smallest form that can fail.
func TestFinalInvariantAudit(t *testing.T) {
	t.Run("same logical vulnerability survives irrelevant line movement", func(t *testing.T) {
		if Fingerprint(whiteboxSSRF("app/views.py", 100)) != Fingerprint(whiteboxSSRF("app/views.py", 4021)) {
			t.Error("identity moved with the line number")
		}
	})

	t.Run("different logical vulnerabilities do not collapse", func(t *testing.T) {
		a := whiteboxSSRF("app/views.py", 100)
		b := whiteboxSSRF("app/views.py", 100)
		b.TaintChain = []TaintLink{{File: "app/views.py", Line: 100, Expr: "urllib.request.urlopen(other)"}}
		if Fingerprint(a) == Fingerprint(b) {
			t.Error("two distinct operations share one identity")
		}
	})

	t.Run("fingerprint does not depend on title", func(t *testing.T) {
		a := whiteboxSSRF("app/views.py", 100)
		b := a
		b.Title = "Completely different words describing the same finding"
		if Fingerprint(a) != Fingerprint(b) {
			t.Error("retitling changed identity")
		}
	})

	t.Run("fingerprint does not depend on decision", func(t *testing.T) {
		a := whiteboxSSRF("app/views.py", 100)
		a.Status, a.DecisionReason, a.DecisionPolicy = "WARN", "no corroboration", "enforced"
		b := whiteboxSSRF("app/views.py", 100)
		b.Status, b.DecisionReason, b.DecisionPolicy = "BLOCK", "corroborated by active probe", "relaxed"
		b.PolicyOverride = true
		if Fingerprint(a) != Fingerprint(b) {
			t.Error("the decision changed identity")
		}
	})

	t.Run("fingerprint does not depend on confidence", func(t *testing.T) {
		a := whiteboxSSRF("app/views.py", 100)
		a.Confidence, a.ConfidenceScore, a.ConfidenceBand = ConfidenceLow, 20, "LOW"
		a.ConfidenceReasons = []string{"-30 placeholder"}
		b := whiteboxSSRF("app/views.py", 100)
		b.Confidence, b.ConfidenceScore, b.ConfidenceBand = ConfidenceHigh, 100, "HIGH"
		b.ConfidenceReasons = []string{"+35 base", "+30 deterministic"}
		if Fingerprint(a) != Fingerprint(b) {
			t.Error("confidence changed identity")
		}
	})

	t.Run("fingerprint does not expose secrets", func(t *testing.T) {
		const credential = "sk_live_51H8xQeLkdIwHu7ix0aBcDeFgHiJkLmNoPqRs"
		f := Finding{
			Category: "secrets", RuleID: "secrets/stripe-live-key", Source: SourceWhitebox,
			Endpoint: "config/settings.py:1",
			Evidence: `STRIPE_SECRET_KEY = "` + credential + `"`,
			Secret:   &SecretRef{Identifier: "STRIPE_SECRET_KEY", File: "config/settings.py"},
		}
		// The identity components are the exact strings that get hashed, so
		// inspecting them proves what the digest was built from — a digest
		// alone could only be checked for the literal, never for a derivation.
		for _, c := range identityComponents(f) {
			if strings.Contains(c, credential) || strings.Contains(c, credential[:12]) {
				t.Errorf("credential material in an identity component: %q", c)
			}
			if strings.Contains(c, "sha256:") {
				t.Errorf("a credential-derived digest reached an identity component: %q", c)
			}
		}
		// And changing only the credential must not move the digest.
		g := f
		g.Evidence = `STRIPE_SECRET_KEY = "sk_live_TOTALLYDIFFERENTVALUEHERE0000000000"`
		if Fingerprint(f) != Fingerprint(g) {
			t.Error("the fingerprint tracks the credential's bytes")
		}
	})

	t.Run("fingerprint generation is deterministic", func(t *testing.T) {
		f := whiteboxSSRF("app/views.py", 100)
		first := Fingerprint(f)
		for range 1000 {
			if Fingerprint(f) != first {
				t.Fatal("repeated calls disagreed")
			}
		}
	})

	t.Run("identity is versioned so v1 and v2 cannot be confused", func(t *testing.T) {
		if FingerprintAlgorithm != "fendix/v2" {
			t.Errorf("algorithm = %q", FingerprintAlgorithm)
		}
		f := whiteboxSSRF("app/views.py", 100)
		if Fingerprint(f) == FingerprintV1(f) {
			t.Error("v1 and v2 produced the same value for one finding")
		}
		// The algorithm name is IN the hashed input, so a future scheme cannot
		// collide with this one by reconstructing the same components.
		if got := identityComponents(f)[0]; got != "alg="+FingerprintAlgorithm {
			t.Errorf("the algorithm is not part of the hashed input: %q", got)
		}
	})

	t.Run("absent components cannot impersonate present ones", func(t *testing.T) {
		// Two findings whose components would concatenate identically without
		// labels and separators: one has file "a|b" and no symbol, the other
		// file "a" and symbol "b".
		a := Finding{Category: "injection", RuleID: "r", Source: SourceWhitebox,
			Endpoint: "a|b:1", Sink: "s"}
		b := Finding{Category: "injection", RuleID: "r", Source: SourceWhitebox,
			Endpoint: "a:1", Symbol: "b", Sink: "s"}
		if Fingerprint(a) == Fingerprint(b) {
			t.Error("component boundaries are forgeable")
		}
	})
}
