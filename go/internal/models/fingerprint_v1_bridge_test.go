package models

import "testing"

// The v1 → v2 identity move re-keys every finding. Consumers that tracked a
// finding under v1 (a backend Issue, a saved baseline, a `.fendix-ignore`
// fingerprint: rule) cannot recognise the v2 key, so without a published
// bridge the same vulnerability reads as "the old one vanished, here is a new
// one" — which is exactly what the backend saw as duplicate Issues.
//
// Publishing the retired key alongside the canonical one makes the mapping
// deterministic and computed by the side that owns both algorithms, instead of
// being re-derived (and eventually drifting) downstream.
func TestFingerprintV1IsStableAndIndependentOfV2(t *testing.T) {
	f := Finding{
		Category: "injection",
		Endpoint: "app/db.py:42",
		Title:    "SQL injection",
		RuleID:   "python.sqli.taint",
	}

	v1 := FingerprintV1(f)
	if v1 == "" {
		t.Fatal("v1 fingerprint must be computable for bridging")
	}
	if v1 == Fingerprint(f) {
		t.Fatal("v1 and v2 must be different namespaces; an equal value would hide the transition")
	}

	// Deterministic across calls — the bridge is only usable if it is stable.
	if FingerprintV1(f) != v1 {
		t.Fatal("v1 fingerprint is not deterministic")
	}
}

// v1 hashed Category|Endpoint|Title, and for whitebox findings Endpoint
// carries the line number. That line-sensitivity is the reason v2 exists; the
// bridge inherits it, so it can only adopt a row whose recorded v1 key came
// from the same location. That is a deliberate limit, and pinning it here
// stops anyone "fixing" the bridge into a fuzzy match later.
func TestFingerprintV1MovesWithTheLineNumber(t *testing.T) {
	at42 := Finding{Category: "injection", Endpoint: "app/db.py:42", Title: "SQL injection"}
	at43 := Finding{Category: "injection", Endpoint: "app/db.py:43", Title: "SQL injection"}

	if FingerprintV1(at42) == FingerprintV1(at43) {
		t.Fatal("v1 was line-sensitive; the bridge must not pretend otherwise")
	}
	if Fingerprint(at42) != Fingerprint(at43) {
		t.Fatal("v2 identity must survive a line move — that is the whole point of the scheme")
	}
}

// StampIdentity is what the orchestrator calls; it must set BOTH keys so the
// report carries the bridge without the orchestrator having to know why.
func TestStampIdentitySetsBothKeys(t *testing.T) {
	f := Finding{Category: "injection", Endpoint: "app/db.py:42", Title: "SQL injection"}
	StampIdentity(&f)

	if f.Fingerprint != Fingerprint(f) {
		t.Fatalf("canonical fingerprint not stamped: %q", f.Fingerprint)
	}
	if f.FingerprintV1 != FingerprintV1(f) {
		t.Fatalf("bridge key not stamped: %q", f.FingerprintV1)
	}
	if f.Fingerprint == f.FingerprintV1 {
		t.Fatal("the two keys must differ")
	}
}
