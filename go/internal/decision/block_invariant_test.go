package decision

import (
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// blockCapableCategories is every category that can currently reach CRITICAL or
// HIGH severity, i.e. every category that can meet a --fail-on threshold.
//
// Deliberately an explicit list rather than something derived: adding a category
// to the engine must be a conscious decision to bring it under this invariant,
// not something that happens silently.
var blockCapableCategories = []string{
	"auth_bypass", "auth", "injection", "secrets", "cors", "deps",
	"idor", "xss", "ssrf", "rate_limiting", "headers", "cookie", "iac",
	"redirect", "graphql", "exposure", "configleak",
}

// THE INVARIANT. No evidence may reach BLOCK without at least one corroborating
// signal, and no MEDIUM-band evidence may reach BLOCK without an INDEPENDENT
// one. Severity alone — which is a constant chosen by the scanner — must never
// be sufficient.
//
// This is the property the whole decision-integrity change exists to establish,
// so it is asserted across the full cross product rather than on hand-picked
// shapes. Any failure here is a real hole in the policy, not a test to relax.
func TestNoBlockWithoutCorroboration(t *testing.T) {
	severities := []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	}
	sources := []models.Source{
		models.SourceBlackbox, models.SourceWhitebox,
		models.SourceCorrelated, models.SourceImported,
	}
	confidences := []models.Confidence{
		models.ConfidenceHigh, models.ConfidenceMedium, models.ConfidenceLow,
	}
	tiers := []models.SourceTier{
		"", models.TierNativeGo, models.TierTreeSitter, models.TierSemgrepShim,
	}
	failOns := []string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	opts := Options{EnforceConfidence: true, DeescalateTests: true}

	checked := 0
	for _, cat := range blockCapableCategories {
		for _, sev := range severities {
			for _, src := range sources {
				for _, conf := range confidences {
					for _, tier := range tiers {
						for _, failOn := range failOns {
							ev := evidence.Evidence{
								Title:      "synthetic " + cat,
								Category:   cat,
								Severity:   sev,
								Source:     src,
								Confidence: conf,
								SourceTier: tier,
								Endpoint:   "GET /synthetic",
							}
							d := DecideWithOptions(ev, failOn, opts)
							checked++
							if d.Status != StatusBlock {
								continue
							}
							if !d.Corroboration.Any() {
								t.Errorf("BLOCK with NO corroborating signal at all: "+
									"category=%s severity=%s source=%s confidence=%s tier=%q failOn=%s "+
									"score=%d band=%s reason=%q",
									cat, sev, src, conf, tier, failOn,
									d.Score.Value, d.Score.Band, d.Reason)
							}
							if d.Score.Band == models.ConfidenceMedium &&
								len(d.Corroboration.Independent) == 0 {
								t.Errorf("MEDIUM-band BLOCK with no INDEPENDENT signal: "+
									"category=%s severity=%s source=%s confidence=%s tier=%q failOn=%s "+
									"score=%d self_evident=%v reason=%q",
									cat, sev, src, conf, tier, failOn,
									d.Score.Value, d.Corroboration.SelfEvident, d.Reason)
							}
						}
					}
				}
			}
		}
	}
	t.Logf("checked %d evidence shapes", checked)
}

// The converse guard. A gate nobody can trip is not a fix, it is a removal —
// so at least one realistic shape per confirmation mechanism must still BLOCK.
// If Task 1's narrowing had gone too far, this is what would have caught it.
func TestConfirmedFindingsStillBlock(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	cases := map[string]evidence.Evidence{
		"reachable taint path": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter, Reachable: true,
		},
		"cross-engine agreement": {
			Category: "secrets", Severity: models.SeverityHigh, Source: models.SourceCorrelated,
			Confidence: models.ConfidenceHigh,
		},
		"contradicted auth requirement": {
			Category: "auth_bypass", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, AuthExpectation: models.AuthExpectationRequired,
		},
		"payload-validated probe": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh,
			Payload:    "' OR 1=1--", Response: "You have an error in your SQL syntax",
		},
		"cross-tool corroboration": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceImported,
			Confidence:            models.ConfidenceHigh,
			CrossToolCorroborated: true, CorroboratingTools: []string{"codeql"},
		},
		// The code-only-scan case deterministicDetn exists for: a REAL
		// hardcoded credential in production source, where no second
		// observation is possible even in principle.
		"deterministic detection in production source": {
			Category: "secrets", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Confidence: models.ConfidenceHigh, SourceTier: models.TierNativeGo,
		},
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			ev.Title, ev.Endpoint = name, "GET /x"
			d := DecideWithOptions(ev, "HIGH", opts)
			if d.Status != StatusBlock {
				t.Errorf("Status = %q, want BLOCK (score=%d band=%s independent=%v self_evident=%v reason=%q)",
					d.Status, d.Score.Value, d.Score.Band,
					d.Corroboration.Independent, d.Corroboration.SelfEvident, d.Reason)
			}
		})
	}
}

// Every BLOCK must be EXPLAINABLE: the reason must name what corroborated it,
// so the exported justification is never an empty assertion.
func TestEveryBlockNamesItsCorroboration(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	shapes := []evidence.Evidence{
		{Category: "injection", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter, Reachable: true},
		{Category: "auth_bypass", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, AuthExpectation: models.AuthExpectationRequired},
		{Category: "cors", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, DirectObservation: true},
	}
	for _, ev := range shapes {
		ev.Title, ev.Endpoint = "shape "+ev.Category, "GET /x"
		d := DecideWithOptions(ev, "HIGH", opts)
		if d.Status != StatusBlock {
			continue
		}
		if d.Reason == "" {
			t.Errorf("%s: BLOCK with an empty reason", ev.Category)
		}
		if !d.Corroboration.Any() {
			t.Errorf("%s: BLOCK whose reason cites nothing", ev.Category)
		}
	}
}

// Determinism: the same evidence must always yield the same verdict, reason,
// score and signal lists. A map iteration or a time-dependent rule anywhere in
// this path would surface here.
func TestDecisionIsDeterministic(t *testing.T) {
	ev := evidence.Evidence{
		Title: "determinism probe", Category: "injection", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		SourceTier: models.TierTreeSitter, Reachable: true, ProvenPath: true,
		RouteConfirmed: true, Endpoint: "app/x.py:1",
	}
	opts := Options{EnforceConfidence: true, DeescalateTests: true}

	first := DecideWithOptions(ev, "HIGH", opts)
	for i := 0; i < 200; i++ {
		got := DecideWithOptions(ev, "HIGH", opts)
		if got.Status != first.Status || got.Reason != first.Reason ||
			got.Score.Value != first.Score.Value || got.Score.Band != first.Score.Band {
			t.Fatalf("iteration %d diverged on verdict:\n got=%+v\nwant=%+v", i, got, first)
		}
		if len(got.Corroboration.Independent) != len(first.Corroboration.Independent) ||
			len(got.Corroboration.SelfEvident) != len(first.Corroboration.SelfEvident) {
			t.Fatalf("iteration %d diverged on signals: %+v vs %+v",
				i, got.Corroboration, first.Corroboration)
		}
		for j := range got.Corroboration.Independent {
			if got.Corroboration.Independent[j] != first.Corroboration.Independent[j] {
				t.Fatalf("iteration %d: signal order changed at %d", i, j)
			}
		}
	}
}

// The escape hatch must remain byte-for-byte legacy: with EnforceConfidence
// off, corroboration is ignored entirely and severity alone decides. Teams
// pinned to the old policy must be able to keep it.
func TestLegacyPolicyIgnoresCorroborationEntirely(t *testing.T) {
	bare := evidence.Evidence{
		Title: "bare blackbox", Category: "auth_bypass", Endpoint: "GET /status",
		Severity: models.SeverityCritical, Source: models.SourceBlackbox,
		Confidence: models.ConfidenceMedium,
	}
	if got := DecideWithOptions(bare, "HIGH", Options{EnforceConfidence: true}); got.Status != StatusWarn {
		t.Errorf("shipped policy Status = %q, want WARN", got.Status)
	}
	if got := DecideWithOptions(bare, "HIGH", Options{}); got.Status != StatusBlock {
		t.Errorf("legacy policy Status = %q, want BLOCK — --enforce-confidence=false must restore it", got.Status)
	}
}
