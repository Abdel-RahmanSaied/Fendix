package decision

import (
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// depFinding is the shape a vulnerable-dependency finding has after the deps
// scanner and the confidence scorer: whitebox, HIGH producer confidence, which
// earns deterministicDetn and lands the base score at 75 (HIGH band).
func depFinding(a models.Applicability) evidence.Evidence {
	return evidence.Evidence{
		Title:         "Vulnerable dependency: django==5.2.16 (CVE-2026-15830)",
		Category:      "deps",
		Endpoint:      "requirements.txt",
		Severity:      models.SeverityHigh,
		Source:        models.SourceWhitebox,
		Confidence:    models.ConfidenceHigh,
		Applicability: a,
	}
}

var depEnforced = Options{EnforceConfidence: true, DeescalateTests: true}

// THE §5 CRITICAL CASE. A dependency finding with credible evidence that the
// vulnerable component is unused must NOT gate a build merely because its
// confidence band is HIGH. Before this, applicability moved the SCORE by ten
// points and the DECISION by nothing — the right outcome sometimes happened,
// but only as an accident of where the band boundary fell.
func TestEvidenceAgainstApplicabilityDoesNotBlockEvenAtHighBand(t *testing.T) {
	ev := depFinding(models.ApplicabilityEvidenceAgainst)
	// Push the score unambiguously into the HIGH band so the outcome cannot be
	// mistaken for the incidental band-boundary behaviour.
	ev.CrossToolCorroborated = true
	ev.CorroboratingTools = []string{"osv-scanner"}

	d := DecideWithOptions(ev, "HIGH", depEnforced)
	if d.Score.Band != models.ConfidenceHigh {
		t.Fatalf("fixture no longer reaches the HIGH band (score=%d band=%s); the test would "+
			"pass for the wrong reason", d.Score.Value, d.Score.Band)
	}
	if d.Status == StatusBlock {
		t.Errorf("Status = BLOCK despite credible evidence the vulnerable component is unused "+
			"(score=%d band=%s reason=%q)", d.Score.Value, d.Score.Band, d.Reason)
	}
	if !strings.Contains(d.Reason, "not applicable") && !strings.Contains(d.Reason, "applicab") {
		t.Errorf("Reason = %q, does not explain that applicability held it back", d.Reason)
	}
}

// The finding must remain VISIBLE and fully-evidenced — de-escalated, never
// suppressed (Rule 3).
func TestEvidenceAgainstApplicabilityPreservesTheFinding(t *testing.T) {
	ev := depFinding(models.ApplicabilityEvidenceAgainst)
	d := DecideWithOptions(ev, "HIGH", depEnforced)

	if d.Status == StatusIgnore {
		t.Error("the finding was suppressed; applicability must de-escalate, never delete")
	}
	if d.Evidence.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want HIGH unchanged — only enforcement moves", d.Evidence.Severity)
	}
	if d.Score.Value != DecideWithOptions(ev, "HIGH", Options{}).Score.Value {
		t.Error("the applicability gate changed the SCORE; it may only change STATUS")
	}
}

// Applicability UNKNOWN must behave exactly as before: normal dependency
// policy. "We did not evaluate" is not evidence of anything.
func TestUnknownApplicabilityUsesNormalDependencyPolicy(t *testing.T) {
	d := DecideWithOptions(depFinding(models.ApplicabilityUnknown), "HIGH", depEnforced)
	if d.Status != StatusBlock {
		t.Errorf("Status = %q, want BLOCK — an unevaluated dependency follows normal policy "+
			"(score=%d band=%s reason=%q)", d.Status, d.Score.Value, d.Score.Band, d.Reason)
	}
}

// The affected component IS imported: evidence FOR applicability. Must block.
func TestApplicableDependencyBlocks(t *testing.T) {
	d := DecideWithOptions(depFinding(models.ApplicabilityApplicable), "HIGH", depEnforced)
	if d.Status != StatusBlock {
		t.Errorf("Status = %q, want BLOCK — the vulnerable component is imported "+
			"(score=%d band=%s reason=%q)", d.Status, d.Score.Value, d.Score.Band, d.Reason)
	}
}

// The explicit operator override: a team that wants to gate on every vulnerable
// version regardless of applicability can say so, and the decision records it.
func TestBlockOnInapplicableOverrideRestoresBlocking(t *testing.T) {
	opts := depEnforced
	opts.BlockOnInapplicable = true

	d := DecideWithOptions(depFinding(models.ApplicabilityEvidenceAgainst), "HIGH", opts)
	if d.Status != StatusBlock {
		t.Errorf("Status = %q, want BLOCK under --block-on-inapplicable (reason=%q)", d.Status, d.Reason)
	}
}

// Applicability is scoped to dependency findings. A non-deps finding that
// somehow carries the field must not be affected by the dependency arm.
func TestApplicabilityOnlyGovernsDependencyFindings(t *testing.T) {
	ev := evidence.Evidence{
		Title: "Potential SSRF", Category: "injection", Endpoint: "app/views.py:674",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter,
		Reachable: true, Applicability: models.ApplicabilityEvidenceAgainst,
	}
	if d := DecideWithOptions(ev, "HIGH", depEnforced); d.Status != StatusBlock {
		t.Errorf("Status = %q, want BLOCK — a proven-reachable injection finding must not be "+
			"held back by a dependency-scoped concept (reason=%q)", d.Status, d.Reason)
	}
}
