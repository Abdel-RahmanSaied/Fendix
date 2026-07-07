package decision

import (
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func ev(sev models.Severity) evidence.Evidence {
	return evidence.Evidence{Severity: sev, Confidence: models.ConfidenceHigh}
}

// legacyCheckFailOn replicates orchestrator.checkFailOn EXACTLY so the test
// is an independent oracle for the Decision-layer exit code.
func legacyCheckFailOn(sevs []models.Severity, failOn string) int {
	if failOn == "" {
		return 0
	}
	threshold := models.SeverityRank(models.Severity(failOn))
	if threshold == 0 {
		return 0
	}
	for _, s := range sevs {
		if models.SeverityRank(s) >= threshold {
			return 1
		}
	}
	return 0
}

// TestExitCodeMatchesLegacyCheckFailOn is the v0.22 contract lock: for every
// (findings, fail-on) combination, ExitCode(DecideAll(...)) must equal the
// legacy checkFailOn result — so wiring the Decision layer in later can't
// change the CLI exit code.
func TestExitCodeMatchesLegacyCheckFailOn(t *testing.T) {
	sevSets := [][]models.Severity{
		{},
		{models.SeverityInfo},
		{models.SeverityLow},
		{models.SeverityMedium},
		{models.SeverityHigh},
		{models.SeverityCritical},
		{models.SeverityLow, models.SeverityMedium},
		{models.SeverityInfo, models.SeverityHigh},
		{models.SeverityMedium, models.SeverityCritical},
	}
	failOns := []string{"", "MEDIUM", "HIGH", "CRITICAL", "INFO", "garbage"}

	for _, set := range sevSets {
		for _, fo := range failOns {
			evs := make([]evidence.Evidence, len(set))
			for i, s := range set {
				evs[i] = ev(s)
			}
			got := ExitCode(DecideAll(evs, fo))
			want := legacyCheckFailOn(set, fo)
			if got != want {
				t.Errorf("set=%v failOn=%q: ExitCode=%d, legacy checkFailOn=%d", set, fo, got, want)
			}
		}
	}
}

func TestDecideStatus(t *testing.T) {
	cases := []struct {
		sev    models.Severity
		failOn string
		want   Status
	}{
		{models.SeverityCritical, "HIGH", StatusBlock},
		{models.SeverityHigh, "HIGH", StatusBlock},
		{models.SeverityMedium, "HIGH", StatusWarn}, // below threshold but actionable
		{models.SeverityMedium, "", StatusWarn},     // no threshold → never block
		{models.SeverityCritical, "", StatusWarn},   // no threshold → not BLOCK even if critical
		{models.SeverityLow, "HIGH", StatusInfo},
		{models.SeverityInfo, "CRITICAL", StatusInfo},
		{models.SeverityCritical, "garbage", StatusWarn}, // invalid threshold → no block
	}
	for _, c := range cases {
		got := Decide(ev(c.sev), c.failOn).Status
		if got != c.want {
			t.Errorf("Decide(%s, %q).Status = %s, want %s", c.sev, c.failOn, got, c.want)
		}
	}
}

func TestDecideCarriesEvidenceAndConfidence(t *testing.T) {
	e := evidence.Evidence{Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium, Title: "x"}
	d := Decide(e, "HIGH")
	if d.Confidence != models.ConfidenceMedium {
		t.Errorf("confidence not carried: %v", d.Confidence)
	}
	if d.Evidence.Title != "x" {
		t.Errorf("supporting evidence not carried")
	}
	if d.Reason == "" {
		t.Error("decision should carry a reason")
	}
}

func TestDecideAllNil(t *testing.T) {
	if DecideAll(nil, "HIGH") != nil {
		t.Error("DecideAll(nil) should be nil")
	}
}

func TestDecidePopulatesConfidenceScore(t *testing.T) {
	// v0.23: every decision carries a deterministic score + reasons.
	d := Decide(evidence.Evidence{Source: models.SourceCorrelated, Reachable: true}, "HIGH")
	if d.Score.Value <= 0 {
		t.Errorf("decision has no confidence score: %+v", d.Score)
	}
	if len(d.Score.Reasons) == 0 {
		t.Error("decision score has no plain-text reasons (no black boxes)")
	}
}

// TestDecideDeescalatesTestFixtureToInfo is the B3 (test-fixture) gate: a
// finding in test/fixture code de-escalates to INFO (evidence preserved,
// Rule 3), config-overridable so a team that DOES want to gate on test-code
// findings can turn it off.
func TestDecideDeescalatesTestFixtureToInfo(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh,
		Endpoint: "app/tests/test_views.py:42",
		Category: "injection",
	}
	// Without a --fail-on threshold this HIGH finding is WARN; in a test path
	// it drops to INFO with an explanatory reason (evidence preserved).
	d := DecideWithOptions(ev, "", Options{DeescalateTests: true})
	if d.Status != StatusInfo {
		t.Errorf("test-fixture finding Status = %q, want INFO", d.Status)
	}
	if !strings.Contains(d.Reason, "test") {
		t.Errorf("reason should explain the de-escalation: %q", d.Reason)
	}
	// Disabling the rule keeps it WARN.
	d2 := DecideWithOptions(ev, "", Options{DeescalateTests: false})
	if d2.Status != StatusWarn {
		t.Errorf("with de-escalation off, Status = %q, want WARN", d2.Status)
	}
	// A non-test HIGH finding is unaffected even with de-escalation on.
	prod := evidence.Evidence{Severity: models.SeverityHigh, Endpoint: "app/views.py:10", Category: "injection"}
	if got := DecideWithOptions(prod, "", Options{DeescalateTests: true}); got.Status != StatusWarn {
		t.Errorf("non-test finding Status = %q, want WARN (unaffected)", got.Status)
	}
	// A BLOCK finding (at/above --fail-on) is NOT silently downgraded by the
	// test-path rule — de-escalation only touches WARN/INFO.
	if got := DecideWithOptions(ev, "HIGH", Options{DeescalateTests: true}); got.Status != StatusBlock {
		t.Errorf("test-fixture BLOCK finding Status = %q, want BLOCK (threshold wins)", got.Status)
	}
}
