package decision

import (
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
