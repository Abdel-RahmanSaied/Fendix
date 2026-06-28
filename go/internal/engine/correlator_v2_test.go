package engine

import (
	"reflect"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// sampleFindingSets returns fresh finding slices each call (no shared backing
// arrays / pointers) so the two correlation pipelines under test can't alias.
func sampleFindingSets() [][]models.Finding {
	return [][]models.Finding{
		// pass-through only (no whitebox)
		{
			{Source: models.SourceBlackbox, Category: "headers", Title: "Missing CSP", Endpoint: "/", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh},
		},
		// a BB+WB injection pair that exercises the merge path
		{
			{Source: models.SourceBlackbox, Category: "injection", Title: "SQL injection", Endpoint: "/api/users", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Evidence: "param id"},
			{Source: models.SourceWhitebox, Category: "injection", Title: "SQL injection", Endpoint: "/api/users", Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium, Reachable: true, Evidence: "cursor.execute"},
		},
		// mixed pass-through + unmatched whitebox
		{
			{Source: models.SourceBlackbox, Category: "headers", Title: "Missing HSTS", Endpoint: "/", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh},
			{Source: models.SourceWhitebox, Category: "secrets", Title: "Hardcoded key", Endpoint: "config.py:3", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh},
		},
	}
}

// TestCorrelateEvidence_RenderIdenticalToLegacy is the E3 contract lock: the
// rendered projection of Correlation V2 must equal the legacy Correlate()
// output for every input — so routing the orchestrator through the Evidence
// layer cannot change the public findings.
func TestCorrelateEvidence_RenderIdenticalToLegacy(t *testing.T) {
	for i := range sampleFindingSets() {
		want := Correlate(sampleFindingSets()[i])
		got := evidence.ToFindings(CorrelateEvidence(evidence.FromFindings(sampleFindingSets()[i])))
		if !reflect.DeepEqual(want, got) {
			t.Errorf("set %d: CorrelateEvidence render differs from legacy Correlate\n want=%+v\n got =%+v", i, want, got)
		}
	}
}

// TestCorrelateEvidence_PreservesPassThroughProvenance confirms provenance the
// Finding can't carry survives correlation for an unchanged pass-through.
func TestCorrelateEvidence_PreservesPassThroughProvenance(t *testing.T) {
	in := []evidence.Evidence{{
		Source: models.SourceBlackbox, Category: "headers", Title: "Missing CSP",
		Endpoint: "/", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
		RuleID: "dast.headers.csp", Payload: "GET /", Response: "200 OK",
		Metadata: map[string]string{"check": "headers"},
	}}
	out := CorrelateEvidence(in)
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if out[0].RuleID != "dast.headers.csp" || out[0].Payload != "GET /" || out[0].Response != "200 OK" {
		t.Errorf("pass-through provenance not preserved: %+v", out[0])
	}
	if out[0].Metadata["check"] != "headers" {
		t.Errorf("metadata not preserved: %+v", out[0].Metadata)
	}
}
