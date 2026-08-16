package engine

import (
	"sort"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// These tests are the regression gate for the "three dead confidence rules"
// defect: confidence.Score reads Payload/Response, ResponseContext and Lineage,
// but the orchestrator scored the ALREADY-PROJECTED models.Finding, and the
// Evidence→Finding projection drops all three. The B4 HTTP-response-context
// feature therefore never fired in production, and a non-correlated whitebox
// finding was capped at 35+10+10+5 = 60 — below the HIGH band's 70.
//
// The fix carries the internal provenance across the projection in an
// evidence.ProvenanceIndex; these tests assert it survives every finalization
// step that runs between the projection and scoring.

func header4xxEvidence(endpoint string) evidence.Evidence {
	return evidence.Evidence{
		Title:           "Missing Content-Security-Policy header",
		Category:        "headers",
		Endpoint:        endpoint,
		Severity:        models.SeverityMedium,
		Source:          models.SourceBlackbox,
		Confidence:      models.ConfidenceMedium,
		Evidence:        "no Content-Security-Policy header on the response",
		Fix:             "Set a Content-Security-Policy header",
		ResponseContext: "4xx",
	}
}

// TestStampDecisionsAppliesHTTPContextPenalty is the direct defect gate: a
// finding tagged with the B4 4xx context must score LOWER than the same
// finding without the tag, and must say so in its reasons.
func TestStampDecisionsAppliesHTTPContextPenalty(t *testing.T) {
	tagged := []evidence.Evidence{header4xxEvidence("GET /admin")}
	untagged := []evidence.Evidence{header4xxEvidence("GET /admin")}
	untagged[0].ResponseContext = ""

	taggedF := evidence.ToFindings(tagged)
	stampDecisions(taggedF, evidence.NewProvenanceIndex(tagged), "")

	untaggedF := evidence.ToFindings(untagged)
	stampDecisions(untaggedF, evidence.NewProvenanceIndex(untagged), "")

	if taggedF[0].ConfidenceScore >= untaggedF[0].ConfidenceScore {
		t.Errorf("4xx-context finding scored %d, want lower than the untagged %d — the B4 penalty did not reach the finding",
			taggedF[0].ConfidenceScore, untaggedF[0].ConfidenceScore)
	}
	if got, want := untaggedF[0].ConfidenceScore-taggedF[0].ConfidenceScore, 15; got != want {
		t.Errorf("penalty was %d points, want %d", got, want)
	}
	if !strings.Contains(strings.Join(taggedF[0].ConfidenceReasons, "\n"), "4xx") {
		t.Errorf("no 4xx reason line on the finding: %v", taggedF[0].ConfidenceReasons)
	}
}

// TestStampDecisionsAwardsPayloadValidation covers the +10 payload-validated
// rule and its headline consequence: without it, a non-correlated whitebox
// finding tops out at 60 and the HIGH band (>=70) is unreachable without
// correlation, collapsing decisions.confirmed into a synonym for
// sources.correlated.
func TestStampDecisionsAwardsPayloadValidation(t *testing.T) {
	evid := []evidence.Evidence{{
		Title:      "SQL injection in user lookup",
		Category:   "injection",
		Endpoint:   "src/app.py:42",
		Severity:   models.SeverityCritical,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
		Reachable:  true,
		SourceTier: models.TierTreeSitter,
		Payload:    "id=1' OR '1'='1",
		Response:   "HTTP 500 — SQL syntax error near \"'\"",
	}}
	findings := evidence.ToFindings(evid)
	stampDecisions(findings, evidence.NewProvenanceIndex(evid), "")

	// base 35 + static 10 + reachable 10 + tree-sitter 5 + payload 10 = 70.
	if findings[0].ConfidenceScore != 70 {
		t.Errorf("ConfidenceScore = %d, want 70 (payload-validated bonus missing)", findings[0].ConfidenceScore)
	}
	if findings[0].ConfidenceBand != string(models.ConfidenceHigh) {
		t.Errorf("ConfidenceBand = %q, want HIGH — the HIGH band must be reachable without correlation",
			findings[0].ConfidenceBand)
	}
	if !strings.Contains(strings.Join(findings[0].ConfidenceReasons, "\n"), "active probe") {
		t.Errorf("no payload-validation reason line: %v", findings[0].ConfidenceReasons)
	}
	if findings[0].Source == models.SourceCorrelated {
		t.Fatal("guard: this case must stay non-correlated")
	}
}

// TestStampDecisionsRecordsLineage covers the third dead rule: the
// "evidence chain" reason line that explains what a correlated score merged
// from.
func TestStampDecisionsRecordsLineage(t *testing.T) {
	evid := []evidence.Evidence{{
		Title:    "SQL injection in user lookup",
		Category: "injection",
		Endpoint: "GET /api/users",
		Severity: models.SeverityCritical,
		Source:   models.SourceCorrelated,
		Lineage: []evidence.Evidence{
			{Source: models.SourceBlackbox, Category: "injection", Endpoint: "GET /api/users"},
			{Source: models.SourceWhitebox, Category: "injection", Endpoint: "src/app.py:42"},
		},
	}}
	findings := evidence.ToFindings(evid)
	stampDecisions(findings, evidence.NewProvenanceIndex(evid), "")

	joined := strings.Join(findings[0].ConfidenceReasons, "\n")
	if !strings.Contains(joined, "evidence chain") ||
		!strings.Contains(joined, "blackbox(injection)") ||
		!strings.Contains(joined, "whitebox(injection)") {
		t.Errorf("lineage trace missing from the finding's reasons:\n%s", joined)
	}
}

// TestProvenanceSurvivesFinalizationPipeline runs the real finalization steps
// that sit between the projection and scoring (escalate → dedup → consistency
// → sort → ID/fingerprint assignment) and asserts the provenance still lands
// on the right finding afterwards.
func TestProvenanceSurvivesFinalizationPipeline(t *testing.T) {
	evid := []evidence.Evidence{
		header4xxEvidence("GET /admin"),
		{
			Title:      "SQL injection in user lookup",
			Category:   "injection",
			Endpoint:   "src/app.py:42",
			Severity:   models.SeverityHigh,
			Source:     models.SourceWhitebox,
			Confidence: models.ConfidenceHigh,
			Reachable:  true,
			SourceTier: models.TierTreeSitter,
			Payload:    "id=1' OR '1'='1",
			Response:   "HTTP 500 — SQL syntax error",
		},
	}
	prov := evidence.NewProvenanceIndex(evid)

	findings := evidence.ToFindings(evid)
	findings = escalateNonCorrelatedReachable(findings)
	findings = Deduplicate(findings)
	findings = enforceConsistency(findings)
	sort.Slice(findings, func(i, j int) bool { return findings[i].Endpoint < findings[j].Endpoint })
	for i := range findings {
		findings[i].Fingerprint = models.Fingerprint(findings[i])
	}
	stampDecisions(findings, prov, "")

	byTitle := map[string]models.Finding{}
	for _, f := range findings {
		byTitle[f.Title] = f
	}
	hdr, ok := byTitle["Missing Content-Security-Policy header"]
	if !ok {
		t.Fatalf("header finding lost in finalization: %+v", findings)
	}
	if !strings.Contains(strings.Join(hdr.ConfidenceReasons, "\n"), "4xx") {
		t.Errorf("4xx penalty lost across finalization: %v", hdr.ConfidenceReasons)
	}
	sqli := byTitle["SQL injection in user lookup"]
	if !strings.Contains(strings.Join(sqli.ConfidenceReasons, "\n"), "active probe") {
		t.Errorf("payload bonus lost across finalization: %v", sqli.ConfidenceReasons)
	}
}

// TestDedupGroupOnlyPenalizedWhenEveryOccurrenceWas locks the merge rule for a
// deduped group: "Missing CSP × N endpoints" only keeps the de-escalation tag
// when EVERY endpoint in the group carried it. That mirrors the CORS scanner's
// own "only ever observed on a 4xx" rule, and it is order-independent so the
// score stays a pure function of the finding SET (F-L6).
func TestDedupGroupOnlyPenalizedWhenEveryOccurrenceWas(t *testing.T) {
	mixed := []evidence.Evidence{header4xxEvidence("GET /admin"), header4xxEvidence("GET /public")}
	mixed[1].ResponseContext = "" // this one fired on a real 2xx
	all4xx := []evidence.Evidence{header4xxEvidence("GET /admin"), header4xxEvidence("GET /public")}

	score := func(evid []evidence.Evidence) models.Finding {
		t.Helper()
		prov := evidence.NewProvenanceIndex(evid)
		findings := Deduplicate(evidence.ToFindings(evid))
		if len(findings) != 1 {
			t.Fatalf("expected the group to dedup to 1 finding, got %d", len(findings))
		}
		stampDecisions(findings, prov, "")
		return findings[0]
	}

	if r := score(mixed); strings.Contains(strings.Join(r.ConfidenceReasons, "\n"), "4xx") {
		t.Errorf("a group that also fired on a non-4xx endpoint must not be de-escalated: %v", r.ConfidenceReasons)
	}
	if r := score(all4xx); !strings.Contains(strings.Join(r.ConfidenceReasons, "\n"), "4xx") {
		t.Errorf("a group that only ever fired on 4xx must keep the penalty: %v", r.ConfidenceReasons)
	}

	// Order-independence: reversing the input must not change the verdict.
	rev := []evidence.Evidence{mixed[1], mixed[0]}
	if a, b := score(mixed).ConfidenceScore, score(rev).ConfidenceScore; a != b {
		t.Errorf("score depends on input order: %d vs %d", a, b)
	}
}

// TestCorrelateEvidencePreservesResponseContext locks the second half of the
// defect: CorrelateEvidence restored RuleID/Payload/Response/Lineage onto a
// pass-through result but silently dropped ResponseContext, so on a hybrid
// (BB+WB) scan the B4 tag died at the correlator even before the projection.
func TestCorrelateEvidencePreservesResponseContext(t *testing.T) {
	in := []evidence.Evidence{
		header4xxEvidence("GET /admin"),
		{
			Title:      "Hardcoded credential",
			Category:   "secrets",
			Endpoint:   "src/config.py:9",
			Severity:   models.SeverityHigh,
			Source:     models.SourceWhitebox,
			Confidence: models.ConfidenceHigh,
		},
	}
	out := CorrelateEvidence(in)

	var found bool
	for _, e := range out {
		if e.Title != "Missing Content-Security-Policy header" {
			continue
		}
		found = true
		if e.ResponseContext != "4xx" {
			t.Errorf("ResponseContext = %q after correlation, want %q", e.ResponseContext, "4xx")
		}
	}
	if !found {
		t.Fatalf("pass-through header finding missing from correlator output: %+v", out)
	}
}

// TestStampDecisionsKeepsStatusAndExitContract guards the parts of step 10.5
// that must NOT change: every finding gets a status, and the returned
// decisions line up index-for-index with the findings they were stamped onto
// (the exit code is derived from them).
func TestStampDecisionsKeepsStatusAndExitContract(t *testing.T) {
	evid := []evidence.Evidence{
		{Title: "A", Category: "headers", Endpoint: "GET /a", Severity: models.SeverityCritical, Source: models.SourceBlackbox},
		{Title: "B", Category: "headers", Endpoint: "GET /b", Severity: models.SeverityLow, Source: models.SourceBlackbox},
	}
	findings := evidence.ToFindings(evid)
	decisions := stampDecisions(findings, evidence.NewProvenanceIndex(evid), "HIGH")

	if len(decisions) != len(findings) {
		t.Fatalf("decisions/findings length mismatch: %d vs %d", len(decisions), len(findings))
	}
	for i := range findings {
		if findings[i].Status != string(decisions[i].Status) {
			t.Errorf("finding %d status %q != decision %q", i, findings[i].Status, decisions[i].Status)
		}
		if findings[i].Status == "" {
			t.Errorf("finding %d has no status", i)
		}
	}
	if findings[0].Status != "BLOCK" {
		t.Errorf("CRITICAL under --fail-on HIGH should BLOCK, got %q", findings[0].Status)
	}
	if findings[1].Status != "INFO" {
		t.Errorf("LOW should be INFO, got %q", findings[1].Status)
	}
}

// TestStampDecisionsEmptyInput — a scan with zero findings must not panic and
// must produce no decisions (exit 0).
func TestStampDecisionsEmptyInput(t *testing.T) {
	if got := stampDecisions(nil, nil, "HIGH"); len(got) != 0 {
		t.Errorf("stampDecisions(nil) = %v, want none", got)
	}
	if got := stampDecisions([]models.Finding{}, evidence.ProvenanceIndex{}, ""); len(got) != 0 {
		t.Errorf("stampDecisions(empty) = %v, want none", got)
	}
}
