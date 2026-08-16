package confidence

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestScoreDeterministic(t *testing.T) {
	ev := evidence.Evidence{Source: models.SourceCorrelated, Reachable: true, RouteConfirmed: true}
	a := Score(ev)
	b := Score(ev)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Score is not deterministic:\n a=%+v\n b=%+v", a, b)
	}
}

func TestScoreBlackboxOnlyIsModest(t *testing.T) {
	// A blackbox-only finding: base(35) + runtime(10) = 45 → MEDIUM.
	got := Score(evidence.Evidence{Source: models.SourceBlackbox})
	if got.Value != base+runtimeEvidence {
		t.Errorf("blackbox-only Value = %d, want %d", got.Value, base+runtimeEvidence)
	}
	if got.Band != models.ConfidenceMedium {
		t.Errorf("blackbox-only Band = %q, want MEDIUM", got.Band)
	}
}

func TestScoreCorrelatedProvenPathIsHigh(t *testing.T) {
	ev := evidence.Evidence{
		Source:         models.SourceCorrelated,
		RouteConfirmed: true,
		Reachable:      true,
		ProvenPath:     true,
		SourceTier:     models.TierTreeSitter,
		Payload:        "id=1' OR '1'='1",
		Response:       "HTTP 500 SQL syntax error",
	}
	got := Score(ev)
	// 35+10+10+25+10+10+5+10+5 = 120, clamped to 100.
	if got.Value != 100 {
		t.Errorf("fully-corroborated Value = %d, want 100 (clamped)", got.Value)
	}
	if got.Band != models.ConfidenceHigh {
		t.Errorf("Band = %q, want HIGH", got.Band)
	}
	joined := strings.Join(got.Reasons, "\n")
	for _, want := range []string{"cross-engine agreement", "reachable", "live request", "active probe"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reasons missing %q:\n%s", want, joined)
		}
	}
}

func TestSemgrepTierPenalty(t *testing.T) {
	withTier := Score(evidence.Evidence{Source: models.SourceWhitebox, SourceTier: models.TierSemgrepShim})
	noTier := Score(evidence.Evidence{Source: models.SourceWhitebox})
	if withTier.Value != noTier.Value+tierSemgrepPenalty {
		t.Errorf("semgrep penalty not applied: withTier=%d noTier=%d", withTier.Value, noTier.Value)
	}
	if !strings.Contains(strings.Join(withTier.Reasons, "\n"), "lower-trust") {
		t.Error("semgrep penalty reason missing")
	}
}

func TestBandThresholds(t *testing.T) {
	cases := []struct {
		score int
		want  models.Confidence
	}{
		{100, models.ConfidenceHigh},
		{70, models.ConfidenceHigh},
		{69, models.ConfidenceMedium},
		{40, models.ConfidenceMedium},
		{39, models.ConfidenceLow},
		{0, models.ConfidenceLow},
	}
	for _, c := range cases {
		if got := bandFor(c.score); got != c.want {
			t.Errorf("bandFor(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestEveryRuleAddsAReason(t *testing.T) {
	// A reason line per contribution + the base line. The "no black boxes"
	// contract: the score must be fully accounted for by the reasons.
	got := Score(evidence.Evidence{Source: models.SourceCorrelated, Reachable: true})
	if len(got.Reasons) < 4 { // base + static + runtime + cross + reachable
		t.Errorf("expected a reason per contribution, got %d: %v", len(got.Reasons), got.Reasons)
	}
	if !strings.HasPrefix(got.Reasons[0], "+35 base") {
		t.Errorf("first reason should be the base: %q", got.Reasons[0])
	}
}

func TestLineageTrace(t *testing.T) {
	ev := evidence.Evidence{
		Source: models.SourceCorrelated,
		Lineage: []evidence.Evidence{
			{Source: models.SourceBlackbox, Category: "injection"},
			{Source: models.SourceWhitebox, Category: "injection"},
		},
	}
	got := Score(ev)
	joined := strings.Join(got.Reasons, "\n")
	if !strings.Contains(joined, "evidence chain") || !strings.Contains(joined, "blackbox(injection)") {
		t.Errorf("lineage trace missing from reasons:\n%s", joined)
	}
}

func TestClamp(t *testing.T) {
	if clamp(-5, 0, 100) != 0 || clamp(150, 0, 100) != 100 || clamp(50, 0, 100) != 50 {
		t.Error("clamp boundaries wrong")
	}
}

func BenchmarkScore(b *testing.B) {
	ev := evidence.Evidence{Source: models.SourceCorrelated, Reachable: true, RouteConfirmed: true, ProvenPath: true, SourceTier: models.TierTreeSitter}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Score(ev)
	}
}

// TestReasonsSumToValue is the "no black boxes" contract: the signed deltas in
// Reasons must reconstruct Value exactly, including the corroboration cap.
func TestReasonsSumToValue(t *testing.T) {
	cases := []evidence.Evidence{
		{Source: models.SourceBlackbox},
		{Source: models.SourceWhitebox, SourceTier: models.TierSemgrepShim},
		{Source: models.SourceCorrelated, RouteConfirmed: true, Reachable: true, ProvenPath: true, SourceTier: models.TierTreeSitter, Payload: "p", Response: "r"},
		// The B4 de-escalation deltas are negative — the sum must still land
		// exactly on Value.
		{Source: models.SourceBlackbox, ResponseContext: "4xx"},
		{Source: models.SourceBlackbox, Payload: "p", Response: "r", ResponseContext: "static-asset",
			Lineage: []evidence.Evidence{{Source: models.SourceBlackbox, Category: "headers"}}},
	}
	for _, ev := range cases {
		r := Score(ev)
		sum := 0
		for _, reason := range r.Reasons {
			var n int
			// each reason starts with a signed int like "+35 ..." / "-20 ..."
			if _, err := fmt.Sscanf(reason, "%d", &n); err == nil {
				sum += n
			}
		}
		if sum != r.Value {
			t.Errorf("reasons sum %d != Value %d for %+v\n%v", sum, r.Value, ev, r.Reasons)
		}
	}
}

// TestScore4xxContextPenalty / TestScoreStaticAssetPenalty are the B4 gates:
// a DAST finding that fired on a 4xx (auth-gated/client-error) response or a
// static-asset endpoint gets a confidence PENALTY (de-escalation, evidence
// preserved) rather than emit-time suppression.
func TestScore4xxContextPenalty(t *testing.T) {
	base := evidence.Evidence{Source: models.SourceBlackbox}
	ctx4xx := evidence.Evidence{Source: models.SourceBlackbox, ResponseContext: "4xx"}
	if Score(ctx4xx).Value >= Score(base).Value {
		t.Errorf("4xx context should lower confidence: base=%d 4xx=%d",
			Score(base).Value, Score(ctx4xx).Value)
	}
	found := false
	for _, r := range Score(ctx4xx).Reasons {
		if strings.Contains(r, "4xx") {
			found = true
		}
	}
	if !found {
		t.Error("expected a 4xx-context reason line")
	}
}

// TestScoringProvenanceSurvivesTheFindingProjection is the DRIFT GUARD for the
// wiring fix. Score is a pure function of Evidence, but the orchestrator can
// only hand it Evidence rebuilt from the projected models.Finding — a lossy
// shape — plus whatever evidence.ProvenanceIndex carries across that boundary.
//
// So: score the real Evidence, then score the same Evidence after a
// project → restore round trip, and require an identical Result. Every rule
// that reads an Evidence-internal field is covered by construction. Add a new
// scored internal field to evidence.Evidence without adding it to
// ScoringProvenance and this test goes red — which is exactly how the
// payload-validated / HTTP-context / lineage rules became dead code.
func TestScoringProvenanceSurvivesTheFindingProjection(t *testing.T) {
	ev := evidence.Evidence{
		Title:    "Missing Content-Security-Policy header",
		Category: "headers",
		Endpoint: "GET /assets/app.js",
		Severity: models.SeverityMedium,
		Source:   models.SourceBlackbox,
		// every Evidence-internal field the scorer reads:
		Payload:         "GET /assets/app.js",
		Response:        "HTTP/1.1 200 OK",
		ResponseContext: "static-asset",
		Lineage:         []evidence.Evidence{{Source: models.SourceBlackbox, Category: "headers"}},
	}

	want := Score(ev)
	// Pinned so the guard fails loudly if the deltas are retuned without
	// revisiting this contract: 35 base + 10 runtime + 10 payload - 15 context.
	if want.Value != base+runtimeEvidence+payloadValidated+httpContextPenalty {
		t.Fatalf("unexpected baseline Value %d — retune this test with the rule deltas", want.Value)
	}

	ix := evidence.NewProvenanceIndex([]evidence.Evidence{ev})
	restored := ix.Restore(evidence.FromFindings(evidence.ToFindings([]evidence.Evidence{ev})))
	got := Score(restored[0])

	if !reflect.DeepEqual(got, want) {
		t.Errorf("score differs across the Finding projection — an Evidence-internal\n"+
			"field the scorer reads is missing from evidence.ScoringProvenance.\n got=%+v\nwant=%+v", got, want)
	}
}

func TestScoreStaticAssetPenalty(t *testing.T) {
	base := evidence.Evidence{Source: models.SourceBlackbox}
	stat := evidence.Evidence{Source: models.SourceBlackbox, ResponseContext: "static-asset"}
	if Score(stat).Value >= Score(base).Value {
		t.Errorf("static-asset context should lower confidence: base=%d static=%d",
			Score(base).Value, Score(stat).Value)
	}
}
