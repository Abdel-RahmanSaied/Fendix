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
