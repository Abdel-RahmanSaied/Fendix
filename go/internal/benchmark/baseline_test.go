package benchmark

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBaselineSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "baseline.json") // exercises MkdirAll
	in := &Baseline{
		Version:   "v0.20.0",
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
		Results: map[string]BenchmarkResult{
			"owasp": {Target: "owasp", TruePos: 80, FalsePos: 20, TrueNeg: 800, FalseNeg: 20},
		},
	}
	if err := in.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Version != in.Version {
		t.Errorf("Version = %q, want %q", out.Version, in.Version)
	}
	got := out.Results["owasp"]
	if got.TruePos != 80 || got.FalsePos != 20 {
		t.Errorf("round-trip result = %+v, want TP=80 FP=20", got)
	}
}

func TestLoadMissingFileIsNotExist(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("Load of missing file: want error, got nil")
	}
}

func TestCompareDetectsRegressionAndImprovement(t *testing.T) {
	base := &Baseline{Results: map[string]BenchmarkResult{
		// precision = 0.90, recall = 0.90
		"t": {Target: "t", TruePos: 90, FalsePos: 10, TrueNeg: 90, FalseNeg: 10},
	}}

	// Recall drops to 0.50 (>10% worse) → regression. Precision steady.
	current := []BenchmarkResult{
		{Target: "t", TruePos: 50, FalsePos: 6, TrueNeg: 94, FalseNeg: 50},
	}
	rr := base.Compare(current)
	if !rr.HasRegression() {
		t.Fatal("expected a regression for a large recall drop")
	}
	var sawRecall bool
	for _, d := range rr.Deltas {
		if d.Metric == "recall" {
			sawRecall = true
			if !d.Regression {
				t.Errorf("recall delta not flagged: %+v", d)
			}
		}
		if d.Metric == "precision" && d.Regression {
			t.Errorf("precision should not regress: %+v", d)
		}
	}
	if !sawRecall {
		t.Error("recall delta missing from report")
	}
}

func TestCompareWithinThresholdIsClean(t *testing.T) {
	base := &Baseline{Results: map[string]BenchmarkResult{
		"t": {Target: "t", TruePos: 90, FalsePos: 10, TrueNeg: 90, FalseNeg: 10},
	}}
	// Tiny movement well under 10%.
	current := []BenchmarkResult{
		{Target: "t", TruePos: 89, FalsePos: 11, TrueNeg: 89, FalseNeg: 11},
	}
	if base.Compare(current).HasRegression() {
		t.Error("sub-threshold movement should not regress")
	}
}

func TestCompareNewTargetIsNotRegression(t *testing.T) {
	base := &Baseline{Results: map[string]BenchmarkResult{}}
	rr := base.Compare([]BenchmarkResult{{Target: "fresh", TruePos: 1}})
	if rr.HasRegression() {
		t.Error("a brand-new target must never count as a regression")
	}
	if len(rr.NewTargets) != 1 || rr.NewTargets[0] != "fresh" {
		t.Errorf("NewTargets = %v, want [fresh]", rr.NewTargets)
	}
}

func TestCompareDurationRegression(t *testing.T) {
	base := &Baseline{Results: map[string]BenchmarkResult{
		"t": {Target: "t", ScanDuration: 10 * time.Second},
	}}
	// 12s is 20% slower → regression (lower-is-better metric).
	current := []BenchmarkResult{{Target: "t", ScanDuration: 12 * time.Second}}
	rr := base.Compare(current)
	var found bool
	for _, d := range rr.Deltas {
		if d.Metric == "duration_ms" {
			found = true
			if !d.Regression {
				t.Errorf("20%% slower scan should regress: %+v", d)
			}
		}
	}
	if !found {
		t.Error("duration_ms delta missing")
	}
}
