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
	// 25s is 2.5x slower → regression. Duration is judged against
	// DurationRegressionThreshold, not the accuracy band: a 20% move is inside
	// the noise a shared CI runner produces for a Dockerized HTTP scan (one
	// unchanged commit measured a 39% spread across three machines), so the
	// gate would fail release tags for a cost the code never incurred. It
	// still catches a genuine slowdown.
	current := []BenchmarkResult{{Target: "t", ScanDuration: 25 * time.Second}}
	rr := base.Compare(current)
	var found bool
	for _, d := range rr.Deltas {
		if d.Metric == "duration_ms" {
			found = true
			if !d.Regression {
				t.Errorf("2.5x slower scan should regress: %+v", d)
			}
		}
	}
	if !found {
		t.Error("duration_ms delta missing")
	}

	// ...and runner-jitter-sized noise must NOT regress.
	quiet := base.Compare([]BenchmarkResult{{Target: "t", ScanDuration: 12 * time.Second}})
	for _, d := range quiet.Deltas {
		if d.Metric == "duration_ms" && d.Regression {
			t.Errorf("20%% slower is runner jitter, must not fail a release: %+v", d)
		}
	}
}

// The DAST targets time a Docker container answering HTTP on a shared CI
// runner, so duration_ms carries the runner's load, not just the scanner's
// cost. One unchanged commit measured 25.6s locally, 33.0s and 35.5s on two CI
// runners — a 39% spread that failed two consecutive release tags under the
// accuracy-sized 10% band. Duration still gates (Rule 6: performance
// regressions are bugs), just at a band wider than the observed jitter.
func TestDurationUsesItsOwnWiderBand(t *testing.T) {
	const base = 28629.0
	cases := []struct {
		name      string
		cur       float64
		regressed bool
	}{
		{"observed rc1 runner jitter (+15%)", 32992, false},
		{"observed v1.2.0 runner jitter (+24%)", 35549, false},
		{"faster than baseline", 25600, false},
		{"still under the band (+80%)", base * 1.8, false},
		{"a genuine 2.5x slowdown", base * 2.5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := isRegression("duration_ms", base, tc.cur)
			if got != tc.regressed {
				t.Errorf("duration %.0f→%.0f regressed=%v, want %v", base, tc.cur, got, tc.regressed)
			}
		})
	}
}

// Accuracy is deterministic and must keep the tight band — widening duration
// must not have loosened precision/recall/F1.
func TestAccuracyMetricsKeepTheTightBand(t *testing.T) {
	for _, m := range []string{"precision", "recall", "f1"} {
		if _, regressed := isRegression(m, 1.0, 0.88); !regressed {
			t.Errorf("%s dropping 1.00→0.88 (-12%%) must still regress", m)
		}
		if _, regressed := isRegression(m, 1.0, 0.95); regressed {
			t.Errorf("%s dropping 1.00→0.95 (-5%%) is inside the band", m)
		}
	}
	// fp_rate / fn_rate are lower-is-better and also stay tight.
	if _, regressed := isRegression("fp_rate", 0.10, 0.12); !regressed {
		t.Error("fp_rate rising 0.10→0.12 (+20%) must still regress")
	}
}
