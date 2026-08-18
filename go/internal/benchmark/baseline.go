package benchmark

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// DefaultBaselinePath is where the committed baseline lives, relative to
// the engine repo root. `fendix benchmark` commands resolve it from the
// current working directory; pass an explicit path to override.
const DefaultBaselinePath = "benchmarks/baselines/baseline.json"

// RegressionThreshold is the fraction a metric may move in its "worse"
// direction (relative to the baseline value) before it counts as a
// regression. The roadmap fixes this at 10% — "any metric worse by > 10%
// = REGRESSION". It is a package var (not a const) so a future release can
// tighten the gate without touching the comparator.
var RegressionThreshold = 0.10

// DurationRegressionThreshold is the separate, much wider band for wall-clock
// metrics. Accuracy is deterministic — the same binary on the same corpus
// yields the same precision every time, so 10% there is a real signal. Scan
// duration is not: the DAST targets time a Docker container answering HTTP on
// a shared CI runner, and that measurement carries the runner's load, not just
// the scanner's cost.
//
// Measured on ONE unchanged commit (v1.2.0): 25.6s locally, 33.0s on the rc1
// runner, 35.5s on the v1.2.0 runner — a 39% spread, with the slowest run
// logging an HTTP `context deadline exceeded` mid-scan. Under the shared 10%
// band that failed two consecutive release tags for a cost the code never
// incurred.
//
// Duration still gates, because Rule 6 treats performance regressions as bugs
// (the v1.1 work took a scan from ~50 min to 9 s, and losing that silently
// would be a real failure). 100% is chosen to sit far above observed runner
// jitter (~25%) while still catching anything that genuinely doubles the
// scan's cost.
var DurationRegressionThreshold = 1.00

// thresholdFor returns the band a metric is judged against.
func thresholdFor(metric string) float64 {
	if metric == "duration_ms" {
		return DurationRegressionThreshold
	}
	return RegressionThreshold
}

// Baseline is the committed snapshot of benchmark numbers that every
// future run is compared against. Results is keyed by target name so
// adding a new target never disturbs existing baselines.
type Baseline struct {
	// Version is the fendix version that produced this baseline.
	Version string `json:"version"`
	// CreatedAt is when the baseline was captured.
	CreatedAt time.Time `json:"created_at"`
	// Results maps target name -> stored result.
	Results map[string]BenchmarkResult `json:"results"`
}

// Load reads a baseline from path. A missing file is reported as
// fs.ErrNotExist (wrapped) so callers can treat "no baseline yet" as the
// first-run case rather than a hard failure.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("loading baseline %s: %w", path, err)
		}
		return nil, fmt.Errorf("loading baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}
	return &b, nil
}

// Save writes the baseline to path as indented JSON, creating parent
// directories as needed. The write is atomic (temp file + rename) so a
// crash mid-write can never corrupt a committed baseline.
func (b *Baseline) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating baseline dir for %s: %w", path, err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp baseline file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp baseline file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp baseline file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming baseline into place: %w", err)
	}
	return nil
}

// MetricDelta is one metric's movement from baseline to current.
// PctChange is signed and relative to the baseline value (current-base)/base.
type MetricDelta struct {
	Target     string  `json:"target"`
	Metric     string  `json:"metric"`
	Baseline   float64 `json:"baseline"`
	Current    float64 `json:"current"`
	PctChange  float64 `json:"pct_change"`
	Regression bool    `json:"regression"`
}

// RegressionReport is the result of comparing a set of current results
// against the stored baseline.
type RegressionReport struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Deltas      []MetricDelta `json:"deltas"`
	// NewTargets lists current results with no baseline entry (first run
	// for that target — recorded, never a regression).
	NewTargets []string `json:"new_targets,omitempty"`
}

// HasRegression reports whether any metric regressed past the threshold.
func (rr *RegressionReport) HasRegression() bool {
	for _, d := range rr.Deltas {
		if d.Regression {
			return true
		}
	}
	return false
}

// higherIsBetter maps each compared metric to its "good" direction. This
// table + isRegression below ARE the regression policy — the one place
// where benchmark judgment is encoded. See the Architect handoff note:
// precision/recall/F1 are better when higher; false-positive rate,
// false-negative rate, scan duration, and memory are better when lower.
var higherIsBetter = map[string]bool{
	"precision":   true,
	"recall":      true,
	"f1":          true,
	"fp_rate":     false,
	"fn_rate":     false,
	"duration_ms": false,
}

// isRegression decides whether a single metric moved enough in its bad
// direction to count as a regression. Relative change is measured against
// the baseline; when the baseline is 0 we fall back to "any movement in
// the bad direction regresses" (a relative threshold is undefined at 0).
//
// THIS IS THE TUNABLE POLICY. Keep the surrounding plumbing; change here.
func isRegression(metric string, base, cur float64) (pct float64, regressed bool) {
	if base != 0 {
		pct = (cur - base) / base
	} else if cur != 0 {
		pct = 1 // treat any move off a zero baseline as a full-unit change
	}
	limit := thresholdFor(metric)
	worseUp := !higherIsBetter[metric] // lower-is-better → up is worse
	if worseUp {
		return pct, pct > limit
	}
	// higher-is-better → a drop past the threshold regresses
	return pct, pct < -limit
}

// Compare scores current results against the baseline and returns a
// per-metric regression report. Targets present in current but not in the
// baseline are reported under NewTargets and never flagged.
func (b *Baseline) Compare(current []BenchmarkResult) *RegressionReport {
	rr := &RegressionReport{}
	for _, cur := range current {
		base, ok := b.Results[cur.Target]
		if !ok {
			rr.NewTargets = append(rr.NewTargets, cur.Target)
			continue
		}
		metrics := []struct {
			name      string
			base, cur float64
		}{
			{"precision", base.Precision(), cur.Precision()},
			{"recall", base.Recall(), cur.Recall()},
			{"f1", base.F1(), cur.F1()},
			{"fp_rate", base.FPRate(), cur.FPRate()},
			{"fn_rate", base.FNRate(), cur.FNRate()},
			{"duration_ms", float64(base.ScanDuration.Milliseconds()), float64(cur.ScanDuration.Milliseconds())},
			// memory_mb intentionally NOT gated: MemoryPeakMB is never populated
			// outside tests (always 0), so it only padded reports with a dead
			// 0→0 guard (v0.27 B5). `make bench` owns real memory measurement;
			// the field is kept for future RSS capture.
		}
		for _, m := range metrics {
			pct, regressed := isRegression(m.name, m.base, m.cur)
			rr.Deltas = append(rr.Deltas, MetricDelta{
				Target:     cur.Target,
				Metric:     m.name,
				Baseline:   m.base,
				Current:    m.cur,
				PctChange:  pct,
				Regression: regressed,
			})
		}
	}
	return rr
}
