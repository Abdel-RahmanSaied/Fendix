package benchmark

import (
	"math"
	"testing"
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestBenchmarkResultRates(t *testing.T) {
	r := &BenchmarkResult{TruePos: 8, FalsePos: 2, TrueNeg: 80, FalseNeg: 10}
	tests := []struct {
		name string
		got  float64
		want float64
	}{
		{"precision", r.Precision(), 8.0 / 10.0},
		{"recall", r.Recall(), 8.0 / 18.0},
		{"fpRate", r.FPRate(), 2.0 / 82.0},
		{"fnRate", r.FNRate(), 10.0 / 18.0},
	}
	for _, tt := range tests {
		if !almost(tt.got, tt.want) {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestBenchmarkResultZeroDenominators(t *testing.T) {
	empty := &BenchmarkResult{}
	if got := empty.Precision(); got != 0 {
		t.Errorf("Precision() on empty = %v, want 0", got)
	}
	if got := empty.Recall(); got != 0 {
		t.Errorf("Recall() on empty = %v, want 0", got)
	}
	if got := empty.FPRate(); got != 0 {
		t.Errorf("FPRate() on empty = %v, want 0", got)
	}
	if got := empty.FNRate(); got != 0 {
		t.Errorf("FNRate() on empty = %v, want 0", got)
	}
	if got := empty.F1(); got != 0 {
		t.Errorf("F1() on empty = %v, want 0", got)
	}
}

func TestBenchmarkResultF1(t *testing.T) {
	// Perfect classifier: P = R = 1 → F1 = 1.
	perfect := &BenchmarkResult{TruePos: 10, FalseNeg: 0, FalsePos: 0, TrueNeg: 10}
	if got := perfect.F1(); !almost(got, 1.0) {
		t.Errorf("F1() perfect = %v, want 1", got)
	}
	// P = 0.8, R = 0.8 → F1 = 0.8.
	r := &BenchmarkResult{TruePos: 8, FalsePos: 2, FalseNeg: 2, TrueNeg: 0}
	if got := r.F1(); !almost(got, 0.8) {
		t.Errorf("F1() = %v, want 0.8", got)
	}
}
