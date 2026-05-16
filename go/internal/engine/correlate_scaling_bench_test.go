package engine

import (
	"fmt"
	"testing"
)

// BenchmarkCorrelate_Scaling sweeps the input size across realistic
// scan scales so a future regression that flips the correlator from
// its current O(W·B) to something worse (e.g. O(W·B·S²) if the
// segment cache is regressed) shows up as a non-linear slope.
//
// Read pattern: `go test -bench=BenchmarkCorrelate_Scaling`
// — each sub-bench reports ns/op + B/op. Doubling N should roughly
// quadruple ns/op while the algorithm is O(W·B); a worse slope is
// a new finding worth chasing.
//
// 5000 is the upper bound for "fits comfortably in test budget";
// going higher (10k+) is left for ad-hoc profiling — see PLAN.md
// for the 25k LOC/s + 150 MB RSS performance floor that this
// engine code must continue to honour.
func BenchmarkCorrelate_Scaling(b *testing.B) {
	sizes := []int{500, 1000, 2500, 5000}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			findings := buildMixedFindings(n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Correlate(findings)
			}
		})
	}
}
