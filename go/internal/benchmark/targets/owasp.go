package targets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/benchmark"
)

// ErrTargetSkipped marks a target that cannot run in the current product
// version (as opposed to a real failure). The runner reports SKIPPED with
// the reason instead of failing the suite.
var ErrTargetSkipped = errors.New("benchmark target skipped")

// OWASP is the OWASP Benchmark target.
//
// IMPORTANT (roadmap honesty, Rule 5): OWASP Benchmark v1.2 is a *Java*
// web application scored by static analysis. Fendix has no Java analyzer
// until v0.27 (see fendix-roadmap.md), so running it now would report
// recall ~0 — a misleading baseline, not a real one. Until Java support
// lands, this target loudly SKIPS rather than emit a garbage number. The
// real v0.20 DAST baseline comes from DVWA + Juice Shop; OWASP Benchmark
// becomes meaningful at v0.27 and feeds the public benchmark at v0.26+.
type OWASP struct{}

// NewOWASP returns the OWASP Benchmark target.
func NewOWASP() *OWASP { return &OWASP{} }

// Name implements benchmark.BenchmarkTarget.
func (o *OWASP) Name() string { return "owasp" }

// Scan reports the target as skipped (Java unsupported until v0.27).
func (o *OWASP) Scan(ctx context.Context, fendixBin string) (*benchmark.ScanResult, error) {
	return nil, fmt.Errorf("owasp: %w — OWASP Benchmark is Java; Fendix Java support lands in v0.27", ErrTargetSkipped)
}

// Run is unreachable in v0.20 (Scan skips first); it scores an empty
// result for interface completeness once Java support exists.
func (o *OWASP) Run(ctx context.Context, result *benchmark.ScanResult) (*benchmark.BenchmarkResult, error) {
	return &benchmark.BenchmarkResult{Target: o.Name(), Timestamp: time.Now()}, nil
}
