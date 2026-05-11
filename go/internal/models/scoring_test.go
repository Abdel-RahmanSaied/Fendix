package models

import "testing"

func TestCalculateSeverity(t *testing.T) {
	tests := []struct {
		name       string
		category   string
		confidence Confidence
		source     Source
		want       Severity
	}{
		// CRITICAL findings (score >= 9.0)
		{
			name:       "auth_bypass/high/correlated is CRITICAL",
			category:   "auth_bypass",
			confidence: ConfidenceHigh,
			source:     SourceCorrelated,
			want:       SeverityCritical,
		},
		{
			name:       "auth_bypass/high/blackbox is CRITICAL",
			category:   "auth_bypass",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityCritical,
		},
		{
			name:       "injection/high/correlated is CRITICAL",
			category:   "injection",
			confidence: ConfidenceHigh,
			source:     SourceCorrelated,
			want:       SeverityCritical,
		},
		{
			name:       "injection/high/blackbox is CRITICAL",
			category:   "injection",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityCritical,
		},
		{
			name:       "secrets/high/correlated is CRITICAL",
			category:   "secrets",
			confidence: ConfidenceHigh,
			source:     SourceCorrelated,
			want:       SeverityCritical,
		},

		// HIGH findings (score >= 7.0)
		{
			name:       "auth_bypass/medium/blackbox is HIGH",
			category:   "auth_bypass",
			confidence: ConfidenceMedium,
			source:     SourceBlackbox,
			want:       SeverityHigh,
		},
		{
			name:       "secrets/high/whitebox is HIGH",
			category:   "secrets",
			confidence: ConfidenceHigh,
			source:     SourceWhitebox,
			want:       SeverityHigh,
		},
		{
			name:       "idor/high/blackbox is HIGH",
			category:   "idor",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityHigh,
		},
		{
			name:       "injection/medium/blackbox is HIGH",
			category:   "injection",
			confidence: ConfidenceMedium,
			source:     SourceBlackbox,
			want:       SeverityHigh,
		},
		{
			name:       "data_exposure/high/correlated is HIGH",
			category:   "data_exposure",
			confidence: ConfidenceHigh,
			source:     SourceCorrelated,
			want:       SeverityHigh,
		},
		{
			name:       "data_exposure/high/blackbox is HIGH",
			category:   "data_exposure",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityHigh,
		},

		// MEDIUM findings (score >= 4.0)
		{
			name:       "cors/high/blackbox is MEDIUM",
			category:   "cors",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityMedium,
		},
		{
			name:       "headers/high/blackbox is MEDIUM",
			category:   "headers",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityMedium,
		},
		{
			name:       "data_exposure/medium/whitebox is MEDIUM",
			category:   "data_exposure",
			confidence: ConfidenceMedium,
			source:     SourceWhitebox,
			want:       SeverityMedium,
		},
		{
			name:       "injection/low/whitebox is MEDIUM",
			category:   "injection",
			confidence: ConfidenceLow,
			source:     SourceWhitebox,
			want:       SeverityMedium,
		},

		// LOW findings (score >= 1.0)
		{
			name:       "info_disclosure/high/blackbox is LOW",
			category:   "info_disclosure",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityLow,
		},
		{
			name:       "info_disclosure/high/whitebox is LOW",
			category:   "info_disclosure",
			confidence: ConfidenceHigh,
			source:     SourceWhitebox,
			want:       SeverityLow,
		},
		{
			name:       "headers/low/whitebox is LOW",
			category:   "headers",
			confidence: ConfidenceLow,
			source:     SourceWhitebox,
			want:       SeverityLow,
		},

		// INFO findings (score < 1.0)
		{
			name:       "info_disclosure/low/whitebox is INFO",
			category:   "info_disclosure",
			confidence: ConfidenceLow,
			source:     SourceWhitebox,
			want:       SeverityInfo,
		},

		// Unknown category defaults to INFO
		{
			name:       "unknown category is INFO",
			category:   "nonexistent",
			confidence: ConfidenceHigh,
			source:     SourceBlackbox,
			want:       SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateSeverity(tt.category, tt.confidence, tt.source)
			if got != tt.want {
				score := ImpactBase[tt.category] * ConfidenceMult[tt.confidence] * SourceMult[tt.source]
				t.Errorf("CalculateSeverity(%q, %q, %q) = %q (score=%.2f), want %q",
					tt.category, tt.confidence, tt.source, got, score, tt.want)
			}
		})
	}
}

// TASK-125: reachable=true applies ReachableMult (1.5x) and typically
// lifts severity by one level. Locks in the multiplier value + the
// banding it produces.
func TestCalculateSeverityReachable(t *testing.T) {
	cases := []struct {
		name             string
		category         string
		confidence       Confidence
		source           Source
		wantWithout      Severity
		wantWithReachable Severity
	}{
		{
			// injection 9.5 × HIGH 1.0 × whitebox 0.9 = 8.55 → HIGH;
			// × 1.5 = 12.825 → CRITICAL.
			name: "injection_whitebox_HIGH bumps to CRITICAL",
			category: "injection", confidence: ConfidenceHigh, source: SourceWhitebox,
			wantWithout: SeverityHigh, wantWithReachable: SeverityCritical,
		},
		{
			// headers 4.0 × HIGH 1.0 × blackbox 1.0 = 4.0 → MEDIUM;
			// × 1.5 = 6.0 → MEDIUM (banding doesn't cross 7.0 yet).
			name: "headers stays MEDIUM (within band)",
			category: "headers", confidence: ConfidenceHigh, source: SourceBlackbox,
			wantWithout: SeverityMedium, wantWithReachable: SeverityMedium,
		},
		{
			// data_exposure 7.0 × HIGH 1.0 × blackbox 1.0 = 7.0 → HIGH;
			// × 1.5 = 10.5 → CRITICAL.
			name: "data_exposure_HIGH bumps HIGH → CRITICAL",
			category: "data_exposure", confidence: ConfidenceHigh, source: SourceBlackbox,
			wantWithout: SeverityHigh, wantWithReachable: SeverityCritical,
		},
		{
			// cors 6.5 × MEDIUM 0.75 × whitebox 0.9 = 4.39 → MEDIUM;
			// × 1.5 = 6.58 → MEDIUM (still in band).
			name: "cors_MEDIUM_whitebox stays MEDIUM",
			category: "cors", confidence: ConfidenceMedium, source: SourceWhitebox,
			wantWithout: SeverityMedium, wantWithReachable: SeverityMedium,
		},
		{
			// unknown category returns INFO regardless of reachable.
			name: "unknown category INFO regardless of reachable",
			category: "made_up", confidence: ConfidenceHigh, source: SourceWhitebox,
			wantWithout: SeverityInfo, wantWithReachable: SeverityInfo,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotWithout := CalculateSeverityReachable(c.category, c.confidence, c.source, false)
			if gotWithout != c.wantWithout {
				t.Errorf("without reachable: got %s, want %s", gotWithout, c.wantWithout)
			}
			gotWith := CalculateSeverityReachable(c.category, c.confidence, c.source, true)
			if gotWith != c.wantWithReachable {
				t.Errorf("with reachable: got %s, want %s", gotWith, c.wantWithReachable)
			}
		})
	}
}

func TestReachableMultConstantStable(t *testing.T) {
	// Lock in the documented value per docs/example_plan.md §3.5.
	if ReachableMult != 1.5 {
		t.Errorf("ReachableMult must remain 1.5 per the plan; got %f", ReachableMult)
	}
}

func TestCalculateSeverity_BackwardsCompatible(t *testing.T) {
	// CalculateSeverity must still produce the same answer as before
	// when reachable is implicitly false. Locks in that existing callers
	// (tests, benchmarks) keep working without touching them.
	got := CalculateSeverity("injection", ConfidenceHigh, SourceWhitebox)
	want := CalculateSeverityReachable("injection", ConfidenceHigh, SourceWhitebox, false)
	if got != want {
		t.Errorf("CalculateSeverity drift: %s vs %s", got, want)
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityInfo, 0},
		{Severity("UNKNOWN"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := SeverityRank(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityRank(%q) = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	// Verify that rank ordering is consistent
	if SeverityRank(SeverityCritical) <= SeverityRank(SeverityHigh) {
		t.Error("CRITICAL should rank higher than HIGH")
	}
	if SeverityRank(SeverityHigh) <= SeverityRank(SeverityMedium) {
		t.Error("HIGH should rank higher than MEDIUM")
	}
	if SeverityRank(SeverityMedium) <= SeverityRank(SeverityLow) {
		t.Error("MEDIUM should rank higher than LOW")
	}
	if SeverityRank(SeverityLow) <= SeverityRank(SeverityInfo) {
		t.Error("LOW should rank higher than INFO")
	}
}

func TestMaxSeverityForConfidence(t *testing.T) {
	tests := []struct {
		conf Confidence
		want Severity
	}{
		{ConfidenceHigh, SeverityCritical},
		{ConfidenceMedium, SeverityHigh},
		{ConfidenceLow, SeverityMedium},
	}
	for _, tc := range tests {
		t.Run(string(tc.conf), func(t *testing.T) {
			if got := MaxSeverityForConfidence(tc.conf); got != tc.want {
				t.Errorf("MaxSeverityForConfidence(%s) = %s, want %s", tc.conf, got, tc.want)
			}
		})
	}
}

func TestEnforceSeverityConsistency(t *testing.T) {
	tests := []struct {
		name           string
		in             Finding
		wantSev        Severity
		wantDowngraded bool
	}{
		{
			name:           "LOW conf with HIGH sev downgrades to MEDIUM",
			in:             Finding{Severity: SeverityHigh, Confidence: ConfidenceLow},
			wantSev:        SeverityMedium,
			wantDowngraded: true,
		},
		{
			name:           "LOW conf with CRITICAL sev downgrades to MEDIUM",
			in:             Finding{Severity: SeverityCritical, Confidence: ConfidenceLow},
			wantSev:        SeverityMedium,
			wantDowngraded: true,
		},
		{
			name:           "LOW conf with MEDIUM sev unchanged",
			in:             Finding{Severity: SeverityMedium, Confidence: ConfidenceLow},
			wantSev:        SeverityMedium,
			wantDowngraded: false,
		},
		{
			name:           "MEDIUM conf with CRITICAL sev downgrades to HIGH",
			in:             Finding{Severity: SeverityCritical, Confidence: ConfidenceMedium},
			wantSev:        SeverityHigh,
			wantDowngraded: true,
		},
		{
			name:           "MEDIUM conf with HIGH sev unchanged",
			in:             Finding{Severity: SeverityHigh, Confidence: ConfidenceMedium},
			wantSev:        SeverityHigh,
			wantDowngraded: false,
		},
		{
			name:           "HIGH conf with CRITICAL sev unchanged",
			in:             Finding{Severity: SeverityCritical, Confidence: ConfidenceHigh},
			wantSev:        SeverityCritical,
			wantDowngraded: false,
		},
		{
			name:           "HIGH conf with INFO sev unchanged",
			in:             Finding{Severity: SeverityInfo, Confidence: ConfidenceHigh},
			wantSev:        SeverityInfo,
			wantDowngraded: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, downgraded := EnforceSeverityConsistency(tc.in)
			if got.Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", got.Severity, tc.wantSev)
			}
			if downgraded != tc.wantDowngraded {
				t.Errorf("downgraded = %v, want %v", downgraded, tc.wantDowngraded)
			}
			// Other fields must be untouched.
			if got.Confidence != tc.in.Confidence {
				t.Errorf("confidence mutated: got %s, want %s", got.Confidence, tc.in.Confidence)
			}
		})
	}
}
