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
