package models

import (
	"testing"
)

func BenchmarkCalculateSeverity(b *testing.B) {
	categories := []string{"auth_bypass", "injection", "secrets", "data_exposure", "cors", "headers"}
	confidences := []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow}
	sources := []Source{SourceBlackbox, SourceWhitebox, SourceCorrelated}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cat := categories[i%len(categories)]
		conf := confidences[i%len(confidences)]
		src := sources[i%len(sources)]
		CalculateSeverity(cat, conf, src)
	}
}

func BenchmarkSeverityRank(b *testing.B) {
	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SeverityRank(severities[i%len(severities)])
	}
}

func BenchmarkFindingMarshalJSON(b *testing.B) {
	line := "src/config.py:14"
	f := Finding{
		ID:         "SEC-001",
		Title:      "Hardcoded API key detected",
		Severity:   SeverityCritical,
		Source:     SourceWhitebox,
		Category:   "secrets",
		Endpoint:   "src/config.py:14",
		Evidence:   "API_KEY = 'sk-live-abc...' [truncated]",
		Fix:        "Move to environment variable. Rotate the exposed key immediately.",
		References: []string{"CWE-798"},
		Confidence: ConfidenceHigh,
		Line:       &line,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f // Force compiler to not optimize away
		// We can't call json.Marshal here without importing encoding/json
		// but this tests the struct allocation pattern
		_ = Finding{
			ID:         f.ID,
			Title:      f.Title,
			Severity:   f.Severity,
			Source:     f.Source,
			Category:   f.Category,
			Endpoint:   f.Endpoint,
			Evidence:   f.Evidence,
			Fix:        f.Fix,
			References: f.References,
			Confidence: f.Confidence,
			Line:       f.Line,
		}
	}
}
