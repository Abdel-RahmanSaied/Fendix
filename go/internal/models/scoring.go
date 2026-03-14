package models

// ImpactBase maps finding categories to their base impact scores.
// These are used in severity calculation: Score = Base × ConfidenceMult × SourceMult.
var ImpactBase = map[string]float64{
	"auth_bypass":     10.0,
	"injection":       9.5,
	"secrets":         9.0,
	"idor":            8.5,
	"data_exposure":   7.0,
	"cors":            6.5,
	"headers":         4.0,
	"info_disclosure": 2.0,
}

// ConfidenceMult maps confidence levels to score multipliers.
var ConfidenceMult = map[Confidence]float64{
	ConfidenceHigh:   1.0,
	ConfidenceMedium: 0.75,
	ConfidenceLow:    0.5,
}

// SourceMult maps finding sources to score multipliers.
// Correlated findings get a boost because both engines agree.
var SourceMult = map[Source]float64{
	SourceCorrelated: 1.1,
	SourceBlackbox:   1.0,
	SourceWhitebox:   0.9,
}

// CalculateSeverity computes the severity level for a finding based on
// its category, confidence, and source using the scoring model.
func CalculateSeverity(category string, confidence Confidence, source Source) Severity {
	base, ok := ImpactBase[category]
	if !ok {
		return SeverityInfo
	}
	score := base * ConfidenceMult[confidence] * SourceMult[source]

	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 1.0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
