package models

// ImpactBase maps finding categories to their base impact scores.
// These are used in severity calculation: Score = Base × ConfidenceMult × SourceMult.
var ImpactBase = map[string]float64{
	"auth_bypass":     10.0,
	"injection":       9.5,
	"secrets":         9.0,
	"ssrf":            8.5, // CWE-918 server-side request forgery
	"idor":            8.5,
	"method_tamper":   7.0, // CWE-650/285 verb-based access-control bypass
	"data_exposure":   7.0,
	"cors":            6.5,
	"host_header":     6.5, // CWE-644/601 host-header injection / poisoning
	"redirect":        5.0, // CWE-601 open redirect
	"graphql":         4.0, // CWE-200 introspection exposure
	"headers":         4.0,
	"cookie":          4.0, // CWE-1004/614/1275 insecure cookie flags
	"rate_limiting":   4.0, // CWE-770 no rate limiting (was mis-homed under "headers")
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

// ReachableMult is the multiplier applied when the engine proved
// intra-function dataflow from a request source to a dangerous sink
// (Finding.Reachable=true). Per docs/example_plan.md §3.5: "(1.5 if
// reachable_code else 1.0)". Translates to ~one severity-level bump
// on the discrete CRITICAL/HIGH/MEDIUM/LOW/INFO scale.
//
// TASK-125: lifts the multiplier from "an idea in the plan doc" to a
// first-class factor in CalculateSeverity. The correlator already
// applies a discrete escalateSeverity for the correlated-reachable
// case (TASK-114); this lets non-correlated whitebox findings with
// reachable=true also benefit, via the orchestrator's
// escalateNonCorrelatedReachable step.
const ReachableMult = 1.5

// CalculateSeverity computes the severity level for a finding based on
// its category, confidence, and source using the scoring model.
func CalculateSeverity(category string, confidence Confidence, source Source) Severity {
	return CalculateSeverityReachable(category, confidence, source, false)
}

// CalculateSeverityReachable extends CalculateSeverity with the
// Finding.Reachable=true bump (TASK-125 / docs/example_plan.md §3.5).
// When reachable is true, the score is multiplied by ReachableMult
// before banding, which lifts most findings by one severity level
// (subject to the confidence cap enforced by EnforceSeverityConsistency).
func CalculateSeverityReachable(category string, confidence Confidence, source Source, reachable bool) Severity {
	base, ok := ImpactBase[category]
	if !ok {
		return SeverityInfo
	}
	score := base * ConfidenceMult[confidence] * SourceMult[source]
	if reachable {
		score *= ReachableMult
	}

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

// MaxSeverityForConfidence returns the highest severity level that a finding
// of the given confidence may carry. The cap is derived from the scoring
// formula's implicit maximum:
//
//	confidence=LOW    → score ≤ base × 0.5 × 1.1 = 5.5  → MEDIUM cap
//	confidence=MEDIUM → score ≤ base × 0.75 × 1.1 = 8.25 → HIGH cap (CRITICAL needs ≥ 9.0)
//	confidence=HIGH   → no cap (any severity allowed)
//
// Findings that violate this contract are downgraded by the orchestrator's
// EnforceSeverityConsistency step before reports are written, so consumers
// of the JSON report can assume the cap holds.
func MaxSeverityForConfidence(c Confidence) Severity {
	switch c {
	case ConfidenceLow:
		return SeverityMedium
	case ConfidenceMedium:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

// EnforceSeverityConsistency returns f with severity downgraded to
// MaxSeverityForConfidence(f.Confidence) when the original severity exceeds
// that cap. The boolean return indicates whether a downgrade happened, so
// callers can log or count violations.
func EnforceSeverityConsistency(f Finding) (Finding, bool) {
	cap := MaxSeverityForConfidence(f.Confidence)
	if SeverityRank(f.Severity) > SeverityRank(cap) {
		f.Severity = cap
		return f, true
	}
	return f, false
}
