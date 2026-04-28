// Package models defines the core data types shared across Fendix.
// Finding, Severity, Confidence, and Source are the primary types
// used by both Go and Python engines via the IPC contract.
package models

// Severity represents the severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence represents how certain we are about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Source indicates which engine produced the finding.
type Source string

const (
	SourceBlackbox   Source = "blackbox"
	SourceWhitebox   Source = "whitebox"
	SourceCorrelated Source = "correlated"
)

// Finding represents a single security finding produced by either engine.
// This struct is the shared data contract between Go and Python.
//
// AffectedEndpoints is populated by the orchestrator's deduplication pass
// (TASK-088) when N findings of the same (Title, Category, Severity)
// collapse into one. The slice contains every affected endpoint including
// the primary one in `Endpoint`. When the finding represents a single
// occurrence, AffectedEndpoints is nil (omitted from JSON via omitempty).
type Finding struct {
	ID                string     `json:"id"`
	Title             string     `json:"title"`
	Severity          Severity   `json:"severity"`
	Source            Source     `json:"source"`
	Category          string     `json:"category"`
	Endpoint          string     `json:"endpoint"`
	AffectedEndpoints []string   `json:"affected_endpoints,omitempty"`
	Evidence          string     `json:"evidence"`
	Fix               string     `json:"fix"`
	References        []string   `json:"references"`
	Confidence        Confidence `json:"confidence"`
	Line              *string    `json:"line"`
}

// SeverityRank returns a numeric rank for severity comparison.
// Higher values indicate more severe findings.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
