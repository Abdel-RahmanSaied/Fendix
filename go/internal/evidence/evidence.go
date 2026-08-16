// Package evidence is the v0.22 domain layer in Fendix's
// Engine → Evidence → Finding → Decision architecture.
//
// An Evidence is everything an analysis engine observed about a potential
// issue. It is a SUPERSET of the rendered models.Finding: it carries every
// field a Finding renders, plus richer provenance the public Finding JSON
// does not expose — the exact rule/check id, the raw probe payload and
// response (DAST), a detection timestamp, free-form metadata, and, for
// correlated results, the lineage of the inputs that merged.
//
// Findings are PROJECTED from Evidence via ToFinding. The reporters still
// marshal models.Finding, so the public JSON/SARIF/HTML contract is
// unchanged — that invariant is the whole point of v0.22, and it is enforced
// by the round-trip identity tests in this package plus the output-snapshot
// and schema regression suites.
//
// The "render block" below MUST stay field-for-field in sync with
// models.Finding; the adapter tests fail loudly if it drifts.
package evidence

import (
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Evidence is the domain object produced by engines and consumed by the
// correlation service and (eventually) the decision layer.
type Evidence struct {
	// --- Render block: projected 1:1 onto models.Finding ------------------
	// Field names match models.Finding EXACTLY (including Evidence — yes, an
	// Evidence field on the Evidence type), so a scanner migrates from
	// building models.Finding{...} to evidence.Evidence{...} by swapping the
	// type name and nothing else. Keep in lockstep with models.Finding.
	ID                string
	Fingerprint       string
	Title             string
	Severity          models.Severity
	Source            models.Source
	Category          string
	Endpoint          string
	AffectedEndpoints []string
	Evidence          string // the human-readable snippet (== models.Finding.Evidence)
	Fix               string
	References        []string
	Confidence        models.Confidence
	Line              *string
	TaintChain        []models.TaintLink
	Reachable         bool
	SourceTier        models.SourceTier
	Route             *models.Route
	RouteConfirmed    bool
	ProvenPath        bool
	// v0.24 decision-report fields (render block; project 1:1 onto Finding).
	Status            string
	ConfidenceScore   int
	ConfidenceBand    string
	ConfidenceReasons []string

	// --- v0.22 provenance: INTERNAL ONLY, never serialized into Finding ---
	// ToFinding drops every field below. Anything here that confidence.Score
	// reads must also be carried by ScoringProvenance (provenance.go),
	// otherwise the rule that reads it is dead for any caller downstream of
	// the projection — see the comment at the top of provenance.go.
	// RuleID is the precise rule/check identity (e.g. a semgrep rule id or a
	// DAST check name) — finer-grained than Category.
	RuleID string
	// Payload is the request/probe Fendix sent (DAST); empty for static evidence.
	Payload string
	// Response is a bounded excerpt of what the target returned (DAST).
	Response string
	// DetectedAt is when in the scan this evidence was observed.
	DetectedAt time.Time
	// Lineage holds the constituent evidence that merged into this one
	// (populated by the correlation service for Source=correlated results),
	// so the BB+WB inputs are no longer lost after a merge.
	Lineage []Evidence
	// Metadata is free-form structural context (scanner version, etc.).
	Metadata map[string]string
	// ResponseContext tags DAST evidence with de-escalation context (B4):
	// "4xx" (the finding fired on an auth-gated / client-error response) or
	// "static-asset" (a static file, not an API route). The confidence
	// scorer applies a penalty; evidence is preserved (Rule 3). INTERNAL —
	// never projected onto Finding, so the public JSON/SARIF contract is
	// unchanged.
	ResponseContext string
}

// FromFinding lifts a models.Finding into Evidence, copying the render block
// verbatim and leaving the new provenance zero. This is the migration
// boundary: a scanner not yet emitting Evidence can have its Finding lifted
// losslessly so it flows through the Evidence pipeline unchanged.
func FromFinding(f models.Finding) Evidence {
	return Evidence{
		ID:                f.ID,
		Fingerprint:       f.Fingerprint,
		Title:             f.Title,
		Severity:          f.Severity,
		Source:            f.Source,
		Category:          f.Category,
		Endpoint:          f.Endpoint,
		AffectedEndpoints: f.AffectedEndpoints,
		Evidence:          f.Evidence,
		Fix:               f.Fix,
		References:        f.References,
		Confidence:        f.Confidence,
		Line:              f.Line,
		TaintChain:        f.TaintChain,
		Reachable:         f.Reachable,
		SourceTier:        f.SourceTier,
		Route:             f.Route,
		RouteConfirmed:    f.RouteConfirmed,
		ProvenPath:        f.ProvenPath,
		Status:            f.Status,
		ConfidenceScore:   f.ConfidenceScore,
		ConfidenceBand:    f.ConfidenceBand,
		ConfidenceReasons: f.ConfidenceReasons,
	}
}

// ToFinding projects Evidence back to the public models.Finding shape. This
// is the ONLY representation the reporters see, so it MUST reproduce the
// Finding exactly — the round-trip tests assert FromFinding∘ToFinding is the
// identity on every Finding field (and therefore on the marshaled JSON).
func (e Evidence) ToFinding() models.Finding {
	return models.Finding{
		ID:                e.ID,
		Fingerprint:       e.Fingerprint,
		Title:             e.Title,
		Severity:          e.Severity,
		Source:            e.Source,
		Category:          e.Category,
		Endpoint:          e.Endpoint,
		AffectedEndpoints: e.AffectedEndpoints,
		Evidence:          e.Evidence,
		Fix:               e.Fix,
		References:        e.References,
		Confidence:        e.Confidence,
		Line:              e.Line,
		TaintChain:        e.TaintChain,
		Reachable:         e.Reachable,
		SourceTier:        e.SourceTier,
		Route:             e.Route,
		RouteConfirmed:    e.RouteConfirmed,
		ProvenPath:        e.ProvenPath,
		Status:            e.Status,
		ConfidenceScore:   e.ConfidenceScore,
		ConfidenceBand:    e.ConfidenceBand,
		ConfidenceReasons: e.ConfidenceReasons,
	}
}

// FromFindings / ToFindings are slice helpers for the pipeline boundary.
func FromFindings(fs []models.Finding) []Evidence {
	if fs == nil {
		return nil
	}
	out := make([]Evidence, len(fs))
	for i, f := range fs {
		out[i] = FromFinding(f)
	}
	return out
}

// ToFindings projects a slice of Evidence to Findings for the reporters.
func ToFindings(es []Evidence) []models.Finding {
	if es == nil {
		return nil
	}
	out := make([]models.Finding, len(es))
	for i, e := range es {
		out[i] = e.ToFinding()
	}
	return out
}
