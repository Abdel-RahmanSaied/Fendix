// Package decision is the v0.22 Decision layer in Fendix's
// Engine → Evidence → Finding → Decision architecture.
//
// A Decision is the internal verdict for a piece of Evidence: should this
// finding BLOCK the build, merely WARN, be INFO, or be IGNOREd. v0.22 builds
// the type and a faithful exit-code mapping but does NOT surface it — the
// orchestrator still computes its exit code via checkFailOn, and the CLI is
// unchanged. The mapping here is locked by tests so that when v0.24 wires the
// Decision layer into the orchestrator, exit codes stay byte-for-byte the same.
package decision

import (
	"github.com/Abdel-RahmanSaied/Fendix/internal/confidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Status is the verdict for one piece of evidence.
type Status string

const (
	// StatusBlock — fails the build (exit 1). Matches "at/above --fail-on".
	StatusBlock Status = "BLOCK"
	// StatusWarn — surfaced prominently but non-blocking (MEDIUM+ below threshold).
	StatusWarn Status = "WARN"
	// StatusInfo — informational (LOW / INFO severity).
	StatusInfo Status = "INFO"
	// StatusIgnore — suppressed (e.g. by a .fendix-ignore rule). Reserved;
	// suppression happens upstream today, so Decide does not emit it yet.
	StatusIgnore Status = "IGNORE"
)

// Decision is the internal verdict plus its justification. Not serialized in
// v0.22 (see package doc).
type Decision struct {
	Status     Status
	Confidence models.Confidence
	Reason     string
	// Score is the v0.23 deterministic confidence score (0–100) + plain-text
	// reason breakdown for this decision. Internal in v0.23 (not serialized);
	// surfaced in v0.24's decision reports.
	Score confidence.Result
	// Evidence is the supporting evidence this verdict was derived from.
	Evidence evidence.Evidence
}

// Decide computes the Decision for one piece of evidence under the given
// --fail-on threshold (the raw flag value; "" = no threshold). The BLOCK
// rule is identical to checkFailOn: block iff failOn is a valid severity
// (rank > 0) and the evidence's severity rank is at or above it.
func Decide(ev evidence.Evidence, failOn string) Decision {
	threshold := 0
	if failOn != "" {
		threshold = models.SeverityRank(models.Severity(failOn))
	}
	rank := models.SeverityRank(ev.Severity)

	d := Decision{Confidence: ev.Confidence, Score: confidence.Score(ev), Evidence: ev}
	switch {
	case threshold > 0 && rank >= threshold:
		d.Status = StatusBlock
		d.Reason = "severity at or above the --fail-on threshold"
	case rank >= models.SeverityRank(models.SeverityMedium):
		d.Status = StatusWarn
		d.Reason = "actionable finding below the --fail-on threshold"
	default:
		d.Status = StatusInfo
		d.Reason = "informational finding"
	}
	return d
}

// DecideAll maps a slice of evidence to decisions under one threshold.
func DecideAll(evs []evidence.Evidence, failOn string) []Decision {
	if evs == nil {
		return nil
	}
	out := make([]Decision, len(evs))
	for i, ev := range evs {
		out[i] = Decide(ev, failOn)
	}
	return out
}

// ExitCode reproduces checkFailOn's exit semantics from a set of decisions:
// 1 if any decision BLOCKs, else 0. This is the contract that lets the
// orchestrator delegate to the Decision layer later without changing exit codes.
func ExitCode(decisions []Decision) int {
	for _, d := range decisions {
		if d.Status == StatusBlock {
			return 1
		}
	}
	return 0
}
