// Package confidence is the v0.23 Confidence Engine: a DETERMINISTIC,
// rule-based, fully explainable scorer that turns an evidence.Evidence into a
// 0–100 confidence score plus a plain-text reason for every contribution.
//
// There is NO AI in this path (Constitution Rule 8). Every point comes from a
// fixed, documented rule keyed off the provenance v0.22 threaded onto Evidence
// (source engine, runtime confirmation, reachability, cross-engine agreement,
// payload validation, analyzer tier, correlation lineage). The same Evidence
// always yields the same score and the same reasons — auditable, reproducible.
//
// v0.23 is INTERNAL: the score attaches to the internal decision.Decision and
// does NOT change the public report (the existing models.Confidence enum,
// severity, and JSON/SARIF/HTML are untouched). v0.24 surfaces it.
package confidence

import (
	"fmt"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Rule deltas. Exposed as consts so the scoring policy is auditable at a
// glance and a future release can tune it without spelunking the logic.
const (
	base               = 35 // a scanner flagged this at all
	staticEvidence     = 10 // SAST (whitebox/correlated) saw it in source
	runtimeEvidence    = 10 // DAST (blackbox/correlated) observed it live
	crossEngineAgree   = 25 // DAST and SAST independently flagged the same issue
	routeConfirmed     = 10 // a live request confirmed the vulnerable route
	reachableTaint     = 10 // AST proved a source→sink taint path
	provenPathBonus    = 5  // confirmed route AND reachable taint chain
	payloadValidated   = 10 // an active probe payload elicited a confirming response
	tierTreeSitterBump = 5  // highest-trust analyzer tier
	tierSemgrepPenalty = -5 // lowest-trust analyzer tier (regex breadth)

	// Band thresholds on the 0–100 score.
	bandHigh   = 70
	bandMedium = 40
)

// Result is the deterministic confidence verdict for one piece of Evidence.
type Result struct {
	// Value is the clamped 0–100 score.
	Value int
	// Band is the coarse bucket derived from Value (HIGH/MEDIUM/LOW).
	Band models.Confidence
	// Reasons is the plain-text breakdown — one line per rule that fired,
	// in deterministic order. This is the "no black boxes" contract.
	Reasons []string
}

// Score computes the confidence Result for ev. Pure and deterministic.
func Score(ev evidence.Evidence) Result {
	score := base
	reasons := []string{fmt.Sprintf("+%d base: a scanner produced this finding", base)}

	add := func(delta int, why string) {
		score += delta
		sign := "+"
		if delta < 0 {
			sign = "" // negative already carries its sign
		}
		reasons = append(reasons, fmt.Sprintf("%s%d %s", sign, delta, why))
	}

	hasStatic := ev.Source == models.SourceWhitebox || ev.Source == models.SourceCorrelated
	hasRuntime := ev.Source == models.SourceBlackbox || ev.Source == models.SourceCorrelated
	if hasStatic {
		add(staticEvidence, "static (SAST) evidence present")
	}
	if hasRuntime {
		add(runtimeEvidence, "runtime (DAST) observation present")
	}
	if ev.Source == models.SourceCorrelated {
		add(crossEngineAgree, "cross-engine agreement: DAST and SAST independently flagged this")
	}
	if ev.RouteConfirmed {
		add(routeConfirmed, "live request confirmed the vulnerable route")
	}
	if ev.Reachable {
		add(reachableTaint, "AST proved a reachable source→sink taint path")
	}
	if ev.ProvenPath {
		add(provenPathBonus, "proven path: confirmed route AND reachable taint chain")
	}
	if ev.Payload != "" && ev.Response != "" {
		add(payloadValidated, "active probe payload elicited a confirming response")
	}
	switch ev.SourceTier {
	case models.TierTreeSitter:
		add(tierTreeSitterBump, "high-trust analyzer tier (tree-sitter taint)")
	case models.TierSemgrepShim:
		add(tierSemgrepPenalty, "lower-trust analyzer tier (semgrep regex breadth)")
	}

	// Evidence-chain tracing: a correlated score is only as trustworthy as
	// the inputs that merged into it, so surface them.
	if trace := lineageTrace(ev); trace != "" {
		reasons = append(reasons, trace)
	}

	// Keep the "no black boxes" contract exact: when corroboration pushes the
	// raw sum over the ceiling, record the cap so the reasons sum to Value.
	if score > 100 {
		reasons = append(reasons, fmt.Sprintf("-%d capped at 100 (corroboration ceiling)", score-100))
	}
	score = clamp(score, 0, 100)
	return Result{Value: score, Band: bandFor(score), Reasons: reasons}
}

// lineageTrace renders ev.Lineage (the BB+WB inputs that merged during
// correlation) into a single plain-text chain line. Empty when there's no
// lineage (non-correlated evidence).
func lineageTrace(ev evidence.Evidence) string {
	if len(ev.Lineage) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ev.Lineage))
	for _, in := range ev.Lineage {
		src := string(in.Source)
		if src == "" {
			src = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", src, in.Category))
	}
	return "evidence chain: merged from " + strings.Join(parts, " + ")
}

func bandFor(score int) models.Confidence {
	switch {
	case score >= bandHigh:
		return models.ConfidenceHigh
	case score >= bandMedium:
		return models.ConfidenceMedium
	default:
		return models.ConfidenceLow
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
