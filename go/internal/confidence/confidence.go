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
//
// NOTE on payloadValidated, recorded because it changes how the rest of the
// table should be read: the rule requires BOTH ev.Payload and ev.Response, and
// evidence.Evidence.Response has no production producer anywhere in the module
// — every active-probe scanner sets Payload, none sets Response, and the only
// other occurrences are provenance/correlator plumbing that copies it. So the
// +10 has never fired outside tests, and the real DAST-only ceiling before
// directObservation was 45, not 55. Do not re-derive the calibration from the
// nominal sum.
const (
	base               = 35  // a scanner flagged this at all
	staticEvidence     = 10  // SAST (whitebox/correlated) saw it in source
	runtimeEvidence    = 10  // DAST (blackbox/correlated) observed it live
	crossEngineAgree   = 25  // DAST and SAST independently flagged the same issue
	routeConfirmed     = 10  // a live request confirmed the vulnerable route
	reachableTaint     = 10  // AST proved a source→sink taint path
	provenPathBonus    = 5   // confirmed route AND reachable taint chain
	payloadValidated   = 10  // an active probe payload elicited a confirming response
	directObservation  = 30  // the claim is a deterministic read of a live response (header/cookie/CORS value present or absent)
	tierTreeSitterBump = 5   // highest-trust analyzer tier
	tierSemgrepPenalty = -5  // lowest-trust analyzer tier (regex breadth)
	httpContextPenalty = -15 // B4: finding fired on a 4xx / static-asset context
	placeholderPenalty = -20 // the credential value matches deterministic fixture heuristics

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
//
// CALLER CONTRACT: several rules here (payload-validated, the B4
// ResponseContext de-escalation, the lineage reason line) read fields that
// exist ONLY on evidence.Evidence — models.Finding has no home for them. So
// scoring an Evidence rebuilt from a projected Finding silently skips those
// rules. Anything downstream of the Evidence→Finding projection must run its
// input through evidence.ProvenanceIndex.Restore first; the orchestrator does
// this in stampDecisions, and
// TestScoringProvenanceSurvivesTheFindingProjection guards it.
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
	// A deterministic read of a live response — a header present or absent, a
	// cookie attribute present or absent, a literal CORS header value — is
	// near-certain: there is no inference step between the bytes on the wire
	// and the claim. Gated on hasRuntime because the concept is DAST-only; a
	// static analyzer can never make this observation, and the gate stops a
	// future SAST emitter from claiming the bonus.
	//
	// The delta is 30, not 25. At +25 a clean direct observation lands on
	// exactly bandHigh (35+10+25 == 70) with zero margin, and correlation can
	// never lift these categories higher — engine.categoryMap covers only
	// secrets/injection/auth, so a headers/cookie/cors finding is never
	// SourceCorrelated. Any future negative delta would then drop every one of
	// them out of HIGH in a single step. At +30 a clean observation sits at 75,
	// and one carrying the B4 context penalty lands at 60 — still MEDIUM, which
	// is precisely the de-escalation the 4xx / static-asset FP classes need.
	if hasRuntime && ev.DirectObservation {
		add(directObservation, "direct observation: the finding is a deterministic read of a live response")
	}
	switch ev.SourceTier {
	case models.TierTreeSitter:
		add(tierTreeSitterBump, "high-trust analyzer tier (tree-sitter taint)")
	case models.TierSemgrepShim:
		add(tierSemgrepPenalty, "lower-trust analyzer tier (semgrep regex breadth)")
	}

	// B4: de-escalate (not suppress) DAST findings that fired on a 4xx
	// (auth-gated/client-error) response or a static-asset endpoint. Evidence
	// is preserved (Rule 3); only the confidence score drops.
	switch ev.ResponseContext {
	case "4xx":
		add(httpContextPenalty, "finding fired on a 4xx (auth-gated/client-error) response")
	case "static-asset":
		add(httpContextPenalty, "finding fired on a static-asset endpoint, not an API route")
	}

	// De-escalate (never suppress) a credential finding whose value is shaped
	// like a fixture. The classification itself is computed deterministically
	// in scanner/secrets and carried on the Evidence, so nothing here is
	// heuristic at scoring time (Rule 8) and the finding is still reported in
	// full with its evidence intact (Rule 3).
	if ev.Placeholder {
		add(placeholderPenalty, "credential value matches deterministic placeholder heuristics (fixture-shaped)")
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
