// Package decision is the Decision layer in Fendix's
// Engine → Evidence → Finding → Decision architecture.
//
// A Decision is the verdict for a piece of Evidence: should this finding BLOCK
// the build, merely WARN, be INFO, or be IGNOREd. Since v0.24 this layer is NOT
// parallel bookkeeping — it IS the product: orchestrator.Run stamps every
// finding's published `status` from stampDecisions and then returns
// decision.ExitCode(decisions) as the process exit code. The legacy checkFailOn
// helper no longer exists anywhere in the module; the comments that still name
// it mark the behaviour this package must reproduce, not live code.
//
// Two entry points, deliberately:
//
//   - Decide / DecideAll take no Options and implement the LEGACY,
//     severity-only mapping (block iff severity >= --fail-on). Production does
//     not take this path any more. It is retained because it is the oracle
//     TestExitCodeMatchesLegacyCheckFailOn locks, and that lock is what makes
//     `--enforce-confidence=false` a byte-for-byte-compatible escape hatch
//     rather than a promise.
//   - DecideWithOptions / DecideAllWithOptions take the scan policy and are
//     what the orchestrator calls. Under Options.EnforceConfidence (the CLI
//     default) a finding at or above --fail-on BLOCKs only when the
//     deterministic confidence band supports the claim; under
//     Options.DeescalateTests an uncorroborated finding in test/fixture code is
//     held at WARN.
//
// Neither policy ever drops a finding, edits its evidence text or changes its
// confidence score (Rule 3 / Rule 8): the only things that move are
// Decision.Status, Decision.Reason and one appended 0-point Score.Reasons line
// explaining the move.
package decision

import (
	"strings"

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

// Decision is the internal verdict plus its justification.
type Decision struct {
	Status     Status
	Confidence models.Confidence
	Reason     string
	// Score is the deterministic confidence score (0–100) + plain-text reason
	// breakdown for this decision. Stamped onto the finding as
	// confidence_score / confidence_band / confidence_reasons.
	Score confidence.Result
	// Evidence is the supporting evidence this verdict was derived from.
	Evidence evidence.Evidence

	// aboveThreshold records that this finding's severity met --fail-on,
	// independent of what the confidence policy then did with it. It is the
	// floor DecideWithOptions uses to keep a threshold-crossing finding from
	// sinking all the way to INFO after a demotion. Unexported on purpose:
	// nothing serializes Decision, and it is policy bookkeeping, not a verdict.
	aboveThreshold bool
}

// Decide computes the Decision for one piece of evidence under the given
// --fail-on threshold (the raw flag value; "" = no threshold), using the
// LEGACY severity-only mapping: block iff failOn is a valid severity (rank > 0)
// and the evidence's severity rank is at or above it. Identical to the
// pre-v1.2.2 checkFailOn.
//
// This is the frozen compatibility oracle, not the production path — see the
// package doc. Production calls DecideWithOptions; passing a zero Options there
// reproduces exactly this mapping, which is the --enforce-confidence=false
// contract.
func Decide(ev evidence.Evidence, failOn string) Decision {
	return decide(ev, failOn, Options{})
}

// decide is the shared body. opts.EnforceConfidence changes ONLY the
// at-or-above-threshold arm; the WARN (actionable, below threshold) and INFO
// (informational) arms are byte-identical in both modes, so a finding that
// never met --fail-on is unaffected by the confidence policy.
func decide(ev evidence.Evidence, failOn string, opts Options) Decision {
	threshold := 0
	if failOn != "" {
		threshold = models.SeverityRank(models.Severity(failOn))
	}
	rank := models.SeverityRank(ev.Severity)

	d := Decision{Confidence: ev.Confidence, Score: confidence.Score(ev), Evidence: ev}
	d.aboveThreshold = threshold > 0 && rank >= threshold
	switch {
	case d.aboveThreshold:
		if opts.EnforceConfidence {
			applyConfidenceGate(&d, ev)
		} else {
			d.Status = StatusBlock
			d.Reason = "severity at or above the --fail-on threshold"
		}
	case rank >= models.SeverityRank(models.SeverityMedium):
		d.Status = StatusWarn
		d.Reason = "actionable finding below the --fail-on threshold"
	default:
		d.Status = StatusInfo
		d.Reason = "informational finding"
	}
	return d
}

// applyConfidenceGate is FIX-08: a finding whose severity met --fail-on BLOCKs
// only when the deterministic confidence band supports the claim.
//
// The rule table, in evaluation order:
//
//	marked unconfirmed-by-live-scan, no corroboration → WARN
//	band LOW                                          → WARN
//	band MEDIUM, no corroborating signal              → WARN
//	band MEDIUM, ≥1 corroborating signal              → BLOCK
//	band HIGH                                         → BLOCK
//
// The unconfirmed arm runs FIRST and is band-independent: the correlator set
// that marker because a live scan ran and did NOT confirm this finding, which
// is a direct contradiction of the claim rather than merely weak support for
// it. Reporting "[Unconfirmed by live scan]" in the evidence text and failing
// the build on the same finding is the specific incoherence FIX-08 exists to
// remove, so no band alone lifts it — only an actual corroborating signal does.
//
// Every WARN arm appends one 0-point line to the score breakdown. It must be
// 0-point and carry an explicit "+0 " prefix: confidence_reasons is published
// alongside confidence_score and the two have to reconcile (Rule 8 —
// engine.assertReasonsSumToScore and confidence.TestReasonsSumToValue both
// parse the leading signed delta). The score itself never moves; a demotion is
// an ENFORCEMENT decision, not a re-scoring of the evidence.
func applyConfidenceGate(d *Decision, ev evidence.Evidence) {
	sigs := corroborations(ev)

	hold := func(reason string) {
		d.Status = StatusWarn
		d.Reason = reason
		d.Score.Reasons = appendReason(d.Score.Reasons, "+0 held at WARN: "+reason)
	}

	switch {
	case ev.UnconfirmedByLiveScan && len(sigs) == 0:
		hold("severity at or above the --fail-on threshold but the finding is unconfirmed " +
			"by live scan and uncorroborated — needs corroboration to block")
	case d.Score.Band == models.ConfidenceLow:
		hold("severity above threshold but confidence LOW — needs corroboration to block")
	case d.Score.Band == models.ConfidenceMedium && len(sigs) == 0:
		hold("severity above threshold but confidence MEDIUM with no corroborating signal — " +
			"needs corroboration to block")
	case d.Score.Band == models.ConfidenceMedium:
		d.Status = StatusBlock
		d.Reason = "severity at or above the --fail-on threshold; corroborated by: " + strings.Join(sigs, ", ")
	default: // ConfidenceHigh
		d.Status = StatusBlock
		d.Reason = "severity at or above the --fail-on threshold; confidence HIGH"
		if len(sigs) > 0 {
			d.Reason += "; corroborated by: " + strings.Join(sigs, ", ")
		}
	}
}

// corroborations names every corroborating signal present on ev, in a FIXED
// order. Pure and deterministic (Rule 8): a fixed sequence of ifs, never a map
// or a set, because the result is joined into Decision.Reason and the
// order-independence locks compare those strings verbatim.
//
// Returns nil (not an empty slice) when nothing fires, so `len(...) == 0` is
// the single corroboration predicate everywhere.
//
// On the two "observation" signals — DECISIONS.md D7 is binding here, and the
// distinction is easy to collapse by accident:
//
//   - liveRuntimeObservation is keyed on Source (blackbox or correlated): the
//     finding came from a live probe against a running target at all. It is
//     deliberately WIDER than evidence.Evidence.DirectObservation.
//   - Evidence.DirectObservation is the narrow deterministic-read flag the
//     header/cookie/CORS checks set, and it is scored separately by
//     confidence.directObservation.
//
// If this predicate were "unified" onto the narrow field, every active-probe
// DAST finding (injection, XSS, SSRF, GraphQL) would lose its ONLY corroborator
// — those scanners do not set DirectObservation — and a pure-blackbox finding
// sits at 35 base + 10 runtime = 45, MEDIUM band. The whole live-scan gate would
// silently disappear. Hence both, OR-ed.
//
// confidence.HasDeterministicDetection is the static mirror of the same idea and
// is called rather than re-derived, so the corroboration predicate cannot drift
// from the delta that pays for it.
//
// Note on payload validation: it mirrors confidence.go's rule exactly (Payload
// AND Response), and evidence.Evidence.Response has no production producer
// today, so this arm is forward-compatibility only. Do not build a test or a
// gating expectation on it.
func corroborations(ev evidence.Evidence) []string {
	liveRuntimeObservation := ev.Source == models.SourceBlackbox || ev.Source == models.SourceCorrelated

	var sigs []string
	if ev.Source == models.SourceCorrelated {
		sigs = append(sigs, "cross-engine agreement")
	}
	if liveRuntimeObservation {
		sigs = append(sigs, "live runtime observation")
	}
	if ev.DirectObservation {
		sigs = append(sigs, "direct observation of a live response")
	}
	if confidence.HasDeterministicDetection(ev) {
		sigs = append(sigs, "deterministic detection in production code")
	}
	if ev.RouteConfirmed {
		sigs = append(sigs, "confirmed route")
	}
	if ev.Reachable {
		sigs = append(sigs, "reachable taint path")
	}
	if ev.ProvenPath {
		sigs = append(sigs, "proven path")
	}
	if ev.Payload != "" && ev.Response != "" {
		sigs = append(sigs, "payload-validated probe")
	}
	return sigs
}

// appendReason appends one explainability line to a fresh copy of the reason
// slice. Copying is not optional: confidence.Score builds Reasons once per
// call, and appending in place could write into a backing array another
// Decision shares, making the published output depend on evaluation order
// (TestDeescalationDoesNotAliasTheSharedReasonSlice guards this).
func appendReason(reasons []string, line string) []string {
	return append(append([]string(nil), reasons...), line)
}

// Options tunes the decision policy.
//
// ZERO-VALUE POLARITY MATTERS. Both fields default to false = legacy, while
// both CLI flags default to true. A directly-constructed Options{} — which is
// what most engine tests build — therefore opts OUT of the shipped policy. That
// is exactly the shape that let DeescalateTests ship as dead code (see the
// header comment on internal/engine/deescalate_tests_wiring_test.go): the unit
// tests passed, the docs described the behaviour, and no config field turned it
// on. If you add a field here, add a wiring test that drives it from
// models.ScanConfig, not just from a literal.
type Options struct {
	// DeescalateTests drops findings in test / fixture code (evidence
	// preserved — Rule 3): WARN → INFO, and an UNCORROBORATED BLOCK → WARN.
	// A corroborated test-code finding — e.g. a provider-validated live
	// credential committed into a fixture — still BLOCKs. Overridable so a
	// team that DOES want to gate on every test-code finding can turn it off
	// with --deescalate-tests=false. (B3 / FIX-09.)
	DeescalateTests bool

	// EnforceConfidence gates the --fail-on threshold on the deterministic
	// confidence band: at or above the threshold, a finding BLOCKs only when
	// its band supports the claim (HIGH always; MEDIUM with at least one
	// corroborating signal; LOW never), and a finding the correlator marked
	// unconfirmed-by-live-scan never blocks on its own. Evidence is never
	// suppressed — only enforcement moves. (FIX-08.)
	//
	// The CLI default is true (--enforce-confidence). Setting it false
	// restores the legacy severity-only mapping BYTE-FOR-BYTE; it does not
	// also disable the test-fixture rule, which is gated on DeescalateTests.
	EnforceConfidence bool
}

// testFixtureReason is the 0-point explainability line appended to the score
// breakdown when the test-fixture WARN → INFO de-escalation fires. It carries
// an explicit "+0" so the published reasons still sum to ConfidenceScore — the
// de-escalation changes the decision STATUS, never the score (the same
// zero-delta convention confidence.lineageTrace uses).
const testFixtureReason = "+0 de-escalated to INFO: finding is in test/fixture code " +
	"(rule: test-fixture; evidence preserved)"

// testFixtureBlockReason is the same line for FIX-09's BLOCK → WARN arm. Kept
// separate so the report distinguishes "this was never going to gate anything"
// from "this crossed your --fail-on threshold and we held it at WARN".
const testFixtureBlockReason = "+0 de-escalated to WARN: finding is in test/fixture code " +
	"with no corroborating signal (rule: test-fixture; evidence preserved)"

// DecideWithOptions is the production entry point: decide() under the scan
// policy, plus the test-fixture de-escalation.
//
// The test-fixture rule (B3, extended by FIX-09) reads:
//
//   - BLOCK + no corroborating signal → WARN. 31 of the 35 catalogued false
//     positives in tasks/FP_CORPUS.md are test fixtures, and before FIX-09 the
//     rule only demoted WARN → INFO — so the project's single largest FP class
//     was structurally exempt from its own mitigation whenever a team set
//     --fail-on. A CORROBORATED test-code finding still BLOCKs, which is what
//     keeps this de-escalation rather than path suppression (Rule 3).
//   - WARN + below --fail-on → INFO. The original v1.1 rule, unchanged.
//
// The arms are mutually exclusive by construction (a switch on the status
// decide() produced), so exactly ONE 0-point reason line is ever appended —
// TestDeescalationIsExplainedInTheScoreReasons locks that arithmetic.
//
// THE FLOOR: a finding whose severity met --fail-on is never reported below
// WARN. Without it, a threshold-crossing test-code finding could be demoted
// BLOCK → WARN here (or WARN by the confidence gate) and then demoted again
// WARN → INFO by the second arm, burying it at the same level as a
// below-threshold LOW. d.aboveThreshold is the guard.
//
// CALLER CONTRACT: the de-escalation keys off ev.InTest, which is
// Evidence-internal and therefore does NOT survive the Evidence→Finding
// projection. Callers downstream of that projection MUST run their input
// through evidence.ProvenanceIndex.Restore first; the orchestrator does this in
// stampDecisions. Deliberately there is no fall back to re-deriving the flag
// from ev.Endpoint here: for a deduplicated finding the primary endpoint is
// only one member of the group, so path-matching it directly would let a single
// test occurrence de-escalate a group that also contains production
// occurrences. The index's "agree or drop" fold is the only correct source.
func DecideWithOptions(ev evidence.Evidence, failOn string, opts Options) Decision {
	d := decide(ev, failOn, opts)
	if !opts.DeescalateTests || !ev.InTest {
		return d
	}
	switch d.Status {
	case StatusBlock:
		// A corroborated finding in test code still gates the build: a live
		// credential that a provider validated is a real leak wherever the
		// file happens to live.
		if len(corroborations(ev)) == 0 {
			d.Status = StatusWarn
			d.Reason = "de-escalated to WARN: finding is in test/fixture code with no corroborating " +
				"signal beyond the pattern match (rule: test-fixture; evidence preserved; " +
				"--fail-on threshold was met)"
			d.Score.Reasons = appendReason(d.Score.Reasons, testFixtureBlockReason)
		}
	case StatusWarn:
		if !d.aboveThreshold {
			d.Status = StatusInfo
			d.Reason = "de-escalated to INFO: finding is in test/fixture code (rule: test-fixture; evidence preserved)"
			// Surface the de-escalation in the published breakdown too. Without
			// this the report shows a finding silently demoted to INFO with
			// nothing in confidence_reasons explaining why.
			d.Score.Reasons = appendReason(d.Score.Reasons, testFixtureReason)
		}
	}
	return d
}

// DecideAll maps a slice of evidence to decisions under one threshold, using
// the legacy zero-Options mapping (no confidence gate, no test-fixture
// de-escalation). See the package doc: this is the compatibility oracle, not
// the production path.
func DecideAll(evs []evidence.Evidence, failOn string) []Decision {
	return DecideAllWithOptions(evs, failOn, Options{})
}

// DecideAllWithOptions maps a slice of evidence to decisions under one
// threshold and one policy. This is the production entry point the
// orchestrator uses; DecideAll is the zero-Options convenience wrapper kept
// for callers that predate the policy.
func DecideAllWithOptions(evs []evidence.Evidence, failOn string, opts Options) []Decision {
	if evs == nil {
		return nil
	}
	out := make([]Decision, len(evs))
	for i, ev := range evs {
		out[i] = DecideWithOptions(ev, failOn, opts)
	}
	return out
}

// ExitCode reproduces checkFailOn's exit semantics from a set of decisions:
// 1 if any decision BLOCKs, else 0. orchestrator.Run returns this directly, so
// it is the process exit code — under the default policy a finding the
// confidence gate held at WARN no longer contributes a 1.
func ExitCode(decisions []Decision) int {
	for _, d := range decisions {
		if d.Status == StatusBlock {
			return 1
		}
	}
	return 0
}
