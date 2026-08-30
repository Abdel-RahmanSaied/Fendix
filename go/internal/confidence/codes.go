package confidence

// Stable machine-readable identities for the scoring rules in Score, and for
// the enforcement lines the decision layer appends to the same breakdown.
//
// THESE ARE A PUBLISHED CONTRACT. They travel into the native JSON report and
// into SARIF `properties.confidence_breakdown`, where downstream policy keys
// off them. The wording in a Reason's Text may be reworded freely; a Code may
// not be renamed without breaking every consumer that matched on it.
//
// Codes are snake_case and name the RULE, not its direction: a de-escalation
// is identified by its negative Delta, not by a "penalty" suffix in the name.
const (
	CodeBaseDetection          = "base_detection"
	CodeStaticEvidence         = "static_evidence"
	CodeRuntimeEvidence        = "runtime_evidence"
	CodeCrossEngineAgreement   = "cross_engine_agreement"
	CodeImportedEvidence       = "imported_evidence"
	CodeImportedHighPrecision  = "imported_high_precision"
	CodeImportedLowPrecision   = "imported_low_precision"
	CodeRouteConfirmed         = "route_confirmed"
	CodeReachableTaintPath     = "reachable_taint_path"
	CodeProvenPath             = "proven_path"
	CodePayloadValidated       = "payload_validated"
	CodeDirectObservation      = "direct_observation"
	CodeDeterministicDetection = "deterministic_detection"
	CodeTierTreeSitter         = "tier_tree_sitter"
	CodeTierSemgrep            = "tier_semgrep"
	CodeCrossToolCorroborated  = "cross_tool_corroborated"
	CodeHTTPContext4xx         = "http_context_4xx"
	CodeHTTPContextStaticAsset = "http_context_static_asset"
	CodeFixtureShapedValue     = "fixture_shaped_value"
	CodeComponentNotImported   = "component_not_imported"
	CodeEvidenceLineage        = "evidence_lineage"
	CodeCorroborationCeiling   = "corroboration_ceiling"
)

// Enforcement codes. These name lines the DECISION layer appends to the same
// breakdown: zero-delta records of an enforcement choice — why blocking was
// withheld, or why a finding was de-escalated. They carry Delta 0 by
// construction because a demotion is an enforcement decision, never a
// re-scoring of the evidence.
//
// They live here, beside the scoring codes, because both end up in ONE
// published array. A consumer reading confidence_breakdown must be able to
// resolve every code it sees against a single namespace.
const (
	CodeHeldUnconfirmedByLiveScan          = "held_unconfirmed_by_live_scan"
	CodeHeldConfidenceLow                  = "held_confidence_low"
	CodeHeldUncorroborated                 = "held_uncorroborated"
	CodeHeldMediumNoIndependent            = "held_medium_no_independent_signal"
	CodeNotApplicableComponentAbsent       = "not_applicable_component_absent"
	CodeDeescalatedTestFixture             = "deescalated_test_fixture"
	CodeDeescalatedTestFixtureThreshold    = "deescalated_test_fixture_threshold_met"
	CodeDeescalatedTestFixtureCorroborated = "deescalated_test_fixture_corroborated"
)
