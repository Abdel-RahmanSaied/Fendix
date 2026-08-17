package engine

import (
	"sort"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Deduplicate collapses findings with the same (Title, Category, Severity)
// into a single finding whose AffectedEndpoints lists every distinct endpoint.
//
// This addresses the "missing CSP header × 21 endpoints" problem from the
// 2026-04-28 real-world test pass: a passive header check fired once per
// scanned endpoint, producing 21 nearly-identical entries that all reported
// the same fix. Post-dedup, the user sees one finding with 21 affected
// endpoints — same actionable information, far less noise.
//
// Dedup runs AFTER correlation so correlated findings (which already merged
// black-box + white-box pairs) are deduped against each other too.
//
// Merge rules:
//   - Primary kept = the total-order-minimum finding in the group (F-L6).
//     Picking by a deterministic tiebreaker — not "first seen" — means the
//     merged Evidence/Fix/Endpoint/Line are identical no matter what order
//     the findings arrived in (worker-pool result interleaving is
//     non-deterministic). The tiebreaker is endpoint, then evidence, then
//     fix, then line (see findingLess).
//   - AffectedEndpoints = sorted, deduped list of all endpoints in the group
//     (includes the primary so consumers can iterate one field)
//   - References = union of all groups' References, deduped, sorted
//   - Confidence = highest in the group (HIGH > MEDIUM > LOW)
//   - Source = SourceCorrelated if any member is correlated, else most-trusted
//     (correlated > blackbox > whitebox); a mix of black + white without an
//     existing correlated entry would have been merged by Correlate already,
//     so this fallback only matters for same-source groups.
//
// Findings are returned in first-occurrence order of each group's key, with
// the dedupKey itself as a total-order tiebreaker so the output sequence is
// fully determined by the input SET (F-L6) rather than the input permutation.
func Deduplicate(findings []models.Finding) []models.Finding {
	if len(findings) <= 1 {
		return findings
	}

	type groupState struct {
		primary   models.Finding
		endpoints map[string]bool
		refs      map[string]bool
		// firstIdx keeps the group in its original relative position so
		// downstream sort/ID assignment stays stable.
		firstIdx int
	}

	groups := make(map[string]*groupState)
	order := make([]string, 0, len(findings))

	for i, f := range findings {
		key := dedupKey(f)
		g, ok := groups[key]
		if !ok {
			g = &groupState{
				primary:   f,
				endpoints: endpointSet(f),
				refs:      stringSet(f.References),
				firstIdx:  i,
			}
			groups[key] = g
			order = append(order, key)
			continue
		}
		// Merge endpoint and references.
		if f.Endpoint != "" {
			g.endpoints[f.Endpoint] = true
		}
		// Fold in any endpoints the member ALREADY carried. Without this the
		// group's endpoint set depended on arrival order: only the first
		// member's AffectedEndpoints was seeded, and a later member's list was
		// dropped — so two runs over the same finding SET could publish
		// different affected_endpoints, and (since the scoring-provenance fold
		// walks that list) different confidence scores and decision statuses.
		// F-L6 requires the output be a function of the set, not the sequence.
		for _, ep := range f.AffectedEndpoints {
			if ep != "" {
				g.endpoints[ep] = true
			}
		}
		for _, r := range f.References {
			g.refs[r] = true
		}
		// Severity-adjacent fields are accumulated independently of which
		// finding ends up being the primary, so they stay order-invariant.
		mergedConfidence := g.primary.Confidence
		if confidenceRank(f.Confidence) > confidenceRank(mergedConfidence) {
			mergedConfidence = f.Confidence
		}
		mergedSource := mergeSource(g.primary.Source, f.Source)
		// Deterministic primary: adopt f's identity fields only when it
		// sorts strictly before the current primary. This makes the kept
		// Evidence/Fix/Endpoint/Line a pure function of the group's member
		// SET, not the arrival order (F-L6).
		if findingLess(f, g.primary) {
			g.primary = f
		}
		g.primary.Confidence = mergedConfidence
		g.primary.Source = mergedSource
	}

	// Order groups by first-occurrence, with the dedupKey as a total-order
	// tiebreaker. firstIdx alone is permutation-dependent; appending the key
	// gives a deterministic sequence for any input ordering of the same set.
	sort.SliceStable(order, func(i, j int) bool {
		gi, gj := groups[order[i]], groups[order[j]]
		if gi.firstIdx != gj.firstIdx {
			return gi.firstIdx < gj.firstIdx
		}
		return order[i] < order[j]
	})

	out := make([]models.Finding, 0, len(order))
	for _, key := range order {
		g := groups[key]
		// Only set AffectedEndpoints when there's > 1 endpoint — a singleton
		// would just duplicate the existing Endpoint field.
		if len(g.endpoints) > 1 {
			g.primary.AffectedEndpoints = sortedKeys(g.endpoints)
		}
		g.primary.References = sortedKeys(g.refs)
		out = append(out, g.primary)
	}
	return out
}

// dedupKey returns the equivalence-class key for grouping. (Title, Category,
// Severity) is intentionally narrow — same vuln type at the same severity is
// the same finding. We don't include Source because the same vuln reported
// by both black-box and white-box (without going through the correlator)
// should still collapse.
func dedupKey(f models.Finding) string {
	return string(f.Severity) + "|" + f.Category + "|" + f.Title
}

// findingLess is the total order used to pick a group's primary
// representative deterministically (F-L6). Two findings in the same group
// share (Severity, Category, Title) by construction, so the discriminating
// fields are the per-occurrence ones: Endpoint, then Evidence, then Fix,
// then Line. Comparing these — rather than relying on arrival order — makes
// the kept Evidence/Fix/Endpoint a pure function of the group's member set,
// so a re-ordered scan produces the byte-identical merged finding.
func findingLess(a, b models.Finding) bool {
	if a.Endpoint != b.Endpoint {
		return a.Endpoint < b.Endpoint
	}
	if a.Evidence != b.Evidence {
		return a.Evidence < b.Evidence
	}
	if a.Fix != b.Fix {
		return a.Fix < b.Fix
	}
	return derefLine(a.Line) < derefLine(b.Line)
}

// derefLine flattens a *string Line into a comparable value; a nil pointer
// sorts before any present value so the order is total and nil-safe.
func derefLine(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// confidenceRank returns a numeric rank so we can pick the highest in a group.
// HIGH=3, MEDIUM=2, LOW=1, else=0.
func confidenceRank(c models.Confidence) int {
	switch c {
	case models.ConfidenceHigh:
		return 3
	case models.ConfidenceMedium:
		return 2
	case models.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// mergeSource picks the more-trusted source for a merged group. Correlated
// always wins (it's already a hybrid signal); among non-correlated, blackbox
// outranks whitebox (a confirmed-by-traffic finding is more actionable than
// a static-only one). Same-source merges return the source unchanged.
func mergeSource(a, b models.Source) models.Source {
	if a == models.SourceCorrelated || b == models.SourceCorrelated {
		return models.SourceCorrelated
	}
	if a == models.SourceBlackbox || b == models.SourceBlackbox {
		return models.SourceBlackbox
	}
	return a
}

// endpointSet seeds a group's endpoint set from one finding: its primary
// Endpoint plus any AffectedEndpoints it already carries (an out-of-tree
// plugin or a re-ingested report may supply them). Empty strings are dropped
// so a finding with no endpoint cannot inject "" into a group's
// AffectedEndpoints list.
func endpointSet(f models.Finding) map[string]bool {
	out := make(map[string]bool, len(f.AffectedEndpoints)+1)
	if f.Endpoint != "" {
		out[f.Endpoint] = true
	}
	for _, ep := range f.AffectedEndpoints {
		if ep != "" {
			out[ep] = true
		}
	}
	return out
}

// stringSet builds a presence-only set from a slice. Nil input returns an
// empty (but non-nil) map so callers can always do `set[x] = true`.
func stringSet(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		if x != "" {
			out[x] = true
		}
	}
	return out
}

// sortedKeys returns the keys of a presence map in deterministic order.
// Used to make dedup output stable for snapshot-style tests and reports.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
