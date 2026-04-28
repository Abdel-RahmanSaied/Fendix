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
//   - Primary kept = first-seen finding (preserves Evidence, Fix, ID order)
//   - AffectedEndpoints = sorted, deduped list of all endpoints in the group
//     (includes the primary so consumers can iterate one field)
//   - References = union of all groups' References, deduped, sorted
//   - Confidence = highest in the group (HIGH > MEDIUM > LOW)
//   - Source = SourceCorrelated if any member is correlated, else most-trusted
//     (correlated > blackbox > whitebox); a mix of black + white without an
//     existing correlated entry would have been merged by Correlate already,
//     so this fallback only matters for same-source groups.
//
// Findings are returned in the same relative order as the first occurrence
// of each group's primary in the input.
func Deduplicate(findings []models.Finding) []models.Finding {
	if len(findings) <= 1 {
		return findings
	}

	type groupState struct {
		primary   models.Finding
		endpoints map[string]bool
		refs      map[string]bool
		// firstIdx keeps the primary in its original relative position so
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
				endpoints: map[string]bool{f.Endpoint: true},
				refs:      stringSet(f.References),
				firstIdx:  i,
			}
			groups[key] = g
			order = append(order, key)
			continue
		}
		// Merge endpoint, references, and upgrade severity-adjacent fields.
		if f.Endpoint != "" {
			g.endpoints[f.Endpoint] = true
		}
		for _, r := range f.References {
			g.refs[r] = true
		}
		if confidenceRank(f.Confidence) > confidenceRank(g.primary.Confidence) {
			g.primary.Confidence = f.Confidence
		}
		g.primary.Source = mergeSource(g.primary.Source, f.Source)
	}

	// Sort group keys back to insertion order so the output preserves first-
	// occurrence ordering. (map iteration is random in Go.)
	sort.SliceStable(order, func(i, j int) bool {
		return groups[order[i]].firstIdx < groups[order[j]].firstIdx
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
