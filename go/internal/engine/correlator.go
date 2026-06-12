package engine

import (
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// correlationKey identifies a finding by its normalized endpoint and category
// for cross-referencing blackbox and whitebox results.
type correlationKey struct {
	endpoint string
	category string
}

// categoryMap maps whitebox categories to their blackbox counterparts
// for cross-correlation matching.
var categoryMap = map[string]string{
	"secrets":   "data_exposure",
	"injection": "injection",
	"auth":      "auth_bypass",
}

// methodPrefixRe strips a leading HTTP method token from an endpoint string.
// Whitebox emitters such as the spec parser format endpoints as "GET /pet/findByStatus";
// without stripping, the leading "GET " corrupts URL parsing and fuzzy-segment matching.
var methodPrefixRe = regexp.MustCompile(`(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+`)

// Correlate cross-references blackbox and whitebox findings.
//
// Rules:
//   - If both engines agree on a vulnerability (same normalized endpoint + related category):
//     merge into a single correlated finding with source=correlated, confidence=HIGH,
//     and severity escalated by one level.
//   - If whitebox finds an issue at a URL endpoint but blackbox does NOT confirm:
//     keep whitebox finding, confidence=MEDIUM, add "Unconfirmed by live scan" note.
//     The note is only added when the whitebox endpoint normalises to a URL
//     path (`/...`) — file:line findings such as a hardcoded secret in
//     `src/config.py:14` cannot be confirmed by a live HTTP scan, so the
//     suffix is misleading there and is skipped (TASK-092).
//   - If blackbox finds an issue but no whitebox counterpart:
//     keep as-is.
//
// Match strategy (per whitebox finding, in order):
//  1. Exact normalized endpoint + related category (fast path via index).
//  2. Path-suffix match: one normalized path is a suffix of the other on a `/`
//     boundary. Handles base-path skew (whitebox `/pet/findByStatus`
//     matches blackbox `/api/v3/pet/findByStatus`).
//  3. Fuzzy segment match: at least one non-noise path segment of length > 2 is
//     shared. Handles file-path-vs-URL-path matches like `routes/users.py` vs
//     `/api/v1/users`.
//
// Each blackbox finding can correlate with at most one whitebox finding.
func Correlate(findings []models.Finding) []models.Finding {
	var blackbox, whitebox []models.Finding
	for _, f := range findings {
		switch f.Source {
		case models.SourceBlackbox:
			blackbox = append(blackbox, f)
		case models.SourceWhitebox:
			whitebox = append(whitebox, f)
		default:
			// Already correlated or unknown source — pass through
			blackbox = append(blackbox, f)
		}
	}

	slog.Debug("correlator inputs",
		"blackbox_count", len(blackbox),
		"whitebox_count", len(whitebox),
	)

	if len(whitebox) == 0 || len(blackbox) == 0 {
		// Nothing to correlate — return all findings as-is.
		// When some live scan ran (blackbox findings exist) but didn't match
		// a given whitebox finding, downgrade that finding's confidence and
		// suffix its evidence. The suffix is only meaningful for whitebox
		// findings tied to a URL endpoint; file-path findings (e.g. a
		// hardcoded secret at src/config.py:14) cannot be confirmed by a
		// live scan, so they keep their original evidence and confidence.
		if len(blackbox) == 0 && len(whitebox) > 0 {
			for i := range whitebox {
				if isURLEndpoint(whitebox[i].Endpoint) {
					whitebox[i].Confidence = models.ConfidenceMedium
					whitebox[i].Evidence += " [Unconfirmed by live scan]"
				}
			}
		}
		result := make([]models.Finding, 0, len(blackbox)+len(whitebox))
		result = append(result, blackbox...)
		result = append(result, whitebox...)
		return result
	}

	// Pre-compute normalized blackbox endpoints once. The suffix and fuzzy
	// passes walk all blackbox findings per whitebox finding, and re-running
	// url.Parse on every iteration is the dominant allocator for large scans.
	//
	// Also pre-compute the per-blackbox segment set used by the fuzzy
	// matcher. The fuzzy pass calls pathSegments on BOTH sides of every
	// (W,B) comparison; caching the blackbox side here means the segment
	// split runs B times instead of W·B times. The matching whitebox
	// segment is cached once per whitebox iteration inside the Correlate
	// loop below (see `wbSegments` capture).
	bbNorm := make([]string, len(blackbox))
	bbSegments := make([][]string, len(blackbox))
	bbIndex := make(map[correlationKey][]int)
	for i, f := range blackbox {
		bbNorm[i] = normalizeEndpoint(f.Endpoint)
		bbSegments[i] = pathSegments(bbNorm[i])
		bbIndex[correlationKey{endpoint: bbNorm[i], category: f.Category}] = append(
			bbIndex[correlationKey{endpoint: bbNorm[i], category: f.Category}], i,
		)
	}

	// Track which blackbox findings are already merged so we don't merge the
	// same one twice with different whitebox findings.
	bbCorrelated := make(map[int]bool)

	var result []models.Finding

	for _, wf := range whitebox {
		wbNorm := normalizeEndpoint(wf.Endpoint)
		relCats := relatedCategories(wf.Category)
		// Cache the whitebox segments once per iteration of the outer
		// loop; the fuzzy pass would otherwise re-split this string
		// on every (W,B) comparison.
		wbSegments := pathSegments(wbNorm)

		bbIdx, matchKind := findCorrelationMatch(wbNorm, wbSegments, relCats, blackbox, bbNorm, bbSegments, bbIndex, bbCorrelated)
		if bbIdx >= 0 {
			bf := blackbox[bbIdx]
			bbCorrelated[bbIdx] = true
			merged := mergeFindings(bf, wf)
			result = append(result, merged)
			slog.Info("correlated finding",
				"wb_endpoint", wf.Endpoint,
				"bb_endpoint", bf.Endpoint,
				"wb_category", wf.Category,
				"bb_category", bf.Category,
				"match_kind", matchKind,
			)
			continue
		}

		slog.Debug("correlator no blackbox match",
			"wb_title", wf.Title,
			"wb_endpoint_norm", wbNorm,
			"wb_category", wf.Category,
		)

		// Unconfirmed whitebox finding. Suffix only when the endpoint is a
		// URL — file:line findings can't be confirmed by a live scan.
		if isURLEndpoint(wf.Endpoint) {
			wf.Confidence = models.ConfidenceMedium
			wf.Evidence += " [Unconfirmed by live scan]"
		}
		result = append(result, wf)
	}

	// Add uncorrelated blackbox findings as-is
	for i, bf := range blackbox {
		if !bbCorrelated[i] {
			result = append(result, bf)
		}
	}

	return result
}

// findCorrelationMatch returns the index of a blackbox finding that matches
// the whitebox finding identified by `wbNorm` + `relCats`, plus the match
// kind ("exact", "suffix", or "fuzzy"). Returns (-1, "") if no match.
//
// `bbNorm` and `bbSegments` are the pre-computed normalized endpoint and
// segment-set for each blackbox finding (avoids re-running url.Parse and
// pathSegments per inner-loop iteration). `wbSegments` is the same for
// the current whitebox finding. The `taken` set excludes blackbox
// findings already merged into another correlated finding so each
// blackbox is consumed at most once.
func findCorrelationMatch(
	wbNorm string,
	wbSegments []string,
	relCats []string,
	blackbox []models.Finding,
	bbNorm []string,
	bbSegments [][]string,
	bbIndex map[correlationKey][]int,
	taken map[int]bool,
) (int, string) {
	// 1. Exact match via index (fast path).
	for _, cat := range relCats {
		key := correlationKey{endpoint: wbNorm, category: cat}
		for _, idx := range bbIndex[key] {
			if !taken[idx] {
				return idx, "exact"
			}
		}
	}

	// 2. Path-suffix match (handles base-path skew).
	for i, bf := range blackbox {
		if taken[i] {
			continue
		}
		if !categoryRelated(relCats, bf.Category) {
			continue
		}
		if pathSuffixMatch(wbNorm, bbNorm[i]) {
			return i, "suffix"
		}
	}

	// 3. Fuzzy segment match (handles file-path-vs-URL-path).
	// Uses pre-computed segments for both sides — the F2 fix to avoid
	// O(W·B) recomputation of pathSegments inside the inner loop.
	for i, bf := range blackbox {
		if taken[i] {
			continue
		}
		if !categoryRelated(relCats, bf.Category) {
			continue
		}
		if segmentsRelated(wbSegments, bbSegments[i]) {
			return i, "fuzzy"
		}
	}

	return -1, ""
}

// categoryRelated reports whether `bbCat` is in the related-categories list.
func categoryRelated(relCats []string, bbCat string) bool {
	for _, c := range relCats {
		if c == bbCat {
			return true
		}
	}
	return false
}

// mergeFindings creates a correlated finding from matching blackbox and whitebox findings.
// Severity is escalated by one level, confidence is HIGH, source is correlated.
//
// TASK-114: when the whitebox half carries a TaintChain (the AST analyzer
// proved an intra-function source→sink dataflow), the merged finding inherits
// the chain plus Reachable=true and gets a *second* severity escalation. This
// is the "DAST + SAST agree AND we can show the path" case — exactly the
// confirmed-finding-only-when-both-agree wedge promised in the README hero.
func mergeFindings(bb, wb models.Finding) models.Finding {
	severity := escalateSeverity(higherSeverity(bb.Severity, wb.Severity))
	// Proven Path v1 / tier-provenance enforcement: the second "reachable"
	// escalation is the strong claim ("we can show the exploit path"), so it
	// is only granted to the high-trust tree-sitter taint tier. A
	// semgrep_shim finding that never cleared the F1≥0.95 gate must not ride
	// correlation up to CRITICAL — that would silently bypass the gate the
	// roadmap explicitly protects. Empty tier (legacy/native) keeps the
	// prior behaviour so this change can't regress existing escalations.
	if wb.Reachable && wb.SourceTier != models.TierSemgrepShim {
		severity = escalateSeverity(severity)
	}
	merged := models.Finding{
		Title:      bb.Title,
		Severity:   severity,
		Source:     models.SourceCorrelated,
		SourceTier: wb.SourceTier,
		Category:   bb.Category,
		Endpoint:   bb.Endpoint,
		Evidence:   bb.Evidence + " | Code: " + wb.Evidence,
		Fix:        bb.Fix,
		References: mergeRefs(bb.References, wb.References),
		Confidence: models.ConfidenceHigh,
		Line:       wb.Line,
		TaintChain: wb.TaintChain,
		Reachable:  wb.Reachable,
		Route:      wb.Route,
	}
	return merged
}

// normalizeEndpoint extracts a comparable path from an endpoint string,
// stripping HTTP method prefixes, scheme, host, port, and query parameters.
func normalizeEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}

	// Strip a leading HTTP method token (e.g., "GET /pet" → "/pet").
	// Whitebox emitters format endpoints as "<METHOD> <PATH>"; without this,
	// the prefix corrupts both URL parsing and segment matching.
	endpoint = methodPrefixRe.ReplaceAllString(endpoint, "")

	// Handle file:line format (whitebox findings like "src/config.py:14")
	if !strings.Contains(endpoint, "://") && !strings.HasPrefix(endpoint, "/") {
		// Looks like a file path — extract the filename without line number
		parts := strings.SplitN(endpoint, ":", 2)
		return strings.ToLower(parts[0])
	}

	// Handle URL or bare-path format (blackbox findings, or whitebox after
	// method strip).
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return strings.ToLower(endpoint)
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}

	// Remove trailing slash for consistency
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}

	return strings.ToLower(path)
}

// isURLEndpoint reports whether a Finding.Endpoint string points at an HTTP
// endpoint (URL or bare path) rather than a source location like
// "src/config.py:14". The suffix `[Unconfirmed by live scan]` is only
// meaningful for the former — a live HTTP scan cannot confirm a finding
// that lives in source code.
func isURLEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	endpoint = methodPrefixRe.ReplaceAllString(endpoint, "")
	return strings.HasPrefix(endpoint, "/") || strings.Contains(endpoint, "://")
}

// pathSuffixMatch reports whether one normalized path is a suffix of the other
// on a `/` boundary. Both inputs must be URL-style paths starting with `/`;
// file paths and empty inputs return false.
//
// Example: pathSuffixMatch("/pet/findbystatus", "/api/v3/pet/findbystatus") = true.
// Counter-example: pathSuffixMatch("/3/pet", "/api/v3/pet") = false (the suffix
// boundary is mid-segment in `v3`).
func pathSuffixMatch(a, b string) bool {
	if !strings.HasPrefix(a, "/") || !strings.HasPrefix(b, "/") {
		return false
	}
	if a == b {
		return true
	}
	// Reject the trivial root case — every path is a suffix of itself plus "/".
	if a == "/" || b == "/" {
		return false
	}

	short, long := a, b
	if len(b) < len(a) {
		short, long = b, a
	}

	// HasSuffix with a leading-`/` short pattern enforces a clean segment
	// boundary because the literal `/` must align in `long`.
	return strings.HasSuffix(long, short)
}

// endpointsRelated checks if two normalized endpoints refer to the same
// resource. Handles cases where whitebox uses file paths and blackbox
// uses URL paths. Kept for callers that don't pre-compute segments;
// the correlator hot path uses segmentsRelated directly to avoid
// re-splitting.
func endpointsRelated(a, b string) bool {
	if a == b {
		return true
	}
	return segmentsRelated(pathSegments(a), pathSegments(b))
}

// segmentsRelated is the inner kernel of endpointsRelated: given two
// already-split segment lists, report whether any segment of length >2
// appears in both. Lifted out so the correlator can pre-compute
// segments once per finding (F2 fix in the 2026-05-16 complexity
// audit) instead of re-splitting on every (W, B) comparison.
func segmentsRelated(aSegments, bSegments []string) bool {
	for _, as := range aSegments {
		if len(as) <= 2 {
			continue
		}
		for _, bs := range bSegments {
			if as == bs {
				return true
			}
		}
	}
	return false
}

// pathSegmentNoise is the set of path tokens we filter out during fuzzy
// matching. Hoisted to package level so we don't allocate it on every
// pathSegments() call — the fuzzy-match pass calls pathSegments W·B
// times per scan, and the F2 finding in the time-complexity audit
// (2026-05-16) pinpointed this map as the dominant allocator in
// BenchmarkMemory_Correlate1000.
//
// Add tokens here only if they're (a) genuinely noise (not a vuln
// signal) and (b) common enough that filtering them improves match
// precision. Don't add per-customer tokens — that belongs in
// configuration, not in this package.
var pathSegmentNoise = map[string]bool{
	"api": true, "v1": true, "v2": true, "v3": true,
	"src": true, "py": true, "js": true, "go": true, "ts": true,
	"internal": true, "routes": true, "handlers": true,
	// HTTP methods leak in when an endpoint format like "GET /pet" is
	// normalized; filter them so they don't pollute fuzzy matching.
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true,
}

// pathSegments splits a path into meaningful segments, filtering out
// common noise. See pathSegmentNoise for the filter set and why it's
// at package scope.
func pathSegments(path string) []string {
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\' || r == '.'
	})

	// Pre-size: usually 1-3 segments survive filtering.
	segments := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if !pathSegmentNoise[p] && len(p) > 1 {
			segments = append(segments, p)
		}
	}
	return segments
}

// relatedCategories returns the list of categories that should be considered
// matches for correlation purposes.
func relatedCategories(category string) []string {
	result := []string{category}

	if mapped, ok := categoryMap[category]; ok {
		result = append(result, mapped)
	}

	// Reverse mapping
	for wb, bb := range categoryMap {
		if bb == category {
			result = append(result, wb)
		}
	}

	return result
}

// escalateSeverity bumps severity up by one level.
func escalateSeverity(s models.Severity) models.Severity {
	switch s {
	case models.SeverityInfo:
		return models.SeverityLow
	case models.SeverityLow:
		return models.SeverityMedium
	case models.SeverityMedium:
		return models.SeverityHigh
	case models.SeverityHigh:
		return models.SeverityCritical
	case models.SeverityCritical:
		return models.SeverityCritical // Can't go higher
	default:
		return s
	}
}

// higherSeverity returns whichever severity is more severe.
func higherSeverity(a, b models.Severity) models.Severity {
	if models.SeverityRank(a) >= models.SeverityRank(b) {
		return a
	}
	return b
}

// mergeRefs combines two reference lists, deduplicating.
func mergeRefs(a, b []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, r := range a {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}
	for _, r := range b {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}
	return result
}
