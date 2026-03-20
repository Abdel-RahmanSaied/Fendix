package engine

import (
	"log/slog"
	"net/url"
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

// Correlate cross-references blackbox and whitebox findings.
//
// Rules:
//   - If both engines agree on a vulnerability (same normalized endpoint + related category):
//     merge into a single correlated finding with source=correlated, confidence=HIGH,
//     and severity escalated by one level.
//   - If whitebox finds an issue but blackbox does NOT confirm:
//     keep whitebox finding, confidence=MEDIUM, add "Unconfirmed by live scan" note.
//   - If blackbox finds an issue but no whitebox counterpart:
//     keep as-is.
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

	if len(whitebox) == 0 || len(blackbox) == 0 {
		// Nothing to correlate — return all findings as-is
		// But still downgrade unconfirmed whitebox findings if no blackbox data
		if len(blackbox) == 0 && len(whitebox) > 0 {
			for i := range whitebox {
				whitebox[i].Confidence = models.ConfidenceMedium
				whitebox[i].Evidence += " [Unconfirmed by live scan]"
			}
		}
		result := make([]models.Finding, 0, len(blackbox)+len(whitebox))
		result = append(result, blackbox...)
		result = append(result, whitebox...)
		return result
	}

	// Build index of blackbox findings by normalized endpoint+category
	bbIndex := make(map[correlationKey][]int)
	for i, f := range blackbox {
		key := correlationKey{
			endpoint: normalizeEndpoint(f.Endpoint),
			category: f.Category,
		}
		bbIndex[key] = append(bbIndex[key], i)
	}

	// Track which blackbox findings were correlated
	bbCorrelated := make(map[int]bool)

	var result []models.Finding

	for _, wf := range whitebox {
		matched := false

		// Try to find a matching blackbox finding
		wbNorm := normalizeEndpoint(wf.Endpoint)

		// Check direct category match
		for _, bbCat := range relatedCategories(wf.Category) {
			key := correlationKey{endpoint: wbNorm, category: bbCat}
			if indices, ok := bbIndex[key]; ok {
				// Found a correlation — merge
				bbIdx := indices[0]
				bf := blackbox[bbIdx]
				bbCorrelated[bbIdx] = true

				merged := mergeFindings(bf, wf)
				result = append(result, merged)
				matched = true

				slog.Info("correlated finding",
					"endpoint", wbNorm,
					"category", wf.Category,
					"bb_title", bf.Title,
					"wb_title", wf.Title,
				)
				break
			}
		}

		// Also try endpoint-agnostic category match (e.g. whitebox "auth" on route
		// matches blackbox "auth_bypass" on same route with different normalization)
		if !matched {
			for _, bbCat := range relatedCategories(wf.Category) {
				for i, bf := range blackbox {
					if bf.Category == bbCat && endpointsRelated(wbNorm, normalizeEndpoint(bf.Endpoint)) {
						bbCorrelated[i] = true
						merged := mergeFindings(bf, wf)
						result = append(result, merged)
						matched = true

						slog.Info("correlated finding (fuzzy match)",
							"wb_endpoint", wf.Endpoint,
							"bb_endpoint", bf.Endpoint,
							"category", wf.Category,
						)
						break
					}
				}
				if matched {
					break
				}
			}
		}

		if !matched {
			// Unconfirmed whitebox finding
			wf.Confidence = models.ConfidenceMedium
			wf.Evidence += " [Unconfirmed by live scan]"
			result = append(result, wf)
		}
	}

	// Add uncorrelated blackbox findings as-is
	for i, bf := range blackbox {
		if !bbCorrelated[i] {
			result = append(result, bf)
		}
	}

	return result
}

// mergeFindings creates a correlated finding from matching blackbox and whitebox findings.
// Severity is escalated by one level, confidence is HIGH, source is correlated.
func mergeFindings(bb, wb models.Finding) models.Finding {
	merged := models.Finding{
		Title:      bb.Title,
		Severity:   escalateSeverity(higherSeverity(bb.Severity, wb.Severity)),
		Source:     models.SourceCorrelated,
		Category:   bb.Category,
		Endpoint:   bb.Endpoint,
		Evidence:   bb.Evidence + " | Code: " + wb.Evidence,
		Fix:        bb.Fix,
		References: mergeRefs(bb.References, wb.References),
		Confidence: models.ConfidenceHigh,
		Line:       wb.Line,
	}
	return merged
}

// normalizeEndpoint extracts just the path from an endpoint string,
// stripping scheme, host, port, and query parameters.
func normalizeEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}

	// Handle file:line format (whitebox findings like "src/config.py:14")
	if !strings.Contains(endpoint, "://") && !strings.HasPrefix(endpoint, "/") {
		// Looks like a file path — extract the filename without line number
		parts := strings.SplitN(endpoint, ":", 2)
		return strings.ToLower(parts[0])
	}

	// Handle URL format (blackbox findings)
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

// endpointsRelated checks if two normalized endpoints refer to the same resource.
// This handles cases where whitebox uses file paths and blackbox uses URL paths.
func endpointsRelated(a, b string) bool {
	if a == b {
		return true
	}

	// Check if one endpoint's path is contained in the other
	// e.g., "/api/v1/users" and "routes/users.py" share "users"
	aSegments := pathSegments(a)
	bSegments := pathSegments(b)

	for _, as := range aSegments {
		for _, bs := range bSegments {
			if as == bs && len(as) > 2 {
				return true
			}
		}
	}

	return false
}

// pathSegments splits a path into meaningful segments, filtering out common noise.
func pathSegments(path string) []string {
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\' || r == '.'
	})

	var segments []string
	noise := map[string]bool{
		"api": true, "v1": true, "v2": true, "v3": true,
		"src": true, "py": true, "js": true, "go": true, "ts": true,
		"internal": true, "routes": true, "handlers": true,
	}

	for _, p := range parts {
		p = strings.ToLower(p)
		if !noise[p] && len(p) > 1 {
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
