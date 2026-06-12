package reporters

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// SARIF 2.1.0 structures — see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SARIFLog is the top-level SARIF 2.1.0 object.
type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool identity and rules.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule defines a rule (one per unique finding type).
type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription SARIFMessage    `json:"shortDescription"`
	Help             SARIFMessage    `json:"help"`
	HelpURI          string          `json:"helpUri,omitempty"`
	DefaultConfig    SARIFRuleConfig `json:"defaultConfiguration"`
	Properties       SARIFProperties `json:"properties,omitempty"`
}

// SARIFRuleConfig sets the default severity level for a rule.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFMessage holds a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult is a single finding in SARIF format.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	// CodeFlows renders a finding's taint chain as a step-through path
	// (Proven Path v1). GitHub Code Scanning renders these as an
	// expandable source→sink walk in the alert UI — the "screenshot that
	// sells" proof. Empty for findings without a proven chain.
	CodeFlows  []SARIFCodeFlow        `json:"codeFlows,omitempty"`
	Properties *SARIFResultProperties `json:"properties,omitempty"`
}

// SARIFResultProperties carries fendix-specific provenance on a result so
// SARIF consumers (and our own re-ingestion) can see the detection tier and
// route binding that back the Proven Path claim.
type SARIFResultProperties struct {
	SourceTier   string `json:"source_tier,omitempty"`
	Reachable    bool   `json:"reachable,omitempty"`
	RouteMethod  string `json:"route_method,omitempty"`
	RoutePattern string `json:"route_pattern,omitempty"`
	RouteHandler string `json:"route_handler,omitempty"`
}

// SARIFCodeFlow groups one or more threadFlows (SARIF §3.36). A taint chain
// is a single thread of execution, so we emit exactly one threadFlow per
// code flow.
type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

// SARIFThreadFlow is an ordered sequence of locations along one execution
// thread (SARIF §3.37) — here, source → intermediate hops → sink.
type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

// SARIFThreadFlowLocation wraps one location in a threadFlow (SARIF §3.38).
type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
}

// SARIFLocation describes where a finding was detected.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
	// Message labels a location within a threadFlow step (the taint
	// expression at that hop). Omitted for ordinary result locations.
	Message *SARIFMessage `json:"message,omitempty"`
}

// SARIFPhysicalLocation points to a file and line.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies a file by URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion describes a line range in a file.
type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

// SARIFLogicalLocation describes a logical location (endpoint, function).
type SARIFLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFInvocation captures metadata about the scan run.
//
// executionSuccessful is false (F-L13) when any required scanner errored,
// derived from ScanMetadata.ScannerStatus. A false value tells SARIF
// consumers (GitHub Code Scanning, sarif-multitool) that the analysis was
// degraded — results may be incomplete — rather than presenting a partial
// scan as a clean pass. Per-scanner failures are itemised in
// toolExecutionNotifications.
type SARIFInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	CommandLine                string              `json:"commandLine,omitempty"`
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

// SARIFNotification is a tool-execution notification (SARIF §3.58). Used
// to itemise scanner failures behind a false executionSuccessful.
type SARIFNotification struct {
	Level   string       `json:"level,omitempty"`
	Message SARIFMessage `json:"message"`
}

// SARIFProperties holds custom key-value pairs.
type SARIFProperties struct {
	Category   string   `json:"category,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
}

// taintChainToCodeFlow converts a finding's taint chain into a SARIF
// codeFlow with one threadFlow whose locations are the source→sink steps,
// each carrying the expression as its location message. Returns nil for an
// empty chain so the codeFlows field is omitted (omitempty) on findings
// without a proven path.
func taintChainToCodeFlow(chain []models.TaintLink) *SARIFCodeFlow {
	if len(chain) == 0 {
		return nil
	}
	locs := make([]SARIFThreadFlowLocation, 0, len(chain))
	for _, link := range chain {
		loc := SARIFLocation{
			PhysicalLocation: &SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: normalizeArtifactURI(link.File)},
			},
		}
		if link.Line > 0 {
			loc.PhysicalLocation.Region = &SARIFRegion{StartLine: link.Line}
		}
		// The expression text is untrusted source; neutralize control/bidi
		// chars before embedding it as the step message.
		tfl := SARIFThreadFlowLocation{Location: loc}
		tfl.Location.Message = &SARIFMessage{Text: NeutralizeText(link.Expr)}
		locs = append(locs, tfl)
	}
	return &SARIFCodeFlow{ThreadFlows: []SARIFThreadFlow{{Locations: locs}}}
}

// sarifResultProperties stamps fendix provenance (detection tier, reachable
// flag, route binding) into a result's properties. Returns nil when there's
// nothing to record so the field stays omitted.
func sarifResultProperties(f models.Finding) *SARIFResultProperties {
	if f.SourceTier == "" && !f.Reachable && f.Route == nil {
		return nil
	}
	p := &SARIFResultProperties{
		SourceTier: string(f.SourceTier),
		Reachable:  f.Reachable,
	}
	if f.Route != nil {
		p.RouteMethod = f.Route.Method
		p.RoutePattern = f.Route.Pattern
		p.RouteHandler = f.Route.Handler
	}
	return p
}

// ruleKeyFor returns a stable, human-readable rule ID for a finding's
// check type. Two findings with the same (category, title) share a rule ID;
// the per-finding identifier (Finding.ID, e.g. "SEC-042") stays in the
// SARIF result, not on the rule.
//
// Format: "fendix.<category>.<title-slug>" — opaque to consumers but stable
// across runs so that suppression baselines and PR-grouping tools (GitHub
// Code Scanning, sarif-multitool) treat repeat findings as one rule.
func ruleKeyFor(f models.Finding) string {
	// Neutralize first: the category is embedded verbatim in the rule ID
	// (consumers group/suppress by it), so a zero-width or control char
	// must not leak through even though slug() sanitizes the title half.
	cat := strings.ToLower(strings.TrimSpace(NeutralizeText(f.Category)))
	if cat == "" {
		cat = "uncategorized"
	}
	titleSlug := slug(f.Title)
	if titleSlug == "" {
		titleSlug = "unnamed"
	}
	return "fendix." + cat + "." + titleSlug
}

// slug lowercases a string and collapses any run of non-[a-z0-9] characters
// to a single '-'. Used for rule IDs derived from finding titles.
func slug(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := true // suppress leading dash
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := b.String()
	return strings.TrimRight(out, "-")
}

// sarifLevel maps Fendix severity to SARIF level.
func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifHelpURI extracts the first useful reference URL for a rule.
// CWE IDs are mapped to their MITRE page.
func sarifHelpURI(refs []string) string {
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
			return ref
		}
		if strings.HasPrefix(ref, "CWE-") {
			return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(ref, "CWE-") + ".html"
		}
	}
	return ""
}

// uriSchemeRE matches a leading URI scheme ("javascript:", "http://",
// "file:", "data:", …). Per RFC 3986 a scheme is an ASCII letter
// followed by letters/digits/'+'/'-'/'.' and a ':'. We strip it so an
// artifactLocation.uri can never carry an executable or absolute-URL
// scheme into a SARIF viewer.
var uriSchemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)

// normalizeArtifactURI sanitizes a file path destined for a SARIF
// artifactLocation.uri. SARIF consumers (GitHub Code Scanning, IDEs)
// resolve these against the project root, so a value carrying a scheme
// ("javascript:alert(1)"), an absolute path, or ".." traversal can be
// abused. We coerce the value into a safe relative path:
//
//   - control/bidi characters are stripped (NeutralizeText);
//   - any leading URI scheme is removed;
//   - the path is split on '/', and "", ".", and ".." segments are
//     dropped (so "../../etc/passwd" → "etc/passwd" and "/abs" → "abs");
//   - backslashes are treated as separators too (Windows-style paths).
//
// The result is always a relative path with no scheme and no traversal.
func normalizeArtifactURI(uri string) string {
	uri = NeutralizeText(uri)
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	// Drop a leading scheme ("javascript:", "http://", "file:", …).
	uri = uriSchemeRE.ReplaceAllString(uri, "")
	// Normalise Windows separators so traversal segments can't slip
	// through as "..\..".
	uri = strings.ReplaceAll(uri, "\\", "/")

	segs := strings.Split(uri, "/")
	clean := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch seg {
		case "", ".", "..":
			// Drop empty (collapses "//" and leading "/"), current-dir,
			// and parent-dir traversal segments.
			continue
		default:
			clean = append(clean, seg)
		}
	}
	return strings.Join(clean, "/")
}

// neutralizeTags strips control/bidi characters from each reference tag.
// References feed both helpUri (already scheme-filtered) and the SARIF
// rule's properties.tags array; the tags are free text and must not
// carry invisible or reordering characters into a SARIF viewer. Returns
// nil for an empty/nil input so the omitempty JSON tag still drops the
// field.
func neutralizeTags(refs []string) []string {
	if len(refs) == 0 {
		return refs
	}
	out := make([]string, len(refs))
	for i, ref := range refs {
		out[i] = NeutralizeText(ref)
	}
	return out
}

// parseLine extracts file path and line number from a "file:line" string.
func parseLine(line *string) (string, int) {
	if line == nil || *line == "" {
		return "", 0
	}
	parts := strings.Split(*line, ":")
	if len(parts) < 2 {
		return *line, 0
	}
	lineNum := 0
	fmt.Sscanf(parts[len(parts)-1], "%d", &lineNum)
	filePath := strings.Join(parts[:len(parts)-1], ":")
	return filePath, lineNum
}

// RenderSARIF writes a SARIF 2.1.0 report to the writer.
//
// Rules are deduplicated by check identity (category + title) rather than per
// finding (TASK-083). Pre-fix, 160 findings produced 160 unique rule IDs like
// SEC-001..SEC-160; tools that group results by ruleId (GitHub Code Scanning,
// `sarif-multitool merge`) scattered identical issues across many "rules".
// After the fix, "Missing CSP header" reported on 21 endpoints is one rule
// referenced 21 times — which is what SARIF semantics expect.
func RenderSARIF(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	// Build deduplicated rules list keyed by stable check identity.
	ruleMap := make(map[string]int) // stable ruleKey -> index in rules
	var rules []SARIFRule

	for _, f := range findings {
		key := ruleKeyFor(f)
		if _, exists := ruleMap[key]; exists {
			continue
		}
		idx := len(rules)
		ruleMap[key] = idx

		// Strip control/bidi from human-facing rule fields. helpUri is
		// left to sarifHelpURI, which already restricts it to http/https.
		ruleName := NeutralizeText(f.Title)
		rule := SARIFRule{
			ID:               key,
			Name:             ruleName,
			ShortDescription: SARIFMessage{Text: ruleName},
			Help:             SARIFMessage{Text: NeutralizeText(f.Fix)},
			HelpURI:          sarifHelpURI(f.References),
			DefaultConfig:    SARIFRuleConfig{Level: sarifLevel(f.Severity)},
			Properties: SARIFProperties{
				Category:   NeutralizeText(f.Category),
				Tags:       neutralizeTags(f.References),
				Confidence: string(f.Confidence),
			},
		}
		rules = append(rules, rule)
	}

	// Build results — each finding references its check's shared rule, not a per-instance one.
	results := make([]SARIFResult, 0, len(findings))
	for _, f := range findings {
		key := ruleKeyFor(f)
		result := SARIFResult{
			RuleID:    key,
			RuleIndex: ruleMap[key],
			Level:     sarifLevel(f.Severity),
			Message:   SARIFMessage{Text: NeutralizeText(f.Evidence)},
		}

		// Build locations from either line (whitebox) or endpoint(s) (blackbox).
		// Per SARIF spec, multiple locations on a single result mean "this
		// finding applies to all of these places" — exactly the semantics we
		// want for deduplicated findings (TASK-088).
		if f.Line != nil && *f.Line != "" {
			filePath, lineNum := parseLine(f.Line)
			// Coerce the artifact URI into a safe relative path: no
			// scheme (javascript:/http://), no leading slash, no "..".
			loc := SARIFLocation{
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: normalizeArtifactURI(filePath)},
				},
			}
			if lineNum > 0 {
				loc.PhysicalLocation.Region = &SARIFRegion{StartLine: lineNum}
			}
			result.Locations = []SARIFLocation{loc}
		} else {
			// Use AffectedEndpoints when present (deduped finding); otherwise
			// fall back to the singleton Endpoint. Either way produces one
			// SARIFLocation per endpoint with kind=endpoint.
			endpoints := f.AffectedEndpoints
			if len(endpoints) == 0 && f.Endpoint != "" {
				endpoints = []string{f.Endpoint}
			}
			if len(endpoints) > 0 {
				locs := make([]SARIFLocation, 0, len(endpoints))
				for _, ep := range endpoints {
					locs = append(locs, SARIFLocation{
						LogicalLocations: []SARIFLogicalLocation{{
							// Endpoint string is an untrusted logical
							// location name — strip control/bidi chars.
							Name: NeutralizeText(ep),
							Kind: "endpoint",
						}},
					})
				}
				result.Locations = locs
			}
		}

		// Proven Path v1: render the taint chain as a codeFlow so GitHub
		// shows the source→sink step-through, and stamp provenance
		// (source_tier, reachable, route binding) into result properties.
		if cf := taintChainToCodeFlow(f.TaintChain); cf != nil {
			result.CodeFlows = []SARIFCodeFlow{*cf}
		}
		if props := sarifResultProperties(f); props != nil {
			result.Properties = props
		}

		results = append(results, result)
	}

	// F-L13: executionSuccessful is false when any required scanner
	// errored, and each failure becomes a toolExecutionNotification.
	// Derived from ScanMetadata.ScannerStatus — a degraded scan must not
	// present as a clean pass to SARIF consumers.
	invocation := SARIFInvocation{ExecutionSuccessful: true}
	for _, s := range meta.ScannerStatus {
		if s.Failed() {
			invocation.ExecutionSuccessful = false
			msg := s.Name + " scanner failed"
			if s.Detail != "" {
				msg += ": " + s.Detail
			}
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{
				Level:   "error",
				Message: SARIFMessage{Text: msg},
			})
		}
	}

	log := SARIFLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Fendix",
						Version:        meta.Version,
						InformationURI: "https://github.com/Abdel-RahmanSaied/homebrew-fendix",
						Rules:          rules,
					},
				},
				Results:     results,
				Invocations: []SARIFInvocation{invocation},
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(log); err != nil {
		return fmt.Errorf("encoding SARIF report: %w", err)
	}
	return nil
}
