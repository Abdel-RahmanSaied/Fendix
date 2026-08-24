package reporters

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
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
	// v0.24 decision-report fields.
	Status          string `json:"status,omitempty"`
	ConfidenceScore int    `json:"confidence_score,omitempty"`
	ConfidenceBand  string `json:"confidence_band,omitempty"`
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
	if f.SourceTier == "" && !f.Reachable && f.Route == nil && f.Status == "" && f.ConfidenceScore == 0 {
		return nil
	}
	p := &SARIFResultProperties{
		SourceTier:      string(f.SourceTier),
		Reachable:       f.Reachable,
		Status:          f.Status,
		ConfidenceScore: f.ConfidenceScore,
		ConfidenceBand:  f.ConfidenceBand,
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

// sarifLevelForStatus drives the SARIF level (and thus the GitHub annotation
// color) from the v0.24 decision verdict: BLOCK→error, WARN→warning,
// INFO→note. When no decision is stamped (status==""), it falls back to the
// severity-based level so output is byte-identical to pre-v0.24. This is the
// intended v0.24 behavioral change: a HIGH finding BELOW the --fail-on
// threshold is WARN→warning (not error), so annotations reflect "what blocks".
func sarifLevelForStatus(status string, sev models.Severity) string {
	switch status {
	case "BLOCK":
		return "error"
	case "WARN":
		return "warning"
	case "INFO":
		return "note"
	default:
		return sarifLevel(sev)
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

// bareURISchemes are the scheme tokens a URL collapses to once a trailing
// line suffix is stripped off it. `line: "https:8080"` parses as path
// "https" + line 8080 under parseLine's rule (a legal all-digit suffix), and
// reports rendered before FIX-02 may already carry a bare "https" in the
// field. Neither is a file.
var bareURISchemes = map[string]bool{
	"http": true, "https": true, "ftp": true, "ftps": true,
	"file": true, "data": true, "ws": true, "wss": true, "javascript": true,
}

// looksLikeURLPath reports whether a path parsed out of Finding.Line is
// really a URL — or the bare scheme fragment left over from one — in which
// case it must NOT become an artifactLocation.uri.
//
// The predicate is deliberately NARROW, and deliberately not uriSchemeRE
// (which matches any RFC 3986 scheme prefix): uriSchemeRE also matches the
// "C:" of `C:\src\app.go`, so reusing it here would route every Windows
// whitebox finding into the endpoint branch. Only a literal "://" or an
// exact bare-scheme token counts.
func looksLikeURLPath(p string) bool {
	if strings.Contains(p, "://") {
		return true
	}
	return bareURISchemes[strings.ToLower(strings.TrimSpace(p))]
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

// parseLine splits a Finding.Line value into a file path and a line number.
//
// Only a TRAILING ":<digits>" run is a line suffix. Everything else — no
// colon at all, a colon followed by anything non-numeric, a colon at the very
// end — returns the string WHOLE with line 0. That narrow rule is the entire
// fix (FIX-02): the previous implementation split on EVERY ":" and read the
// last segment as the line number, which mangled the URLs that legitimately
// arrive in this field.
//
// They arrive from python/analyzers/spec_parser.py, which stamps
// `"line": self.spec_path` at eight sites (126/194/217/240/274/298/340/380),
// and spec_path may itself be an https:// URL — spec_parser.py:404 fetches a
// spec over https on purpose. Pre-fix:
//
//	"https://api.example.com/openapi.json"
//	  → Split → ["https", "//api.example.com/openapi.json"]
//	  → Sscanf fails → filePath "https", line 0
//
//	"https://host:8080/api/x"
//	  → Split → ["https", "//host", "8080/api/x"]
//	  → Sscanf reads 8080 → filePath "https://host", line 8080
//
// The second is the worse of the two: normalizeArtifactURI then strips the
// scheme, so the emitter published artifactLocation.uri "host" carrying a
// FABRICATED startLine 8080 — a plausible-looking line in a file that does
// not exist. Both now come back whole with line 0, and RenderSARIF routes
// them to a logical location instead (see looksLikeURLPath).
//
// Parity anchor: this is precisely what the Python side already asserts about
// the same field. python/tests/test_ast_analyzer.py::TestFindingStructure::
// test_line_field_format does `f["line"].rsplit(":", 1)` and requires
// `parts[1].isdigit()`. Do not diverge from it.
//
// NOT fixed here, deliberately: "file:line:col" ("src/app.py:42:10") still
// yields path "src/app.py:42" + line 10, exactly as the old splitter did. No
// producer in the tree emits that shape, so reproducing the behaviour is
// cheaper than guessing at a new one.
func parseLine(line *string) (string, int) {
	if line == nil || *line == "" {
		return "", 0
	}
	s := *line
	i := strings.LastIndexByte(s, ':')
	if i < 0 || i == len(s)-1 {
		// No colon, or a trailing colon with nothing behind it. An empty
		// suffix is not a digit run — `"".isdigit()` is False on the Python
		// side too, so the colon stays part of the path.
		return s, 0
	}
	suffix := s[i+1:]
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return s, 0
		}
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		// All digits, but too many of them to fit an int. A whole path is a
		// better answer than a silently truncated line number.
		return s, 0
	}
	return s[:i], n
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
			// v0.24: per-result level follows the decision verdict (BLOCK→error,
			// WARN→warning, INFO→note); falls back to severity when unstamped.
			Level:   sarifLevelForStatus(f.Status, f.Severity),
			Message: SARIFMessage{Text: NeutralizeText(f.Evidence)},
		}

		// Build locations from either line (whitebox) or endpoint(s) (blackbox).
		// Per SARIF spec, multiple locations on a single result mean "this
		// finding applies to all of these places" — exactly the semantics we
		// want for deduplicated findings (TASK-088).
		//
		// FIX-02: the branch is chosen on the PARSED path, not merely on
		// `f.Line` being non-empty. A `line` that is really a URL names no
		// artifact, so it belongs with the endpoints — and the logicalLocation
		// branch below already renders that correctly, which is why the fix is
		// to stop feeding it a bogus physicalLocation rather than to rewrite
		// it. The URL test has to run BEFORE normalizeArtifactURI, because
		// normalizeArtifactURI is what deletes the scheme and hides the
		// URL-ness.
		filePath, lineNum := parseLine(f.Line) // handles nil / "" itself
		artifactURI := ""
		if filePath != "" && !looksLikeURLPath(filePath) {
			// Coerce the artifact URI into a safe relative path: no
			// scheme (javascript:/http://), no leading slash, no "..".
			artifactURI = normalizeArtifactURI(filePath)
		}
		if artifactURI != "" {
			loc := SARIFLocation{
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: artifactURI},
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
			// A URL-shaped `line` on a finding with no endpoint at all is
			// still a location. De-escalate it to a logical one rather than
			// dropping it — working rule 3: evidence is de-escalated, never
			// deleted.
			if len(endpoints) == 0 && filePath != "" && looksLikeURLPath(filePath) {
				endpoints = []string{filePath}
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
