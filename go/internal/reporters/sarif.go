package reporters

import (
	"encoding/json"
	"fmt"
	"io"
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
	Tool        SARIFTool        `json:"tool"`
	Results     []SARIFResult    `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool identity and rules.
type SARIFDriver struct {
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	InformationURI string          `json:"informationUri"`
	Rules          []SARIFRule     `json:"rules"`
}

// SARIFRule defines a rule (one per unique finding type).
type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SARIFMessage     `json:"shortDescription"`
	Help             SARIFMessage     `json:"help"`
	HelpURI          string           `json:"helpUri,omitempty"`
	DefaultConfig    SARIFRuleConfig  `json:"defaultConfiguration"`
	Properties       SARIFProperties  `json:"properties,omitempty"`
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
	RuleID    string            `json:"ruleId"`
	RuleIndex int               `json:"ruleIndex"`
	Level     string            `json:"level"`
	Message   SARIFMessage      `json:"message"`
	Locations []SARIFLocation   `json:"locations,omitempty"`
}

// SARIFLocation describes where a finding was detected.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
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
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	CommandLine         string `json:"commandLine,omitempty"`
}

// SARIFProperties holds custom key-value pairs.
type SARIFProperties struct {
	Category   string   `json:"category,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
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
	cat := strings.ToLower(strings.TrimSpace(f.Category))
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

		rule := SARIFRule{
			ID:               key,
			Name:             f.Title,
			ShortDescription: SARIFMessage{Text: f.Title},
			Help:             SARIFMessage{Text: f.Fix},
			HelpURI:          sarifHelpURI(f.References),
			DefaultConfig:    SARIFRuleConfig{Level: sarifLevel(f.Severity)},
			Properties: SARIFProperties{
				Category:   f.Category,
				Tags:       f.References,
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
			Message:   SARIFMessage{Text: f.Evidence},
		}

		// Build locations from either line (whitebox) or endpoint(s) (blackbox).
		// Per SARIF spec, multiple locations on a single result mean "this
		// finding applies to all of these places" — exactly the semantics we
		// want for deduplicated findings (TASK-088).
		if f.Line != nil && *f.Line != "" {
			filePath, lineNum := parseLine(f.Line)
			loc := SARIFLocation{
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: filePath},
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
							Name: ep,
							Kind: "endpoint",
						}},
					})
				}
				result.Locations = locs
			}
		}

		results = append(results, result)
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
						InformationURI: "https://github.com/fendix/fendix",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{ExecutionSuccessful: true},
				},
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
