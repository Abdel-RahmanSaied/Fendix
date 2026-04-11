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
func RenderSARIF(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	// Build deduplicated rules list and map findings to rule indices
	ruleMap := make(map[string]int) // ruleID -> index
	var rules []SARIFRule

	for _, f := range findings {
		if _, exists := ruleMap[f.ID]; exists {
			continue
		}
		idx := len(rules)
		ruleMap[f.ID] = idx

		rule := SARIFRule{
			ID:               f.ID,
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

	// Build results
	results := make([]SARIFResult, 0, len(findings))
	for _, f := range findings {
		result := SARIFResult{
			RuleID:    f.ID,
			RuleIndex: ruleMap[f.ID],
			Level:     sarifLevel(f.Severity),
			Message:   SARIFMessage{Text: f.Evidence},
		}

		// Build location from either line (whitebox) or endpoint (blackbox)
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
		} else if f.Endpoint != "" {
			result.Locations = []SARIFLocation{
				{
					LogicalLocations: []SARIFLogicalLocation{
						{
							Name: f.Endpoint,
							Kind: "endpoint",
						},
					},
				},
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
