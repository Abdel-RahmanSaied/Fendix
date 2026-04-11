package reporters

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ScanMetadata contains metadata about the scan run for report output.
type ScanMetadata struct {
	Target         string    `json:"target"`
	StartedAt      time.Time `json:"started_at"`
	Duration       string    `json:"duration"`
	Version        string    `json:"version"`
	Mode           string    `json:"mode"`
	EndpointsCount int       `json:"endpoints_scanned"`
	ActiveProbes   bool      `json:"active_probes"`
	ChecksRun      []string  `json:"checks_run,omitempty"`
}

// SeverityCounts holds the count of findings per severity level.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// SourceCounts holds the count of findings per source type.
type SourceCounts struct {
	Blackbox   int `json:"blackbox"`
	Whitebox   int `json:"whitebox"`
	Correlated int `json:"correlated"`
}

// JSONReport is the top-level structure for JSON report output.
type JSONReport struct {
	Metadata ScanMetadata     `json:"metadata"`
	Summary  SeverityCounts   `json:"summary"`
	Sources  SourceCounts     `json:"sources"`
	Total    int              `json:"total"`
	Findings []models.Finding `json:"findings"`
}

// CountSeverities tallies findings by severity level.
func CountSeverities(findings []models.Finding) SeverityCounts {
	var counts SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			counts.Critical++
		case models.SeverityHigh:
			counts.High++
		case models.SeverityMedium:
			counts.Medium++
		case models.SeverityLow:
			counts.Low++
		case models.SeverityInfo:
			counts.Info++
		}
	}
	return counts
}

// CountSources tallies findings by source type.
func CountSources(findings []models.Finding) SourceCounts {
	var counts SourceCounts
	for _, f := range findings {
		switch f.Source {
		case models.SourceBlackbox:
			counts.Blackbox++
		case models.SourceWhitebox:
			counts.Whitebox++
		case models.SourceCorrelated:
			counts.Correlated++
		}
	}
	return counts
}

// RenderJSON writes a full JSON report to the writer.
func RenderJSON(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	report := JSONReport{
		Metadata: meta,
		Summary:  CountSeverities(findings),
		Sources:  CountSources(findings),
		Total:    len(findings),
		Findings: findings,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}
