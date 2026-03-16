package reporters

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/fendix/fendix/internal/models"
)

// ScanMetadata contains metadata about the scan run for report output.
type ScanMetadata struct {
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`
	Version   string    `json:"version"`
}

// SeverityCounts holds the count of findings per severity level.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// JSONReport is the top-level structure for JSON report output.
type JSONReport struct {
	Metadata ScanMetadata     `json:"metadata"`
	Summary  SeverityCounts   `json:"summary"`
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

// RenderJSON writes a full JSON report to the writer.
func RenderJSON(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	report := JSONReport{
		Metadata: meta,
		Summary:  CountSeverities(findings),
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
