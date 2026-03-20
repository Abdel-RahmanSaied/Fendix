package engine

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// ApplyBaselineDiff filters out findings that were already present in a previous scan.
// It compares by title+endpoint+category (not ID, since IDs are reassigned each run).
// Returns only new findings not present in the baseline.
func ApplyBaselineDiff(current []models.Finding, baselinePath string) []models.Finding {
	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		slog.Error("failed to load baseline", "path", baselinePath, "error", err)
		return current
	}

	baselineKeys := make(map[string]bool)
	for _, f := range baseline {
		baselineKeys[findingKey(f)] = true
	}

	var newFindings []models.Finding
	for _, f := range current {
		if !baselineKeys[findingKey(f)] {
			newFindings = append(newFindings, f)
		}
	}

	suppressed := len(current) - len(newFindings)
	if suppressed > 0 {
		slog.Info("baseline diff applied",
			"baseline_count", len(baseline),
			"current_count", len(current),
			"new_findings", len(newFindings),
			"suppressed", suppressed,
		)
	}

	return newFindings
}

// SaveBaseline writes the current findings to a JSON file for use as a future baseline.
func SaveBaseline(findings []models.Finding, path string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing baseline to %s: %w", path, err)
	}

	slog.Info("baseline saved", "path", path, "findings", len(findings))
	return nil
}

// loadBaseline reads a baseline file. Supports both:
// - Raw Finding array: [{"id":...}, ...]
// - JSONReport format: {"findings": [{"id":...}, ...]}
func loadBaseline(path string) ([]models.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	// Try JSONReport format first
	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err == nil && report.Findings != nil {
		return report.Findings, nil
	}

	// Try raw Finding array
	var findings []models.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON: %w", err)
	}

	return findings, nil
}

// findingKey produces a stable key for deduplication.
// Uses title+endpoint+category since IDs change between runs.
func findingKey(f models.Finding) string {
	return f.Title + "|" + f.Endpoint + "|" + f.Category
}
