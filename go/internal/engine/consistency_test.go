package engine

import (
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// TASK-092: orchestrator step 5.6 must downgrade severity for findings whose
// confidence is below their severity rank (per scoring formula's implicit cap).
func TestEnforceConsistency_DowngradesLowConfidenceHighSeverity(t *testing.T) {
	in := []models.Finding{
		{ID: "SEC-001", Title: "A", Severity: models.SeverityCritical, Confidence: models.ConfidenceLow},
		{ID: "SEC-002", Title: "B", Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium},
		{ID: "SEC-003", Title: "C", Severity: models.SeverityCritical, Confidence: models.ConfidenceMedium},
		{ID: "SEC-004", Title: "D", Severity: models.SeverityCritical, Confidence: models.ConfidenceHigh},
	}

	out := enforceConsistency(in)

	if got := out[0].Severity; got != models.SeverityMedium {
		t.Errorf("LOW conf + CRITICAL sev: want MEDIUM, got %s", got)
	}
	if got := out[1].Severity; got != models.SeverityHigh {
		t.Errorf("MEDIUM conf + HIGH sev: want HIGH unchanged, got %s", got)
	}
	if got := out[2].Severity; got != models.SeverityHigh {
		t.Errorf("MEDIUM conf + CRITICAL sev: want HIGH downgrade, got %s", got)
	}
	if got := out[3].Severity; got != models.SeverityCritical {
		t.Errorf("HIGH conf + CRITICAL sev: want CRITICAL unchanged, got %s", got)
	}
}

func TestEnforceConsistency_EmptyInput(t *testing.T) {
	out := enforceConsistency(nil)
	if len(out) != 0 {
		t.Errorf("expected 0 findings, got %d", len(out))
	}
	out = enforceConsistency([]models.Finding{})
	if len(out) != 0 {
		t.Errorf("expected 0 findings, got %d", len(out))
	}
}
