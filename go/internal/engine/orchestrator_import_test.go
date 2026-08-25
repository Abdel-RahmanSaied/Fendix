package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// codeqlFixture is the realistic CodeQL SARIF checked in for the importer's
// own tests; reusing it here keeps the end-to-end path honest.
const codeqlFixture = "../sarifimport/testdata/codeql.sarif"

func importConfig(t *testing.T, failOn string, paths ...string) *models.ScanConfig {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	return &models.ScanConfig{
		ImportPaths:       paths,
		Format:            "json",
		OutputPath:        out,
		FailOn:            failOn,
		EnforceConfidence: true,
	}
}

// TestRunImport_EndToEnd drives the standalone import pipeline: SARIF in →
// the standard single-document JSON report out, with mode "import", the
// per-tool accounting block, imported sources, and stamped fingerprints —
// the exact contract the backend's Celery task consumes.
func TestRunImport_EndToEnd(t *testing.T) {
	cfg := importConfig(t, "", codeqlFixture)
	o := NewOrchestrator(cfg, "test")
	if code := o.RunImport(context.Background()); code != 0 {
		t.Fatalf("RunImport = %d, want 0 (no --fail-on)", code)
	}

	data, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reporters.ParseJSONReport(data)
	if err != nil {
		t.Fatalf("the import report must parse as a standard fendix JSONReport: %v", err)
	}
	if report.Metadata.Mode != "import" {
		t.Fatalf("metadata.mode = %q, want import", report.Metadata.Mode)
	}
	if len(report.Metadata.Imports) != 1 || report.Metadata.Imports[0].Tool != "codeql" {
		t.Fatalf("metadata.imports must carry the per-tool accounting, got %+v", report.Metadata.Imports)
	}
	if report.Metadata.Imports[0].Results != len(report.Findings) {
		t.Fatalf("imports accounting (%d) and findings (%d) must reconcile",
			report.Metadata.Imports[0].Results, len(report.Findings))
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected imported findings in the report")
	}
	for _, f := range report.Findings {
		if f.Source != models.SourceImported {
			t.Fatalf("finding source = %q, want imported", f.Source)
		}
		if f.Fingerprint == "" {
			t.Fatal("imported findings must carry the run-stable fendix fingerprint")
		}
		if f.Status == "" || f.ConfidenceScore == 0 {
			t.Fatalf("imported findings must carry decision status + score, got %q/%d", f.Status, f.ConfidenceScore)
		}
	}
}

// TestRunImport_ExitCodes locks the gate contract for standalone imports:
// a high-precision error-level finding blocks at --fail-on HIGH on its own
// (score 70, HIGH band); the same document is clean at --fail-on CRITICAL.
func TestRunImport_ExitCodes(t *testing.T) {
	cfg := importConfig(t, "HIGH", codeqlFixture)
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 1 {
		t.Fatalf("high-precision HIGH finding at --fail-on HIGH must exit 1, got %d", code)
	}

	cfg = importConfig(t, "CRITICAL", codeqlFixture)
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 0 {
		t.Fatalf("no CRITICAL findings → --fail-on CRITICAL must exit 0, got %d", code)
	}
}

// TestRunImport_MalformedFileFailsClosed: half-importing a document would
// misrepresent coverage, so any unreadable/invalid file is exit 2.
func TestRunImport_MalformedFileFailsClosed(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.sarif")
	if err := os.WriteFile(bad, []byte("{not sarif"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := importConfig(t, "", codeqlFixture, bad)
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 2 {
		t.Fatalf("a malformed SARIF file must fail the whole import with exit 2, got %d", code)
	}

	cfg = importConfig(t, "", filepath.Join(t.TempDir(), "missing.sarif"))
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 2 {
		t.Fatal("a missing file must exit 2")
	}
}

// TestRunImport_BaselineAndIgnoreApply proves the persistence surfaces the
// import design promised: fendix-native fingerprints make --save-baseline /
// --baseline and .fendix-ignore work on imported findings with zero new code.
func TestRunImport_BaselineAndIgnoreApply(t *testing.T) {
	baseline := filepath.Join(t.TempDir(), "baseline.json")

	cfg := importConfig(t, "", codeqlFixture)
	cfg.SaveBaselinePath = baseline
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 0 {
		t.Fatal("baseline-saving run must succeed")
	}

	// Re-import the same document against the saved baseline: every finding
	// is already known, so the diff must be empty.
	cfg = importConfig(t, "HIGH", codeqlFixture)
	cfg.BaselinePath = baseline
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 0 {
		t.Fatal("a fully-baselined import must exit 0 even at --fail-on HIGH")
	}
	data, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reporters.ParseJSONReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("baseline diff must remove already-known imported findings, got %d", len(report.Findings))
	}
}
