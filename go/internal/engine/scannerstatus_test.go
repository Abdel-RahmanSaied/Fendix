package engine

import (
	"errors"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/npm"
)

func TestScannerStatusList_OkSkipFail(t *testing.T) {
	var l scannerStatusList
	l.ok("secrets")
	l.skip("govulncheck", "offline mode")
	l.fail("pip", errors.New("osv.dev returned 503"))

	if len(l) != 3 {
		t.Fatalf("got %d statuses; want 3", len(l))
	}
	if l[0].State != reporters.ScannerOK || l[1].State != reporters.ScannerSkipped || l[2].State != reporters.ScannerFailed {
		t.Errorf("unexpected states: %+v", l)
	}
	if l[2].Detail != "osv.dev returned 503" {
		t.Errorf("fail detail = %q", l[2].Detail)
	}
}

func TestScannerStatusList_HasFailure(t *testing.T) {
	var clean scannerStatusList
	clean.ok("secrets")
	clean.skip("govulncheck", "offline")
	if clean.hasFailure() {
		t.Error("hasFailure should be false when only ok/skip recorded")
	}

	var dirty scannerStatusList
	dirty.ok("secrets")
	dirty.fail("pip", errors.New("boom"))
	dirty.fail("npm", errors.New("kaboom"))
	if !dirty.hasFailure() {
		t.Error("hasFailure should be true when a scanner failed")
	}
	names := dirty.failedNames()
	if len(names) != 2 || names[0] != "pip" || names[1] != "npm" {
		t.Errorf("failedNames = %v; want [pip npm]", names)
	}
}

func TestTruncateErr_Bounded(t *testing.T) {
	if got := truncateErr(nil); got != "" {
		t.Errorf("truncateErr(nil) = %q; want empty", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	got := truncateErr(errors.New(string(long)))
	if len([]rune(got)) > 241 { // 240 chars + ellipsis rune
		t.Errorf("truncateErr did not bound length: %d", len([]rune(got)))
	}
}

// TestRecordDepScanResult_RecordsOkAndFail covers the shared pip-style
// recorder: success appends findings + records ok; error records fail.
func TestRecordDepScanResult_RecordsOkAndFail(t *testing.T) {
	o := &Orchestrator{cfg: &models.ScanConfig{}}

	var status scannerStatusList
	var findings []models.Finding
	scanFindings := []models.Finding{{ID: "X", Category: "deps"}}
	o.recordDepScanResult(&status, "pip", "native pypi deps scan", &findings, scanFindings, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding appended, got %d", len(findings))
	}
	if len(status) != 1 || status[0].State != reporters.ScannerOK || status[0].Name != "pip" {
		t.Errorf("expected pip ok status, got %+v", status)
	}

	var status2 scannerStatusList
	var findings2 []models.Finding
	o.recordDepScanResult(&status2, "pip", "native pypi deps scan", &findings2, nil, errors.New("network down"))
	if len(status2) != 1 || status2[0].State != reporters.ScannerFailed {
		t.Errorf("expected pip failed status, got %+v", status2)
	}
}

// TestRecordNpmScanResult_LockfileMissingIsSkip verifies the npm
// lockfile-missing sentinel records a SKIP (plus the advisory finding),
// not a failure.
func TestRecordNpmScanResult_LockfileMissingIsSkip(t *testing.T) {
	o := &Orchestrator{cfg: &models.ScanConfig{CodePath: "/tmp/x"}}
	var status scannerStatusList
	var findings []models.Finding
	findings = o.recordNpmScanResult(&status, &findings, nil, npm.ErrLockfileMissingButPackageJsonPresent)
	if len(status) != 1 || status[0].State != reporters.ScannerSkipped {
		t.Errorf("expected npm skipped, got %+v", status)
	}
	if len(findings) != 1 || findings[0].ID != "SEC-NPM_LOCKFILE_MISSING" {
		t.Errorf("expected advisory finding, got %+v", findings)
	}
	if status.hasFailure() {
		t.Error("lockfile-missing must not count as a failure")
	}
}
