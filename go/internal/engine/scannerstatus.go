package engine

import (
	"errors"
	"log/slog"
	"path/filepath"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/npm"
)

// scannerStatusList accumulates the per-scanner outcome for the dep-CVE,
// secrets, semgrep, and textscan passes (F-L7/F-L13/F-L14). It replaces
// the old fail-open behaviour where a scanner crash was logged at WARN
// and silently dropped: every failure is now recorded, surfaced in a
// scan-end summary, exposed in ScanMetadata, and (with
// --fail-on-scanner-error) able to force a non-zero exit.
type scannerStatusList []reporters.ScannerStatus

// ok records a clean run.
func (l *scannerStatusList) ok(name string) {
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerOK})
}

// skip records a scanner that did not run because its precondition was
// absent or it cannot run in the current mode. A skip is not a failure.
func (l *scannerStatusList) skip(name, detail string) {
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerSkipped, Detail: detail})
}

// fail records a scanner that ran but errored. The error message is
// truncated to keep the metadata payload bounded.
func (l *scannerStatusList) fail(name string, err error) {
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerFailed, Detail: truncateErr(err)})
}

// hasFailure reports whether any recorded scanner ran and errored.
// Skipped scanners do not count.
func (l scannerStatusList) hasFailure() bool {
	for _, s := range l {
		if s.Failed() {
			return true
		}
	}
	return false
}

// failedNames returns the names of every scanner that errored, for the
// scan-end summary line.
func (l scannerStatusList) failedNames() []string {
	var out []string
	for _, s := range l {
		if s.Failed() {
			out = append(out, s.Name)
		}
	}
	return out
}

// truncateErr renders an error to a bounded single-line detail string.
func truncateErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	const max = 240
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// recordDepScanResult records the outcome of a pip-style dep scan (one
// that returns an empty slice rather than a sentinel when no manifest is
// found) and appends any findings. Used by both the online and offline
// pip paths so they record status identically.
func (o *Orchestrator) recordDepScanResult(status *scannerStatusList, name, label string, findings *[]evidence.Evidence, scanFindings []evidence.Evidence, err error) {
	switch {
	case err == nil:
		if len(scanFindings) > 0 {
			slog.Info(label+" complete", "findings", len(scanFindings))
			*findings = append(*findings, scanFindings...)
		} else {
			slog.Debug(label + " found no manifests under code path")
		}
		status.ok(name)
	default:
		slog.Warn(label+" failed", "error", err)
		status.fail(name, err)
	}
}

// recordNpmScanResult records the npm dep-scan outcome, preserving the
// existing sentinel handling (lockfile-missing advisory finding,
// no-lockfile silent skip). Shared by the online and offline npm paths.
// Returns the updated findings slice.
func (o *Orchestrator) recordNpmScanResult(status *scannerStatusList, findings *[]evidence.Evidence, npmFindings []evidence.Evidence, err error) []evidence.Evidence {
	switch {
	case err == nil:
		slog.Info("native npm deps scan complete", "findings", len(npmFindings))
		*findings = append(*findings, npmFindings...)
		status.ok("npm")
	case errors.Is(err, npm.ErrLockfileMissingButPackageJsonPresent):
		// Single INFO finding — flag the gap without producing noise.
		// Surfaced by the Track 4 heavy-eval on Juice Shop / dvna / etc.
		slog.Info("npm deps scan: package.json present but lock file missing — emitting advisory finding")
		*findings = append(*findings, evidence.Evidence{
			ID:         "SEC-NPM_LOCKFILE_MISSING",
			Title:      "npm dep-CVE scan skipped — package-lock.json missing",
			Severity:   models.SeverityInfo,
			Source:     models.SourceWhitebox,
			Category:   "config",
			Endpoint:   filepath.Join(o.cfg.CodePath, "package.json"),
			Evidence:   "package.json was found at the scan root but no package-lock.json. Without the lock file, fendix's npm-audit scanner can't resolve transitive versions and skips the dep-CVE pass.",
			Fix:        "Run `npm install` (or `npm ci`) to materialise package-lock.json, then re-scan. For yarn or pnpm projects this scanner is currently silent; that gap is tracked separately. CWE-1395.",
			References: []string{"https://cwe.mitre.org/data/definitions/1395.html"},
			Confidence: models.ConfidenceHigh,
		})
		status.skip("npm", "package-lock.json missing")
	case errors.Is(err, npm.ErrNoLockfile):
		slog.Debug("no package-lock.json at code path, skipping native npm deps scan")
		status.skip("npm", "no package-lock.json at code path")
	default:
		slog.Warn("native npm deps scan failed", "error", err)
		status.fail("npm", err)
	}
	return *findings
}
