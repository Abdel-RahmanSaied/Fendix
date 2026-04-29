package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
)

// Orchestrator coordinates the full scan lifecycle:
// crawl endpoints → run checks → spawn Python → correlate → assign IDs → render report.
type Orchestrator struct {
	cfg     *models.ScanConfig
	spawner *PythonSpawner
}

// NewOrchestrator creates an orchestrator from scan config.
// It resolves the Python engine directory using EnsureEngine:
// embedded extraction → local fallback → error.
func NewOrchestrator(cfg *models.ScanConfig, version string) *Orchestrator {
	engineDir, err := EnsureEngine("", version)
	if err != nil {
		slog.Warn("python engine not available — whitebox scanning disabled", "error", err)
		engineDir = "" // spawner will fail gracefully if whitebox is requested
	}

	return &Orchestrator{
		cfg:     cfg,
		spawner: NewPythonSpawner("", engineDir),
	}
}

// NewOrchestratorWithSpawner creates an orchestrator with a custom Python spawner.
func NewOrchestratorWithSpawner(cfg *models.ScanConfig, spawner *PythonSpawner) *Orchestrator {
	return &Orchestrator{
		cfg:     cfg,
		spawner: spawner,
	}
}

// Run executes the full scan pipeline and returns an exit code.
// 0 = no findings above threshold, 1 = findings found, 2 = error.
func (o *Orchestrator) Run(ctx context.Context) int {
	startTime := time.Now()

	// 1. Discover endpoints
	crawler := scanner.NewCrawler(o.cfg)
	endpoints, err := crawler.CrawlEndpoints(ctx)
	if err != nil {
		slog.Error("endpoint discovery failed — check --url is reachable and --spec is valid YAML/JSON", "error", err)
		return 2
	}

	// Only fail when there's nothing to scan in EITHER engine. Code-only scans
	// (--code without --url/--spec) legitimately have zero endpoints and should
	// still run the white-box analyzer (TASK-080). Black-box checks below
	// receive an empty endpoint list and return zero findings, which is fine.
	if len(endpoints) == 0 && o.cfg.CodePath == "" {
		slog.Warn("no endpoints discovered — nothing to scan")
		fmt.Fprintln(os.Stderr, "fendix: no endpoints discovered. Provide --url, --spec, or --code.")
		return 2
	}

	if len(endpoints) > 0 {
		slog.Info("scanning endpoints", "count", len(endpoints))
	}

	// 2. Build check list
	checks := []scanner.CheckFn{
		scanner.CheckHeaders,
		scanner.CheckCORS,
		scanner.CheckExposure,
		scanner.CheckRateLimit,
	}

	if o.cfg.Auth != nil {
		checks = append(checks, scanner.CheckAuth)
	}

	if o.cfg.Auth != nil && o.cfg.AuthUser2 != nil {
		checks = append(checks, scanner.CheckIDOR)
	}

	if o.cfg.EnableActive {
		scanner.PrintDisclaimer()
		checks = append(checks, scanner.CheckInjection)
	}

	// 3. Run checks via worker pool
	pool := NewWorkerPool(o.cfg.Workers, o.cfg.DelayMs, checks)
	findings := pool.Run(ctx, o.cfg, endpoints)

	// 4. Spawn Python engine for white-box analysis (if code path or spec provided)
	if o.cfg.CodePath != "" || o.cfg.SpecPath != "" {
		pyStatus := CheckPython(o.spawner.pythonBin)
		if !pyStatus.Available {
			slog.Warn("python not available — skipping whitebox analysis")
			fmt.Fprintln(os.Stderr, "fendix: "+PythonRequiredMessage())
		} else {
			slog.Info("python available", "version", pyStatus.Version, "binary", pyStatus.Binary)
			wbFindings := o.runWhiteboxScan(ctx)
			findings = append(findings, wbFindings...)
		}
	}

	// 5. Correlate black-box and white-box findings
	if hasWhitebox(findings) && hasBlackbox(findings) {
		findings = Correlate(findings)
	}

	// 5.5. Deduplicate identical findings across endpoints (TASK-088).
	// Runs after correlation so correlated findings are grouped too.
	// "Missing CSP × 21 endpoints" → 1 finding with AffectedEndpoints[21].
	findings = Deduplicate(findings)

	// 5.6. Enforce severity↔confidence consistency (TASK-092). LOW confidence
	// caps severity at MEDIUM; MEDIUM confidence caps at HIGH. Mismatched
	// findings get their severity downgraded so the public JSON schema's
	// consistency rule holds for every emitted report.
	findings = enforceConsistency(findings)

	// 6. Sort findings deterministically by endpoint+category for stable ID assignment
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Endpoint != findings[j].Endpoint {
			return findings[i].Endpoint < findings[j].Endpoint
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Title < findings[j].Title
	})

	// 7. Assign sequential IDs
	for i := range findings {
		findings[i].ID = fmt.Sprintf("SEC-%03d", i+1)
	}

	// 8. Apply ignore rules from .fendix-ignore
	if o.cfg.IgnorePath != "" {
		ignoreFile, err := ParseIgnoreFile(o.cfg.IgnorePath)
		if err != nil {
			slog.Error("failed to parse ignore file — check YAML syntax and file path", "path", o.cfg.IgnorePath, "error", err)
		} else {
			findings = ApplyIgnoreRules(findings, ignoreFile.Ignore)
		}
	}

	// 9. Apply baseline diff if --baseline provided
	if o.cfg.BaselinePath != "" {
		findings = ApplyBaselineDiff(findings, o.cfg.BaselinePath)
	}

	duration := time.Since(startTime)

	// Determine scan mode for metadata
	scanMode := "blackbox"
	if (o.cfg.CodePath != "" || o.cfg.SpecPath != "") && o.cfg.URL != "" {
		scanMode = "hybrid"
	} else if o.cfg.CodePath != "" || o.cfg.SpecPath != "" {
		scanMode = "whitebox"
	}

	// Build list of check names that were run
	checksRun := []string{"headers", "cors", "exposure", "ratelimit"}
	if o.cfg.Auth != nil {
		checksRun = append(checksRun, "auth")
	}
	if o.cfg.Auth != nil && o.cfg.AuthUser2 != nil {
		checksRun = append(checksRun, "idor")
	}
	if o.cfg.EnableActive {
		checksRun = append(checksRun, "injection")
	}
	if o.cfg.CodePath != "" || o.cfg.SpecPath != "" {
		checksRun = append(checksRun, "secrets", "semgrep", "deps")
	}

	meta := reporters.ScanMetadata{
		Target:         o.cfg.URL,
		StartedAt:      startTime,
		Duration:       duration.Round(time.Millisecond).String(),
		Version:        "dev",
		Mode:           scanMode,
		EndpointsCount: len(endpoints),
		ActiveProbes:   o.cfg.EnableActive,
		ChecksRun:      checksRun,
	}

	// 10. Save baseline if requested (before sanitization, so credentials are available for future diff)
	if o.cfg.SaveBaselinePath != "" {
		if err := SaveBaseline(findings, o.cfg.SaveBaselinePath); err != nil {
			slog.Error("failed to save baseline — check that the directory exists and is writable", "error", err)
		}
	}

	// 11. Sanitize credentials from findings before rendering
	findings = reporters.SanitizeFindings(findings, o.cfg.Auth, o.cfg.AuthUser2)

	// 12. Render report
	if err := o.renderReport(findings, meta); err != nil {
		slog.Error("report rendering failed — check --output path is writable and --format is json/html/sarif", "error", err)
		return 2
	}

	counts := reporters.CountSeverities(findings)
	slog.Info("scan complete",
		"duration", duration.Round(time.Millisecond),
		"total", len(findings),
		"critical", counts.Critical,
		"high", counts.High,
		"medium", counts.Medium,
		"low", counts.Low,
		"info", counts.Info,
	)

	// 8. Check fail-on threshold
	return o.checkFailOn(findings)
}

// renderReport writes the scan report to the configured output.
func (o *Orchestrator) renderReport(findings []models.Finding, meta reporters.ScanMetadata) error {
	var w io.Writer = os.Stdout
	if o.cfg.OutputPath != "" {
		f, err := os.Create(o.cfg.OutputPath)
		if err != nil {
			return fmt.Errorf("creating output file %s: %w", o.cfg.OutputPath, err)
		}
		defer f.Close()
		w = f
	}

	switch o.cfg.Format {
	case "html":
		return reporters.RenderHTML(w, findings, meta)
	case "sarif":
		return reporters.RenderSARIF(w, findings, meta)
	case "json", "":
		return reporters.RenderJSON(w, findings, meta)
	default:
		return fmt.Errorf("unsupported format %q — use json, html, or sarif", o.cfg.Format)
	}
}

// checkFailOn returns exit code 1 if findings exist at or above the --fail-on severity.
func (o *Orchestrator) checkFailOn(findings []models.Finding) int {
	if o.cfg.FailOn == "" {
		return 0
	}

	threshold := models.SeverityRank(models.Severity(o.cfg.FailOn))
	if threshold == 0 {
		slog.Warn("invalid --fail-on value — use CRITICAL, HIGH, or MEDIUM", "value", o.cfg.FailOn)
		return 0
	}

	for _, f := range findings {
		if models.SeverityRank(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}

// runWhiteboxScan spawns the Python engine and collects whitebox findings.
func (o *Orchestrator) runWhiteboxScan(ctx context.Context) []models.Finding {
	checks := []string{"secrets", "auth", "semgrep", "injection", "deps"}
	if len(o.cfg.Checks) > 0 {
		checks = o.cfg.Checks
	}

	req := ScanRequest{
		Mode:     "whitebox",
		Spec:     o.cfg.SpecPath,
		CodePath: o.cfg.CodePath,
		Checks:   checks,
		Verbose:  o.cfg.Verbose,
	}

	result := o.spawner.Run(ctx, req)
	if result.Err != nil {
		slog.Error("python engine failed — ensure Python 3 is installed and python/requirements.txt dependencies are available", "error", result.Err)
		// Return whatever findings we collected before the error
		return result.Findings
	}

	slog.Info("whitebox scan complete", "findings", len(result.Findings))
	return result.Findings
}

// enforceConsistency walks every finding through models.EnforceSeverityConsistency
// and logs a single aggregated WARN summarising any downgrades. Cap rules are
// owned by the models package; the orchestrator only orchestrates.
func enforceConsistency(findings []models.Finding) []models.Finding {
	if len(findings) == 0 {
		return findings
	}
	downgraded := 0
	for i, f := range findings {
		out, changed := models.EnforceSeverityConsistency(f)
		if changed {
			downgraded++
			slog.Debug("severity downgraded for confidence consistency",
				"id", f.ID,
				"title", f.Title,
				"confidence", f.Confidence,
				"original_severity", f.Severity,
				"new_severity", out.Severity,
			)
		}
		findings[i] = out
	}
	if downgraded > 0 {
		slog.Warn("severity↔confidence consistency: downgraded findings", "count", downgraded)
	}
	return findings
}

// hasWhitebox returns true if any finding has source=whitebox.
func hasWhitebox(findings []models.Finding) bool {
	for _, f := range findings {
		if f.Source == models.SourceWhitebox {
			return true
		}
	}
	return false
}

// hasBlackbox returns true if any finding has source=blackbox.
func hasBlackbox(findings []models.Finding) bool {
	for _, f := range findings {
		if f.Source == models.SourceBlackbox {
			return true
		}
	}
	return false
}
