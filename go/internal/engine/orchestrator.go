package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/diagnostic"
	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/plugin"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/govulncheck"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/npm"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/pip"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/secrets"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/semgrep"
)

// Orchestrator coordinates the full scan lifecycle:
// crawl endpoints → run checks → spawn Python → correlate → assign IDs → render report.
type Orchestrator struct {
	cfg     *models.ScanConfig
	spawner *PythonSpawner
	version string
}

// NewOrchestrator creates an orchestrator from scan config.
//
// The Python engine directory is resolved lazily: only when --python-engine
// is set do we call EnsureEngine. Pre-TASK-118 we resolved eagerly and
// logged a WARN if no engine was found, but with the embedded distribution
// dropped that WARN now fires on every scan for the default path — exactly
// the "Python interpreter not required" promise broken at the log level.
// Skip the resolution entirely when the flag is off; runWhiteboxScan never
// gets called in that case so the spawner's empty engineDir is harmless.
func NewOrchestrator(cfg *models.ScanConfig, version string) *Orchestrator {
	engineDir := ""
	if cfg.PythonEngine {
		dir, err := EnsureEngine("", version)
		if err != nil {
			slog.Warn("python engine not available — whitebox scanning disabled", "error", err)
		} else {
			engineDir = dir
		}
	}

	return &Orchestrator{
		cfg:     cfg,
		spawner: NewPythonSpawner("", engineDir),
		version: version,
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

	// Reset per-check WARN aggregator. Real-world scans against unreliable
	// hosts can emit thousands of "request failed" lines without this — one
	// per endpoint per check. logagg caps the WARN volume per check and
	// surfaces the suppressed count via a single Info line at scan end.
	logagg.Reset()

	// Reset the scan-wide active-probe audit log so this run's records
	// don't include leftovers from a previous run in the same process
	// (long-running tests, future server mode).
	scanner.ResetGlobalAuditLog()

	// --debug-bundle wiring (TASK-102). Setup is a no-op when disabled.
	// When enabled, install a slog tee that captures DEBUG-and-above
	// records into the bundle's buffer alongside a fresh stderr text
	// handler. We restore the previous default before the function
	// returns so subsequent code outside Run sees the original handler.
	//
	// We deliberately install a fresh stderr handler instead of wrapping
	// slog.Default().Handler(). main() installs a concrete TextHandler at
	// process startup, but tests and embedders may construct an
	// Orchestrator directly without that prelude — in which case the
	// stdlib's uninstalled default (*slog.defaultHandler) bridges through
	// log.Default() back to slog.Default(), so wrapping it builds an
	// infinite loop on every log call and deadlocks the log mutex.
	// A fresh text handler is unconditionally safe.
	bundle := diagnostic.New(o.cfg.DebugBundlePath, o.cfg)
	if bundle.Enabled() {
		prevDefault := slog.Default()
		stderrLevel := slog.LevelInfo
		if o.cfg.Verbose {
			stderrLevel = slog.LevelDebug
		}
		stderrHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: stderrLevel})
		slog.SetDefault(slog.New(bundle.LogHandler(stderrHandler)))
		defer slog.SetDefault(prevDefault)
	}

	// Apply scan budget controls (TASK-095). MaxDuration wraps the parent
	// context with a deadline immediately so discovery is also bounded by
	// it; MaxRequests is enforced by the budget package's RoundTripper +
	// one-shot ctx cancel and is intentionally armed AFTER discovery so
	// the cap reflects scan-phase requests only (otherwise a small cap
	// like --max-requests 20 would be exhausted by brute-force discovery
	// before any check ran). Both controls implement "soft-stop"
	// semantics: in-flight requests finish, no new ones start.
	budget.Reset()
	if o.cfg.MaxDuration > 0 {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithTimeout(ctx, o.cfg.MaxDuration)
		defer cancelDeadline()
	}
	ctx, cancelBudget := context.WithCancel(ctx)
	defer cancelBudget()
	defer budget.SetCancelFunc(nil) // unregister on Run return

	// 1. Discover endpoints
	crawler := scanner.NewCrawler(o.cfg)
	endpoints, err := crawler.CrawlEndpoints(ctx)
	if err != nil {
		slog.Error("endpoint discovery failed — check --url is reachable and --spec is valid YAML/JSON", "error", err)
		return 2
	}

	// Arm the request cap now that discovery is complete. Reset() the
	// counters so the budget summary at scan end reflects scan-phase
	// requests only — clearer semantics for the user, and independent of
	// however many requests discovery happened to make.
	budget.Reset()
	budget.SetMaxRequests(o.cfg.MaxRequests)
	budget.SetCancelFunc(cancelBudget)

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

	// 2. Build check list. configleak runs first so its CRITICAL
	// "exposed config file" finding lands before the noisier
	// per-endpoint checks (headers / cors / ratelimit) fire on the
	// same path — TASK-133 / Phase 17d corpus signal D2.
	checks := []scanner.CheckFn{
		scanner.CheckConfigLeak,
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

	// 3.5. Native dep-CVE scanners (TASK-119). Run in-process before
	// the Python whitebox engine spawns, so the Python deps.py path
	// can be retired in Phase 17b (TASK-118) without losing coverage.
	// Findings flow through the same dedup pipeline so the Python
	// output collapses with native output during the transition window.
	//
	// Go:   golang.org/x/vuln gives call-graph reachability.
	// PyPI: OSV.dev /v1/query per pinned (==) dep, cached 24h.
	// npm:  OSV.dev /v1/query per resolved version in package-lock.json
	//       v2/v3 (full transitive tree), cached 24h.
	//
	// Each ecosystem has an ErrNo... sentinel for silent-skip; other
	// errors slog.Warn and continue so a network blip doesn't stop a
	// scan from reporting other findings.
	if o.cfg.CodePath != "" && !o.cfg.NoNativeDeps {
		nativeFindings, err := govulncheck.Scan(ctx, o.cfg.CodePath)
		switch {
		case err == nil:
			slog.Info("native go deps scan complete", "findings", len(nativeFindings))
			findings = append(findings, nativeFindings...)
		case errors.Is(err, govulncheck.ErrNoGoMod):
			slog.Debug("no go.mod at code path, skipping native go deps scan")
		default:
			slog.Warn("native go deps scan failed", "error", err)
		}

		// pip-audit walks the scan root recursively up to
		// pip.DefaultRecurseDepth levels to catch multi-service repos
		// where requirements.txt lives in a subdir. Track 4 heavy-eval
		// surfaced this on TwiScope-backend: 8 dep-CVEs were invisible
		// to a root-only scan because requirements.txt was at
		// Twiscope_Main_App/, not the repo root. Vendored / cache dirs
		// (.venv, node_modules, .git, etc.) are skipped regardless of
		// depth — see recurseSkipDirs in the pip package.
		pipMode := "OSV.dev"
		if o.cfg.UsePipAudit {
			pipMode = "pip-audit subprocess"
		}
		slog.Debug("native pypi dep-CVE scan starting", "mode", pipMode)
		pipFindings, err := pip.ScanRecursiveWithOptions(
			ctx, o.cfg.CodePath, pip.DefaultRecurseDepth,
			pip.Options{UsePipAudit: o.cfg.UsePipAudit},
		)
		switch {
		case err == nil:
			if len(pipFindings) > 0 {
				slog.Info("native pypi deps scan complete", "findings", len(pipFindings))
				findings = append(findings, pipFindings...)
			} else {
				slog.Debug("native pypi deps scan found no manifests under code path")
			}
		default:
			slog.Warn("native pypi deps scan failed", "error", err)
		}

		npmFindings, err := npm.Scan(ctx, o.cfg.CodePath)
		switch {
		case err == nil:
			slog.Info("native npm deps scan complete", "findings", len(npmFindings))
			findings = append(findings, npmFindings...)
		case errors.Is(err, npm.ErrLockfileMissingButPackageJsonPresent):
			// Single INFO finding — flag the gap without producing noise.
			// Surfaced by the Track 4 heavy-eval on Juice Shop / dvna / etc.
			slog.Info("npm deps scan: package.json present but lock file missing — emitting advisory finding")
			findings = append(findings, models.Finding{
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
		case errors.Is(err, npm.ErrNoLockfile):
			slog.Debug("no package-lock.json at code path, skipping native npm deps scan")
		default:
			slog.Warn("native npm deps scan failed", "error", err)
		}
	}

	// 3.6. Native secrets scan (TASK-115). Ported in-process from
	// python/analyzers/secrets.py; runs unconditionally when CodePath
	// is set, regardless of Python availability. Same SEC-* IDs as the
	// Python implementation so any overlap (e.g. user explicitly passes
	// --checks secrets) dedupes cleanly.
	if o.cfg.CodePath != "" {
		secretFindings, err := secrets.Scan(ctx, o.cfg.CodePath)
		switch {
		case err == nil:
			slog.Info("native secrets scan complete", "findings", len(secretFindings))
			findings = append(findings, secretFindings...)
		case errors.Is(err, secrets.ErrCodePathMissing):
			slog.Debug("code path missing — skipping native secrets scan")
		default:
			slog.Warn("native secrets scan failed", "error", err)
		}
	}

	// 3.7. Native semgrep scan (TASK-116). Shells out to the host's
	// installed `semgrep` binary with the bundled rule pack; if
	// semgrep isn't on $PATH, we log an install hint and continue —
	// graceful absence matches the existing posture for missing
	// Python. Same SEC-* IDs as the Python wrapper so dedup absorbs
	// any overlap when a user opts the Python path back in.
	if o.cfg.CodePath != "" {
		semgrepFindings, err := semgrep.Scan(ctx, o.cfg.CodePath)
		switch {
		case err == nil:
			slog.Info("native semgrep scan complete", "findings", len(semgrepFindings))
			findings = append(findings, semgrepFindings...)
		case errors.Is(err, semgrep.ErrSemgrepUnavailable):
			slog.Info("semgrep not installed — skipping (install with: pip install semgrep)")
		case errors.Is(err, semgrep.ErrCodePathMissing):
			slog.Debug("code path missing — skipping native semgrep scan")
		default:
			slog.Warn("native semgrep scan failed", "error", err)
		}
	}

	// 4. Spawn Python engine for white-box analysis. Default off as of
	// TASK-118 — secrets (TASK-115) + semgrep (TASK-116) now run in
	// native Go and the embedded Python distribution is no longer
	// bundled. Set --python-engine to re-enable the Python auth /
	// injection / deps checks; requires a usable Python source tree
	// resolvable via EnsureEngine (local python/ or explicit FENDIX_ENGINE).
	if o.cfg.PythonEngine && (o.cfg.CodePath != "" || o.cfg.SpecPath != "") {
		pyStatus := CheckPython(o.spawner.pythonBin)
		if !pyStatus.Available {
			slog.Warn("python not available — skipping whitebox analysis")
			fmt.Fprintln(os.Stderr, "fendix: "+PythonRequiredMessage())
		} else {
			slog.Info("python available", "version", pyStatus.Version, "binary", pyStatus.Binary)
			bundle.SetPythonVersion(pyStatus.Version)
			wbFindings := o.runWhiteboxScan(ctx)
			findings = append(findings, wbFindings...)
		}
	}

	// 4.5. Run out-of-tree plugins (TASK-113). Plugin findings flow
	// through the same correlation/dedup/sort/ID pipeline as embedded
	// engine findings, so a custom-secret-pattern plugin can correlate
	// against a blackbox auth check exactly like the built-in secrets
	// analyzer does.
	if !o.cfg.NoPlugins {
		findings = append(findings, o.runPlugins(ctx)...)
	}

	// 5. Correlate black-box and white-box findings
	if hasWhitebox(findings) && hasBlackbox(findings) {
		findings = Correlate(findings)
	}

	// 5.4. Escalate non-correlated reachable findings (TASK-125).
	// The correlator already bumps correlated-reachable findings via
	// mergeFindings's second escalateSeverity call. This step catches
	// the pure-whitebox case: an AST-proven taint chain on a finding
	// that didn't correlate to a blackbox match. Per docs/example_plan.md
	// §3.5 the multiplier is 1.5x; on the discrete severity scale that's
	// ~one level up. Saturates at CRITICAL.
	findings = escalateNonCorrelatedReachable(findings)

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

	// Surface aggregated WARN suppression counts so operators can tell at a
	// glance how many transient errors were silenced (vs. the visible cap
	// emissions). One Info line per scan; empty when no events occurred.
	if attrs := logagg.Summary(); len(attrs) > 0 {
		slog.Info("warning summary", attrs...)
	}

	// Surface scan-budget telemetry whenever a cap was set, regardless of
	// whether it fired. This makes "did we run out of budget?" trivially
	// auditable in CI and gives operators a feedback loop for tuning
	// --max-requests / --max-duration to their target scan size.
	if o.cfg.MaxRequests > 0 || o.cfg.MaxDuration > 0 {
		sent, rejected := budget.Stats()
		slog.Info("budget summary",
			"requests_sent", sent,
			"requests_rejected", rejected,
			"max_requests", o.cfg.MaxRequests,
			"max_duration", o.cfg.MaxDuration,
		)
	}

	// Write the diagnostic tarball before the fail-on check so that even a
	// non-zero exit produces the bundle (a CI failure is exactly when an
	// operator wants to attach a bug-report bundle).
	if bundle.Enabled() {
		bundle.SetFindings(findings)
		bundle.SetMetadata(meta)
		bundle.SetProbes(scanner.GlobalAuditRecords())
		if err := bundle.Write(o.version); err != nil {
			slog.Error("failed to write debug bundle — check that the path is writable",
				"path", o.cfg.DebugBundlePath,
				"error", err,
			)
		} else {
			slog.Info("debug bundle written", "path", o.cfg.DebugBundlePath)
		}
	}

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
		return reporters.RenderHTMLOpts(w, findings, meta, reporters.HTMLOptions{Lang: o.cfg.Lang})
	case "sarif":
		return reporters.RenderSARIF(w, findings, meta)
	case "pdf":
		return reporters.RenderPDF(w, findings, meta, reporters.PDFOptions{})
	case "json", "":
		return reporters.RenderJSON(w, findings, meta)
	default:
		return fmt.Errorf("unsupported format %q — use json, html, sarif, or pdf", o.cfg.Format)
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

// runPlugins discovers plugins under the configured roots and runs
// every plugin whose Mode is compatible with the current scan
// (blackbox plugins only run when a target URL is set; whitebox
// plugins only run when --code or --spec is set; hybrid plugins
// run whenever either condition holds). Plugin failures are logged
// at WARN and the scan continues — a broken plugin must not
// interrupt the embedded engines.
func (o *Orchestrator) runPlugins(ctx context.Context) []models.Finding {
	cwd, _ := os.Getwd()
	roots := plugin.DefaultRoots(cwd)
	plugins, err := plugin.Discover(roots)
	if err != nil {
		slog.Warn("plugin discovery failed", "error", err)
		return nil
	}
	if len(plugins) == 0 {
		return nil
	}

	hasBlackboxTarget := o.cfg.URL != ""
	hasWhiteboxTarget := o.cfg.CodePath != "" || o.cfg.SpecPath != ""

	var out []models.Finding
	for _, p := range plugins {
		switch p.Mode {
		case plugin.ModeBlackbox:
			if !hasBlackboxTarget {
				slog.Debug("plugin skipped (no blackbox target)", "plugin", p.Name)
				continue
			}
		case plugin.ModeWhitebox:
			if !hasWhiteboxTarget {
				slog.Debug("plugin skipped (no whitebox target)", "plugin", p.Name)
				continue
			}
		case plugin.ModeHybrid:
			if !hasBlackboxTarget && !hasWhiteboxTarget {
				slog.Debug("plugin skipped (no target)", "plugin", p.Name)
				continue
			}
		}

		// Resolve filesystem paths to absolutes before sending to the
		// plugin. The plugin runs with cwd=plugin-dir, so a relative
		// "./repo" from the scan caller's cwd would resolve under
		// the plugin directory and find nothing.
		req := plugin.ScanRequest{
			Mode:       p.Mode,
			URL:        o.cfg.URL,
			Spec:       absPathOrEmpty(o.cfg.SpecPath),
			CodePath:   absPathOrEmpty(o.cfg.CodePath),
			Categories: p.Categories,
			Verbose:    o.cfg.Verbose,
		}
		if o.cfg.Auth != nil {
			req.Auth = o.cfg.Auth.Value
			req.AuthType = string(o.cfg.Auth.Type)
		}

		slog.Info("running plugin", "plugin", p.Name, "version", p.Version, "mode", p.Mode)
		findings, err := p.Run(ctx, req)
		if err != nil {
			slog.Warn("plugin failed (continuing)", "plugin", p.Name, "error", err)
			// A plugin that exited non-zero may still have emitted findings
			// before the failure; preserve them.
		}
		slog.Info("plugin complete", "plugin", p.Name, "findings", len(findings))
		out = append(out, findings...)
	}
	return out
}

// absPathOrEmpty resolves p to an absolute path. Returns "" for an
// empty input (so unset flags don't become spurious paths). Failures
// fall back to the original value rather than dropping the field —
// the plugin can still run, even if relative-path resolution is
// imperfect.
func absPathOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	// URLs must not be passed through filepath.Abs — it collapses the
	// double-slash in "https://" to a single slash and prepends cwd.
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// runWhiteboxScan spawns the Python engine and collects whitebox findings.
//
// "secrets" and "semgrep" are no longer in the default check set as of
// TASK-115 / TASK-116 — the native Go scanners at internal/scanner/secrets/
// and internal/scanner/semgrep/ run in-process before this call. Users can
// still pass --checks secrets,semgrep to opt the Python paths back in
// (matching SEC-* IDs mean dedup collapses any overlap), but they aren't
// on by default. The Python files stay in-tree for one release window in
// case of rollback; TASK-118 deletes them.
func (o *Orchestrator) runWhiteboxScan(ctx context.Context) []models.Finding {
	checks := []string{"auth", "injection", "deps"}
	if len(o.cfg.Checks) > 0 {
		checks = o.cfg.Checks
	}

	// Resolve code_path + spec to absolute paths before handing to the
	// Python subprocess. The spawner sets cmd.Dir = engineDir (the
	// python/ tree), so a relative path from the caller's cwd would
	// resolve under engineDir instead — the same family of bug as
	// the spawner's enginePath fix (TASK-134). Surfaces as the
	// Python engine reporting 0 findings on a real codebase because
	// it never finds the source files.
	req := ScanRequest{
		Mode:     "whitebox",
		Spec:     absPathOrEmpty(o.cfg.SpecPath),
		CodePath: absPathOrEmpty(o.cfg.CodePath),
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

// escalateNonCorrelatedReachable bumps severity by one level on findings
// where the engine proved a reachable taint chain (Finding.Reachable=true)
// but no blackbox match was correlated. The correlator already bumps the
// correlated-reachable case in mergeFindings; this catches the pure-
// whitebox slice that misses correlation (no live HTTP target, or no
// matching blackbox endpoint).
//
// TASK-125 / docs/example_plan.md §3.5: reachable adds a 1.5× multiplier
// which on the discrete severity scale lands as ~one level up. Saturates
// at CRITICAL. Findings with Reachable=false are unchanged.
//
// Confidence cap (enforceConsistency, step 5.6) runs after this, so a
// MEDIUM-confidence finding escalated to CRITICAL gets capped back to
// HIGH — the reachable bump amplifies what the confidence allows; it
// can't override the cap.
func escalateNonCorrelatedReachable(findings []models.Finding) []models.Finding {
	if len(findings) == 0 {
		return findings
	}
	escalated := 0
	for i, f := range findings {
		if !f.Reachable {
			continue
		}
		if f.Source == models.SourceCorrelated {
			// Correlator already applied this bump in mergeFindings.
			// Re-applying here would double-bump and exceed the cap.
			continue
		}
		bumped := escalateSeverity(f.Severity)
		if bumped != f.Severity {
			slog.Debug("reachable severity escalation (non-correlated)",
				"id", f.ID, "title", f.Title,
				"original_severity", f.Severity, "new_severity", bumped)
			findings[i].Severity = bumped
			escalated++
		}
	}
	if escalated > 0 {
		slog.Info("reachable findings escalated", "count", escalated)
	}
	return findings
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
