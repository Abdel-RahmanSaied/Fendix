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
// crawl endpoints → run checks → assign IDs → render report.
type Orchestrator struct {
	cfg *models.ScanConfig
}

// NewOrchestrator creates an orchestrator from scan config.
func NewOrchestrator(cfg *models.ScanConfig) *Orchestrator {
	return &Orchestrator{cfg: cfg}
}

// Run executes the full scan pipeline and returns an exit code.
// 0 = no findings above threshold, 1 = findings found, 2 = error.
func (o *Orchestrator) Run(ctx context.Context) int {
	startTime := time.Now()

	// 1. Discover endpoints
	crawler := scanner.NewCrawler(o.cfg)
	endpoints, err := crawler.CrawlEndpoints(ctx)
	if err != nil {
		slog.Error("endpoint discovery failed", "error", err)
		return 2
	}

	if len(endpoints) == 0 {
		slog.Warn("no endpoints discovered — nothing to scan")
		fmt.Fprintln(os.Stderr, "fendix: no endpoints discovered. Provide --url, --spec, or both.")
		return 2
	}

	slog.Info("scanning endpoints", "count", len(endpoints))

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

	// 3. Run checks via worker pool
	pool := NewWorkerPool(o.cfg.Workers, o.cfg.DelayMs, checks)
	findings := pool.Run(ctx, o.cfg, endpoints)

	// 4. Sort findings deterministically by endpoint+category for stable ID assignment
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Endpoint != findings[j].Endpoint {
			return findings[i].Endpoint < findings[j].Endpoint
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Title < findings[j].Title
	})

	// 5. Assign sequential IDs
	for i := range findings {
		findings[i].ID = fmt.Sprintf("SEC-%03d", i+1)
	}

	duration := time.Since(startTime)
	meta := reporters.ScanMetadata{
		Target:    o.cfg.URL,
		StartedAt: startTime,
		Duration:  duration.Round(time.Millisecond).String(),
		Version:   "dev",
	}

	// 6. Sanitize credentials from findings before rendering
	findings = reporters.SanitizeFindings(findings, o.cfg.Auth, o.cfg.AuthUser2)

	// 7. Render report
	if err := o.renderReport(findings, meta); err != nil {
		slog.Error("report rendering failed", "error", err)
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
	case "json", "":
		return reporters.RenderJSON(w, findings, meta)
	default:
		return fmt.Errorf("unsupported format: %s", o.cfg.Format)
	}
}

// checkFailOn returns exit code 1 if findings exist at or above the --fail-on severity.
func (o *Orchestrator) checkFailOn(findings []models.Finding) int {
	if o.cfg.FailOn == "" {
		return 0
	}

	threshold := models.SeverityRank(models.Severity(o.cfg.FailOn))
	if threshold == 0 {
		slog.Warn("invalid --fail-on value, ignoring", "value", o.cfg.FailOn)
		return 0
	}

	for _, f := range findings {
		if models.SeverityRank(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}
