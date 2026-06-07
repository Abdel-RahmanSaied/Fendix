package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
)

// WorkerPool runs scanner checks concurrently across endpoints using a bounded goroutine pool.
type WorkerPool struct {
	workers int
	delayMs int
	checks  []scanner.CheckFn
}

// NewWorkerPool creates a pool with the given concurrency limit, inter-request delay, and checks to run.
func NewWorkerPool(workers int, delayMs int, checks []scanner.CheckFn) *WorkerPool {
	if workers < 1 {
		workers = 1
	}
	return &WorkerPool{
		workers: workers,
		delayMs: delayMs,
		checks:  checks,
	}
}

// scanJob represents a single endpoint+check combination to execute.
type scanJob struct {
	check    scanner.CheckFn
	endpoint scanner.Endpoint
}

// Run executes all checks against all endpoints using the worker pool.
// Returns all collected findings.
//
// Channel sizing: a bounded buffer keeps memory linear in pool size,
// not in the N×M job matrix. Before: `make(chan ..., len(endpoints)*len(wp.checks))`
// — on a 10k-endpoint × 8-check scan that's 80k slots queued ahead of
// any worker draining. After: `wp.workers*4` is enough to keep all
// workers fed during a tail-end drain without amplifying memory under
// `--max-endpoints 0`.
//
// Context cancellation: the producer also selects on ctx.Done() so a
// long-running scan can be cancelled mid-flight; previously the
// producer relied on the over-sized buffer never blocking, masking
// the lack of a cancel path. Workers continue to honour ctx on each
// loop iteration.
func (wp *WorkerPool) Run(ctx context.Context, cfg *models.ScanConfig, endpoints []scanner.Endpoint) []models.Finding {
	bufSize := wp.workers * 4
	if bufSize < 1 {
		bufSize = 1
	}
	jobs := make(chan scanJob, bufSize)
	results := make(chan []models.Finding, bufSize)

	var wg sync.WaitGroup
	for i := 0; i < wp.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				findings := runCheck(ctx, cfg, job, workerID)
				if len(findings) > 0 {
					select {
					case results <- findings:
					case <-ctx.Done():
						return
					}
				}

				if wp.delayMs > 0 {
					select {
					case <-time.After(time.Duration(wp.delayMs) * time.Millisecond):
					case <-ctx.Done():
						return
					}
				}
			}
		}(i)
	}

	go func() {
		defer close(jobs)
		for _, ep := range endpoints {
			for _, check := range wp.checks {
				select {
				case jobs <- scanJob{check: check, endpoint: ep}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []models.Finding
	for batch := range results {
		allFindings = append(allFindings, batch...)
	}

	slog.Info("worker pool complete", "endpoints", len(endpoints), "checks", len(wp.checks), "findings", len(allFindings))
	return allFindings
}

// runCheck invokes a single check with a per-job recover() so a panic in
// one check is contained to that job: it's logged, recorded as a synthetic
// INFO finding, and the worker moves on to the next job instead of letting
// the panic unwind the worker goroutine and abort the whole scan.
//
// Returning the panic as a finding (rather than swallowing it) keeps the
// failure visible in the report — operators see *which* check died on
// *which* endpoint, which is the support signal a silent skip would lose.
func runCheck(ctx context.Context, cfg *models.ScanConfig, job scanJob, workerID int) (findings []models.Finding) {
	defer func() {
		if r := recover(); r != nil {
			epLabel := fmt.Sprintf("%s %s", job.endpoint.Method, job.endpoint.Path)
			slog.Error("scanner check panicked — job contained, scan continues",
				"worker", workerID, "endpoint", epLabel, "panic", r)
			findings = []models.Finding{{
				Title:      "Scanner check panicked",
				Severity:   models.SeverityInfo,
				Source:     models.SourceBlackbox,
				Category:   "engine",
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("A scanner check panicked while scanning %s and was skipped: %v", epLabel, r),
				Confidence: models.ConfidenceLow,
			}}
		}
	}()
	return job.check(ctx, cfg, job.endpoint)
}
