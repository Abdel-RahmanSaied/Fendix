package engine

import (
	"context"
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
func (wp *WorkerPool) Run(ctx context.Context, cfg *models.ScanConfig, endpoints []scanner.Endpoint) []models.Finding {
	jobs := make(chan scanJob, len(endpoints)*len(wp.checks))
	results := make(chan []models.Finding, len(endpoints)*len(wp.checks))

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

				findings := job.check(ctx, cfg, job.endpoint)
				if len(findings) > 0 {
					results <- findings
				}

				if wp.delayMs > 0 {
					time.Sleep(time.Duration(wp.delayMs) * time.Millisecond)
				}
			}
		}(i)
	}

	for _, ep := range endpoints {
		for _, check := range wp.checks {
			jobs <- scanJob{check: check, endpoint: ep}
		}
	}
	close(jobs)

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
