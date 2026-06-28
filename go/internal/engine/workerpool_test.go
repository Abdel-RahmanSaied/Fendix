package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
)

func TestWorkerPool_RunsAllChecks(t *testing.T) {
	var callCount atomic.Int32
	check1 := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		callCount.Add(1)
		return []evidence.Evidence{{Title: "check1", Severity: models.SeverityLow, Source: models.SourceBlackbox}}
	}
	check2 := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		callCount.Add(1)
		return []evidence.Evidence{{Title: "check2", Severity: models.SeverityMedium, Source: models.SourceBlackbox}}
	}

	pool := NewWorkerPool(2, 0, []scanner.CheckFn{check1, check2})
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: "http://localhost/a"},
		{Method: "GET", Path: "/b", FullURL: "http://localhost/b"},
		{Method: "GET", Path: "/c", FullURL: "http://localhost/c"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	if int(callCount.Load()) != 6 {
		t.Errorf("expected 6 check calls (3 endpoints × 2 checks), got %d", callCount.Load())
	}
	if len(findings) != 6 {
		t.Errorf("expected 6 findings, got %d", len(findings))
	}
}

func TestWorkerPool_RespectsContext(t *testing.T) {
	var callCount atomic.Int32
	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		callCount.Add(1)
		return nil
	}

	pool := NewWorkerPool(1, 0, []scanner.CheckFn{check})
	endpoints := make([]scanner.Endpoint, 100)
	for i := range endpoints {
		endpoints[i] = scanner.Endpoint{Method: "GET", Path: "/test", FullURL: "http://localhost/test"}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &models.ScanConfig{Timeout: 10}
	pool.Run(ctx, cfg, endpoints)

	if int(callCount.Load()) >= 100 {
		t.Errorf("expected fewer than 100 calls with cancelled context, got %d", callCount.Load())
	}
}

func TestWorkerPool_CollectsFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		return []evidence.Evidence{
			{Title: "finding for " + ep.Path, Severity: models.SeverityLow, Source: models.SourceBlackbox},
		}
	}

	pool := NewWorkerPool(3, 0, []scanner.CheckFn{check})
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: server.URL + "/a"},
		{Method: "GET", Path: "/b", FullURL: server.URL + "/b"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

func TestWorkerPool_EmptyChecks(t *testing.T) {
	pool := NewWorkerPool(2, 0, nil)
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: "http://localhost/a"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no checks, got %d", len(findings))
	}
}

func TestWorkerPool_EmptyEndpoints(t *testing.T) {
	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		return []evidence.Evidence{{Title: "should not appear"}}
	}

	pool := NewWorkerPool(2, 0, []scanner.CheckFn{check})
	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, nil)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no endpoints, got %d", len(findings))
	}
}

// TestWorkerPool_PanicIsContained pins the per-job recover() contract: a
// check that panics on one endpoint must NOT abort the scan. The panicking
// job is recorded as a synthetic INFO finding ("Scanner check panicked") and
// every other job still runs to completion.
func TestWorkerPool_PanicIsContained(t *testing.T) {
	var goodCalls atomic.Int32
	good := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		goodCalls.Add(1)
		return []evidence.Evidence{{Title: "ok " + ep.Path, Severity: models.SeverityLow, Source: models.SourceBlackbox}}
	}
	boom := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		panic("synthetic check failure on " + ep.Path)
	}

	// Single worker so the panicking job and the good jobs share the same
	// goroutine — proves recover() lets the worker survive and keep pulling.
	pool := NewWorkerPool(1, 0, []scanner.CheckFn{boom, good})
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: "http://localhost/a"},
		{Method: "GET", Path: "/b", FullURL: "http://localhost/b"},
		{Method: "GET", Path: "/c", FullURL: "http://localhost/c"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	// The good check must have run on all 3 endpoints despite the panics.
	if got := goodCalls.Load(); got != 3 {
		t.Errorf("expected good check to run on all 3 endpoints, got %d (panic aborted other jobs?)", got)
	}

	var ok, panicked int
	for _, f := range findings {
		switch f.Title {
		case "Scanner check panicked":
			panicked++
			if f.Severity != models.SeverityInfo {
				t.Errorf("panic note should be INFO severity, got %s", f.Severity)
			}
			if f.Category != "engine" {
				t.Errorf("panic note should have category 'engine', got %q", f.Category)
			}
			if f.Endpoint == "" {
				t.Errorf("panic note should record the endpoint, got empty")
			}
		default:
			ok++
		}
	}
	if ok != 3 {
		t.Errorf("expected 3 good findings, got %d", ok)
	}
	if panicked != 3 {
		t.Errorf("expected 3 synthetic panic notes (one per endpoint), got %d", panicked)
	}
}

func TestWorkerPool_SingleWorker(t *testing.T) {
	var maxConcurrent atomic.Int32
	var current atomic.Int32

	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		c := current.Add(1)
		if c > maxConcurrent.Load() {
			maxConcurrent.Store(c)
		}
		current.Add(-1)
		return nil
	}

	pool := NewWorkerPool(1, 0, []scanner.CheckFn{check})
	endpoints := make([]scanner.Endpoint, 10)
	for i := range endpoints {
		endpoints[i] = scanner.Endpoint{Method: "GET", Path: "/test", FullURL: "http://localhost/test"}
	}

	cfg := &models.ScanConfig{Timeout: 10}
	pool.Run(context.Background(), cfg, endpoints)

	if maxConcurrent.Load() > 1 {
		t.Errorf("with 1 worker, max concurrency should be 1, got %d", maxConcurrent.Load())
	}
}
