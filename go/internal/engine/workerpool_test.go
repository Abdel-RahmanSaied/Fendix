package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/fendix/fendix/internal/models"
	"github.com/fendix/fendix/internal/scanner"
)

func TestWorkerPool_RunsAllChecks(t *testing.T) {
	var callCount atomic.Int32
	check1 := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []models.Finding {
		callCount.Add(1)
		return []models.Finding{{Title: "check1", Severity: models.SeverityLow, Source: models.SourceBlackbox}}
	}
	check2 := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []models.Finding {
		callCount.Add(1)
		return []models.Finding{{Title: "check2", Severity: models.SeverityMedium, Source: models.SourceBlackbox}}
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
	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []models.Finding {
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

	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []models.Finding {
		return []models.Finding{
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
	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []models.Finding {
		return []models.Finding{{Title: "should not appear"}}
	}

	pool := NewWorkerPool(2, 0, []scanner.CheckFn{check})
	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, nil)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no endpoints, got %d", len(findings))
	}
}

func TestWorkerPool_SingleWorker(t *testing.T) {
	var maxConcurrent atomic.Int32
	var current atomic.Int32

	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []models.Finding {
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
