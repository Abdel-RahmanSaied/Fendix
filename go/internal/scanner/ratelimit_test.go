package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestCheckRateLimit_NoLimiting(t *testing.T) {
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for no rate limiting, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "No rate limiting detected" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
	if int(reqCount.Load()) != rateLimitProbeCount {
		t.Errorf("expected %d requests sent, got %d", rateLimitProbeCount, reqCount.Load())
	}
}

// TASK-123 / FP corpus pattern P3: static-file paths don't warrant a
// "no rate limiting" finding — they're served by CDNs / static-file
// middleware, not the API layer. Also avoids the cost of N probe
// requests against an asset.
func TestCheckRateLimit_SkipsStaticFile(t *testing.T) {
	cases := []string{
		"/.DS_Store",
		"/favicon.ico",
		"/robots.txt",
		"/static/app.bundle.js",
		"/assets/style.css",
		"/img/logo.png",
		"/fonts/Inter.woff2",
		"/source.map",
		"/sitemap.xml",
		"/security.txt",
	}
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	for _, path := range cases {
		reqCount.Store(0)
		ep := Endpoint{Method: "GET", Path: path, FullURL: server.URL + path}
		findings := CheckRateLimit(context.Background(), cfg, ep)
		if len(findings) != 0 {
			t.Errorf("%s: expected 0 findings (static file), got %d", path, len(findings))
		}
		if reqCount.Load() != 0 {
			t.Errorf("%s: expected 0 requests sent (early-skip), got %d", path, reqCount.Load())
		}
	}
}

func TestCheckRateLimit_ApiPathStillScanned(t *testing.T) {
	// Negative control — an API path with the same shape but a non-
	// static extension still triggers the full check.
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("api path should still emit finding, got %d", len(findings))
	}
	if reqCount.Load() != int32(rateLimitProbeCount) {
		t.Errorf("api path should send all probes, got %d", reqCount.Load())
	}
}

func TestCheckRateLimit_Returns429(t *testing.T) {
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := reqCount.Add(1)
		if count > 5 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when 429 returned, got %d", len(findings))
	}
}

func TestCheckRateLimit_HasRateLimitHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "99")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when rate limit headers present, got %d", len(findings))
	}
}

func TestCheckRateLimit_RetryAfterHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when Retry-After present, got %d", len(findings))
	}
}

func TestCheckRateLimit_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: server.URL + "/api/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(ctx, cfg, ep)
	if findings != nil {
		t.Fatalf("expected nil findings on cancelled context, got %d", len(findings))
	}
}
