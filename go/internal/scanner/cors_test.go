package scanner

// These tests scan loopback httptest servers. The SSRF egress guard
// (internal/netguard) refuses loopback/private addresses by default, so each
// config sets AllowPrivate: true — exactly what a real scan auto-applies when
// the --url target resolves to a private/loopback host (see allowPrivate /
// netguard.TargetIsPrivate).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestCheckCORS_WildcardWithCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for wildcard+credentials, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS wildcard origin with credentials allowed" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestCheckCORS_WildcardWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/public", FullURL: server.URL + "/api/public"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for wildcard ACAO, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestCheckCORS_ReflectedOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for reflected origin, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS reflects arbitrary origin" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestCheckCORS_NonStandardMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, TRACE, PURGE")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for non-standard methods, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
}

func TestCheckCORS_NoCORSHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/safe", FullURL: server.URL + "/api/safe"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for no CORS headers, got %d", len(findings))
	}
}

// TASK-123 / FP corpus pattern P2: CORS misconfig findings on a 404
// page are unreachable — the path doesn't serve a feature. Skip.
func TestCheckCORS_SkipsOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set a wildcard ACAO that *would* fire a CRITICAL finding — but
		// the 404 status should gate it out.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(404)
	}))
	defer server.Close()
	ep := Endpoint{Method: "GET", Path: "/.env.local", FullURL: server.URL + "/.env.local"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 CORS findings on 404, got %d: %+v", len(findings), findings)
	}
}

func TestCheckCORS_ProperConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/secure", FullURL: server.URL + "/api/secure"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for proper CORS config, got %d", len(findings))
	}
}

func TestCheckCORS_MultipleIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, TRACE")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/bad", FullURL: server.URL + "/api/bad"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (wildcard + non-standard method), got %d", len(findings))
	}
}
