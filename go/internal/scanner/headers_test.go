package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestCheckHeaders_AllMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10}

	findings := CheckHeaders(context.Background(), cfg, ep)

	// Missing: HSTS, X-Content-Type-Options, X-Frame-Options, CSP = 4 findings
	// Server and X-Powered-By are absent → no info findings (correct behavior)
	if len(findings) < 4 {
		t.Fatalf("expected at least 4 findings for no security headers, got %d", len(findings))
	}

	titles := make(map[string]bool)
	for _, f := range findings {
		titles[f.Title] = true
		if f.Source != models.SourceBlackbox {
			t.Errorf("expected source blackbox, got %s for %s", f.Source, f.Title)
		}
		if f.Category != "headers" {
			t.Errorf("expected category headers, got %s for %s", f.Category, f.Title)
		}
	}

	expected := []string{
		"Missing Strict-Transport-Security header",
		"Missing or incorrect X-Content-Type-Options header",
		"Missing or incorrect X-Frame-Options header",
		"Missing Content-Security-Policy header",
	}
	for _, title := range expected {
		if !titles[title] {
			t.Errorf("missing expected finding: %s", title)
		}
	}
}

func TestCheckHeaders_AllPresent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when all headers present, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  finding: %s", f.Title)
		}
	}
}

func TestCheckHeaders_SeverityMapping(t *testing.T) {
	tests := []struct {
		name             string
		setHeaders       func(w http.ResponseWriter)
		expectedSeverity models.Severity
		expectedTitle    string
	}{
		{
			name:             "HSTS missing is MEDIUM",
			setHeaders:       func(w http.ResponseWriter) {},
			expectedSeverity: models.SeverityMedium,
			expectedTitle:    "Missing Strict-Transport-Security header",
		},
		{
			name: "X-Content-Type-Options wrong value is LOW",
			setHeaders: func(w http.ResponseWriter) {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000")
				w.Header().Set("X-Frame-Options", "DENY")
				w.Header().Set("Content-Security-Policy", "default-src 'self'")
				w.Header().Set("X-Content-Type-Options", "wrong")
			},
			expectedSeverity: models.SeverityLow,
			expectedTitle:    "Missing or incorrect X-Content-Type-Options header",
		},
		{
			name: "X-Frame-Options SAMEORIGIN is OK",
			setHeaders: func(w http.ResponseWriter) {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "SAMEORIGIN")
				w.Header().Set("Content-Security-Policy", "default-src 'self'")
			},
			expectedSeverity: "",
			expectedTitle:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.setHeaders(w)
				w.WriteHeader(200)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
			cfg := &models.ScanConfig{Timeout: 10}
			findings := CheckHeaders(context.Background(), cfg, ep)

			if tt.expectedTitle == "" {
				if len(findings) != 0 {
					t.Fatalf("expected 0 findings, got %d", len(findings))
				}
				return
			}

			found := false
			for _, f := range findings {
				if f.Title == tt.expectedTitle {
					found = true
					if f.Severity != tt.expectedSeverity {
						t.Errorf("severity for %q: got %s, want %s", f.Title, f.Severity, tt.expectedSeverity)
					}
				}
			}
			if !found {
				t.Errorf("expected finding %q not found", tt.expectedTitle)
			}
		})
	}
}

func TestCheckHeaders_ServerVersionDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Server", "nginx/1.21.3")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for server version, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityInfo {
		t.Errorf("server version disclosure should be INFO, got %s", findings[0].Severity)
	}
}

func TestCheckHeaders_XPoweredBy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{Timeout: 10}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for X-Powered-By, got %d", len(findings))
	}
	if findings[0].Title != "X-Powered-By header discloses technology" {
		t.Errorf("unexpected finding title: %s", findings[0].Title)
	}
}

func TestCheckHeaders_WithAuth(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/test", FullURL: server.URL + "/test"}
	cfg := &models.ScanConfig{
		Timeout: 10,
		Auth: &models.AuthContext{
			Type:   "bearer",
			Value:  "Bearer testtoken",
			Header: "Authorization",
		},
	}

	CheckHeaders(context.Background(), cfg, ep)
	if receivedAuth != "Bearer testtoken" {
		t.Errorf("expected auth header to be sent, got %q", receivedAuth)
	}
}

func TestContainsVersion(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"nginx/1.21.3", true},
		{"Apache/2.4.52", true},
		{"nginx", false},
		{"cloudflare", false},
		{"gunicorn/20.1.0", true},
		{"", false},
		{"1.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			result := containsVersion(tt.value)
			if result != tt.expected {
				t.Errorf("containsVersion(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

// TestCheckHeaders_LogaggCapsTransientErrors is the regression test for
// TASK-094 logging hygiene. Real-world scans against partially-unreachable
// targets used to flood logs with one slog.Warn per failed request. Now
// CheckHeaders routes its transient-error WARN through logagg, which caps
// per-key emission at DefaultCap and downgrades the rest to slog.Debug.
//
// The fixture is a server that immediately closes every connection so the
// request fails consistently. Calling CheckHeaders 10 times should produce
// at most DefaultCap WARN-level emissions tracked under key="headers".
func TestCheckHeaders_LogaggCapsTransientErrors(t *testing.T) {
	logagg.Reset()
	defer logagg.Reset()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Start()
	server.Close() // close immediately so subsequent dials fail

	cfg := &models.ScanConfig{Timeout: 1}
	ep := Endpoint{Method: "GET", Path: "/", FullURL: server.URL + "/"}

	const calls = 10
	for i := 0; i < calls; i++ {
		_ = CheckHeaders(context.Background(), cfg, ep)
	}

	warned, suppressed := logagg.Stats("headers")
	if warned != logagg.DefaultCap {
		t.Errorf("warned: got %d, want %d", warned, logagg.DefaultCap)
	}
	if warned+suppressed != calls {
		t.Errorf("total events: warned=%d suppressed=%d sum=%d, want %d", warned, suppressed, warned+suppressed, calls)
	}
}
