package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestCheckExposure_PasswordField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"username": "admin", "password": "supersecret123", "email": "a@b.com"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users/1", FullURL: server.URL + "/api/users/1"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for password exposure")
	}

	found := false
	for _, f := range findings {
		if f.Title == "Password exposed in API response" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("password exposure should be CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing password exposure finding")
	}
}

func TestCheckExposure_SecretField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"api_key": "sk-live-1234567890abcdef", "name": "test"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/config", FullURL: server.URL + "/api/config"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Secret or API key exposed in API response" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("secret exposure should be CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing secret exposure finding")
	}
}

func TestCheckExposure_TokenField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghijklmnop"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "POST", Path: "/api/login", FullURL: server.URL + "/api/login"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Token exposed in API response" {
			found = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("token exposure should be HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing token exposure finding")
	}
}

func TestCheckExposure_StackTrace(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Python traceback",
			body: `{"error": "Internal Server Error", "detail": "Traceback (most recent call last):\n  File \"app.py\", line 42"}`,
		},
		{
			name: "Go panic",
			body: `panic: runtime error: index out of range [3] with length 3`,
		},
		{
			name: "Java stack trace",
			body: `Exception in thread "main" java.lang.NullPointerException`,
		},
		{
			name: "Node.js stack trace",
			body: `{"stack": "at Object.<anonymous> (/app/server.js:15:5)"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: "/api/error", FullURL: server.URL + "/api/error"}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

			findings := CheckExposure(context.Background(), cfg, ep)
			found := false
			for _, f := range findings {
				if f.Title == "Stack trace in error response" {
					found = true
					if f.Severity != models.SeverityMedium {
						t.Errorf("stack trace should be MEDIUM, got %s", f.Severity)
					}
				}
			}
			if !found {
				t.Errorf("missing stack trace finding for %s", tt.name)
			}
		})
	}
}

func TestCheckExposure_InternalIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"server": "10.0.1.42", "status": "ok"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/status", FullURL: server.URL + "/api/status"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Internal IP address disclosed in response" {
			found = true
			if f.Severity != models.SeverityLow {
				t.Errorf("internal IP should be LOW, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing internal IP finding")
	}
}

func TestCheckExposure_VersionString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"app": "myapp", "version": "3.14.1"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/info", FullURL: server.URL + "/api/info"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	found := false
	for _, f := range findings {
		if f.Title == "Software version string in response" {
			found = true
			if f.Severity != models.SeverityInfo {
				t.Errorf("version string should be INFO, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("missing version string finding")
	}
}

func TestCheckExposure_CleanResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id": 1, "name": "John", "email": "john@example.com"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users/1", FullURL: server.URL + "/api/users/1"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for clean response, got %d", len(findings))
	}
}

func TestCheckExposure_MultiplePatterns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"password": "hunter2", "api_key": "sk-live-abcdefghijklmnop", "server": "192.168.1.100"}`)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/dump", FullURL: server.URL + "/api/dump"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings for multiple patterns, got %d", len(findings))
	}
}

func TestCheckExposure_EvidenceTruncation(t *testing.T) {
	longSecret := `"api_key": "` + string(make([]byte, 300)) + `"`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{%s}`, longSecret)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: server.URL + "/api/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckExposure(context.Background(), cfg, ep)
	for _, f := range findings {
		if len(f.Evidence) > maxEvidenceLen+10 {
			t.Errorf("evidence not truncated: length %d", len(f.Evidence))
		}
	}
}
