package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// newIDORVulnerableServer returns the same response regardless of which user token is used.
func newIDORVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":42,"name":"Shared Resource","secret":"data"}`))
	}))
}

// newIDORSecureServer returns different responses per user token.
func newIDORSecureServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch auth {
		case "Bearer user1-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":1,"name":"User 1 Data"}`))
		case "Bearer user2-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":2,"name":"User 2 Data"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
}

func TestCheckIDOR_Vulnerable(t *testing.T) {
	server := newIDORVulnerableServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1-token",
			Type:   models.AuthTypeBearer,
		},
		AuthUser2: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user2-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users/42",
		FullURL: server.URL + "/api/users/42",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}
	if f.Category != "idor" {
		t.Errorf("category = %s, want idor", f.Category)
	}
	if f.Confidence != models.ConfidenceMedium {
		t.Errorf("confidence = %s, want MEDIUM", f.Confidence)
	}
}

func TestCheckIDOR_Secure(t *testing.T) {
	server := newIDORSecureServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1-token",
			Type:   models.AuthTypeBearer,
		},
		AuthUser2: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user2-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users/me",
		FullURL: server.URL + "/api/users/me",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for secure server, got %d", len(findings))
	}
}

func TestCheckIDOR_NoUser2_Skips(t *testing.T) {
	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1-token",
		},
		AuthUser2: nil,
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/resource",
		FullURL: "http://localhost/api/resource",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings without user2, got %d", len(findings))
	}
}

func TestCheckIDOR_NoAuth_Skips(t *testing.T) {
	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         nil,
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/resource",
		FullURL: "http://localhost/api/resource",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings without auth, got %d", len(findings))
	}
}

func TestCheckIDOR_EmptyResponse_NoFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1",
		},
		AuthUser2: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user2",
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/empty",
		FullURL: server.URL + "/api/empty",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("empty responses should not trigger IDOR, got %d findings", len(findings))
	}
}
