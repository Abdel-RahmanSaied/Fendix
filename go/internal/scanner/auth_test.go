package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fendix/fendix/internal/models"
)

// newAuthTestServer creates a mock server that validates auth:
//   - validToken in Authorization header → 200
//   - missing/invalid auth → 401
//
// acceptAnything overrides to always return 200 (simulates broken auth).
func newAuthTestServer(validToken string, acceptAnything bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if acceptAnything {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == validToken {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
}

// newJWTTestServer creates a mock server that validates JWT structure:
//   - rejects malformed JWTs, expired JWTs, and alg:none JWTs
//   - accepts the given validToken
func newJWTTestServer(validToken string, rejectExpired, rejectAlgNone bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")

		// Reject malformed
		parts := strings.Split(token, ".")
		if len(parts) != 3 && !(len(parts) == 3 && parts[2] == "") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check for alg:none
		if rejectAlgNone && parts[2] == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check for "invalid.jwt.token" (malformed)
		if token == "invalid.jwt.token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if auth == validToken {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		// If expired checking enabled, reject unknown tokens
		if rejectExpired {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
}

func TestCheckAuth_UnauthenticatedAccess_Vulnerable(t *testing.T) {
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer valid-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: server.URL + "/api/users",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == "Missing authentication on endpoint" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
			if f.Category != "auth_bypass" {
				t.Errorf("category = %s, want auth_bypass", f.Category)
			}
			if f.Confidence != models.ConfidenceHigh {
				t.Errorf("confidence = %s, want HIGH", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected 'Missing authentication' finding for vulnerable server")
	}
}

func TestCheckAuth_UnauthenticatedAccess_Secure(t *testing.T) {
	server := newAuthTestServer("Bearer valid-token", false)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer valid-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: server.URL + "/api/users",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == "Missing authentication on endpoint" {
			t.Error("should not report unauthenticated access for secure server")
		}
	}
}

func TestCheckAuth_NoAuthConfig_Skips(t *testing.T) {
	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth:    nil,
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: "http://localhost/api/users",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("expected no findings with nil auth, got %d", len(findings))
	}
}

func TestCheckAuth_MalformedJWT_Vulnerable(t *testing.T) {
	// Server accepts everything — malformed JWT goes through
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == "JWT not validated" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected 'JWT not validated' finding")
	}
}

func TestCheckAuth_MalformedJWT_Secure(t *testing.T) {
	validToken := "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
	server := newJWTTestServer(validToken, true, true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == "JWT not validated" {
			t.Error("secure server should reject malformed JWT")
		}
	}
}

func TestCheckAuth_ExpiredJWT_Vulnerable(t *testing.T) {
	// Server accepts everything including expired tokens
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/data",
		FullURL: server.URL + "/api/data",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == "Expired JWT accepted" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected 'Expired JWT accepted' finding")
	}
}

func TestCheckAuth_ExpiredJWT_Secure(t *testing.T) {
	validToken := "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
	server := newJWTTestServer(validToken, true, true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/data",
		FullURL: server.URL + "/api/data",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == "Expired JWT accepted" {
			t.Error("secure server should reject expired JWT")
		}
	}
}

func TestCheckAuth_AlgNone_Vulnerable(t *testing.T) {
	// Server accepts everything including alg:none
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == "JWT algorithm confusion (alg:none accepted)" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected 'JWT algorithm confusion' finding")
	}
}

func TestCheckAuth_AlgNone_Secure(t *testing.T) {
	validToken := "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
	server := newJWTTestServer(validToken, true, true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == "JWT algorithm confusion (alg:none accepted)" {
			t.Error("secure server should reject alg:none JWT")
		}
	}
}

func TestCheckAuth_NonJWTAuth_SkipsJWTChecks(t *testing.T) {
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "X-API-Key",
			Value:  "sk-live-abcdef123456",
			Type:   models.AuthTypeAPIKey,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: server.URL + "/api/users",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if strings.Contains(f.Title, "JWT") {
			t.Errorf("JWT checks should not run for non-JWT auth, found: %s", f.Title)
		}
	}

	// Should still detect unauthenticated access
	var foundUnauth bool
	for _, f := range findings {
		if f.Title == "Missing authentication on endpoint" {
			foundUnauth = true
		}
	}
	if !foundUnauth {
		t.Error("should still detect unauthenticated access for non-JWT auth")
	}
}

func TestIsJWTAuth(t *testing.T) {
	tests := []struct {
		name string
		auth *models.AuthContext
		want bool
	}{
		{"nil auth", nil, false},
		{"bearer JWT", &models.AuthContext{Value: "Bearer eyJ.payload.sig"}, true},
		{"raw JWT", &models.AuthContext{Value: "eyJ.payload.sig"}, true},
		{"api key", &models.AuthContext{Value: "sk-live-abc123"}, false},
		{"basic auth", &models.AuthContext{Value: "Basic dXNlcjpwYXNz"}, false},
		{"empty", &models.AuthContext{Value: ""}, false},
		{"bearer non-jwt", &models.AuthContext{Value: "Bearer simpletoken"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJWTAuth(tt.auth)
			if got != tt.want {
				t.Errorf("isJWTAuth(%q) = %v, want %v", tt.auth, got, tt.want)
			}
		})
	}
}

func TestBuildExpiredJWT(t *testing.T) {
	token := buildExpiredJWT()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Error("all JWT parts should be non-empty")
	}
}

func TestBuildAlgNoneJWT(t *testing.T) {
	token := buildAlgNoneJWT()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	if parts[2] != "" {
		t.Error("alg:none JWT should have empty signature")
	}
}

func TestCheckAuth_AllFindingsForVulnerableServer(t *testing.T) {
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		Timeout: 5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	expectedTitles := map[string]bool{
		"Missing authentication on endpoint":          false,
		"JWT not validated":                            false,
		"Expired JWT accepted":                         false,
		"JWT algorithm confusion (alg:none accepted)": false,
	}

	for _, f := range findings {
		if _, ok := expectedTitles[f.Title]; ok {
			expectedTitles[f.Title] = true
		}
		if f.Source != models.SourceBlackbox {
			t.Errorf("finding %q source = %s, want blackbox", f.Title, f.Source)
		}
	}

	for title, found := range expectedTitles {
		if !found {
			t.Errorf("missing expected finding: %s", title)
		}
	}
}

