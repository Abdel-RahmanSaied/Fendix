package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
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
		AllowPrivate: true,
		Timeout:      5,
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
		AllowPrivate: true,
		Timeout:      5,
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
		AllowPrivate: true,
		Timeout:      5,
		Auth:         nil,
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

// newJWTOnlyServer mocks a server that DOES check for the
// Authorization header (rejects no-auth with 401) but fails to
// validate JWT structure (accepts everything including malformed,
// expired, alg:none). This is the legitimate JWT-bypass vulnerability
// shape — distinct from a fully-public endpoint, which is handled by
// `Missing authentication on endpoint` and dedupes the JWT findings.
func newJWTOnlyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// No Authorization header → 401 (so missing-auth probe sees 401 and skips)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Any Authorization header value → 200 (no actual validation)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
}

func TestCheckAuth_MalformedJWT_Vulnerable(t *testing.T) {
	// Server REQUIRES auth header but doesn't validate JWT — real JWT-bypass.
	// (Using a fully-accept-everything server would dedup these findings as
	// FPs of the "missing authentication" root cause; see the Track 4
	// FP-dedup posture in auth.go::CheckAuth.)
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
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
		AllowPrivate: true,
		Timeout:      5,
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
	// Real JWT-bypass shape: server requires header but doesn't check exp.
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
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
		AllowPrivate: true,
		Timeout:      5,
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
	// Real JWT-bypass shape: server requires header but doesn't validate alg.
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
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
		AllowPrivate: true,
		Timeout:      5,
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
		AllowPrivate: true,
		Timeout:      5,
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

// TestCheckAuth_PublicEndpointEmitsOnlyMissingAuth verifies the FP-dedup
// posture surfaced by the Track 4 heavy-eval (TwiScope-backend /metrics
// scan). When an endpoint accepts ALL Authorization values — no header,
// garbage Bearer, real JWT — it's fully public. The previous behaviour
// emitted 4 CRITICALs (Missing-auth + 3 JWT-bypass). The new behaviour
// emits only the root cause (Missing-auth); the 3 JWT findings are
// downstream byproducts of the same fix and add no operational signal.
func TestCheckAuth_PublicEndpointEmitsOnlyMissingAuth(t *testing.T) {
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/metrics",
		FullURL: server.URL + "/metrics",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
		if f.Source != models.SourceBlackbox {
			t.Errorf("finding %q source = %s, want blackbox", f.Title, f.Source)
		}
	}

	// Missing-auth fires (the root cause)
	if !titles["Missing authentication on endpoint"] {
		t.Error("expected 'Missing authentication on endpoint' to fire on fully-public endpoint")
	}
	// The 3 JWT-bypass findings are suppressed as FPs of the root cause
	for _, suppressed := range []string{
		"JWT not validated",
		"Expired JWT accepted",
		"JWT algorithm confusion (alg:none accepted)",
	} {
		if titles[suppressed] {
			t.Errorf("Track 4 FP-dedup: %q should be suppressed on fully-public endpoint (root cause is missing-auth)", suppressed)
		}
	}
}

// TestCheckAuth_JWTBypassEndpointEmitsAllJWTFindings is the contrast
// case: when the endpoint DOES require an Authorization header but
// fails to validate the JWT structure, the missing-auth check does
// NOT fire, and the JWT-bypass findings should ALL fire because each
// is an independent vulnerability. This proves the dedup only kicks
// in on the public-endpoint shape, not on real JWT-bypass surfaces.
func TestCheckAuth_JWTBypassEndpointEmitsAllJWTFindings(t *testing.T) {
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
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

	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
	}

	// Missing-auth should NOT fire (server returns 401 to no-auth)
	if titles["Missing authentication on endpoint"] {
		t.Error("missing-auth should not fire when server returns 401 to no-Authorization request")
	}
	// All 3 JWT-bypass findings should fire (independent vulnerabilities)
	for _, expected := range []string{
		"JWT not validated",
		"Expired JWT accepted",
		"JWT algorithm confusion (alg:none accepted)",
	} {
		if !titles[expected] {
			t.Errorf("expected JWT-bypass finding %q to fire on header-checks-only server", expected)
		}
	}
}
