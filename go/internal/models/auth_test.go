package models

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectAuthType(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"bearer with prefix", "Bearer eyJhbGciOiJIUzI1NiJ9.token", AuthTypeBearer},
		{"bearer lowercase", "bearer tok123", AuthTypeBearer},
		{"basic with prefix", "Basic dXNlcjpwYXNz", AuthTypeBasic},
		{"basic lowercase", "basic dXNlcjpwYXNz", AuthTypeBasic},
		{"cookie key=value", "session=abc123", AuthTypeCookie},
		{"cookie multiple pairs", "session=abc;csrf=xyz", AuthTypeCookie},
		{"raw token defaults to bearer", "sk-live-abc123def456ghi789", AuthTypeBearer},
		{"empty defaults to bearer", "", AuthTypeBearer},
		{"jwt-like defaults to bearer", "eyJhbGciOiJIUzI1NiJ9.payload.sig", AuthTypeBearer},
		{"api key with spaces defaults to bearer", "my secret key", AuthTypeBearer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectAuthType(tt.value)
			if got != tt.want {
				t.Errorf("DetectAuthType(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestNormalizeAuth(t *testing.T) {
	tests := []struct {
		name       string
		input      *AuthContext
		wantType   string
		wantHeader string
	}{
		{
			name:       "nil returns nil",
			input:      nil,
			wantType:   "",
			wantHeader: "",
		},
		{
			name:       "fills default header",
			input:      &AuthContext{Value: "Bearer tok", Type: AuthTypeBearer},
			wantType:   AuthTypeBearer,
			wantHeader: DefaultAuthHeader,
		},
		{
			name:       "auto-detects bearer",
			input:      &AuthContext{Value: "Bearer tok123"},
			wantType:   AuthTypeBearer,
			wantHeader: DefaultAuthHeader,
		},
		{
			name:       "auto-detects basic",
			input:      &AuthContext{Value: "Basic dXNlcjpwYXNz"},
			wantType:   AuthTypeBasic,
			wantHeader: DefaultAuthHeader,
		},
		{
			name:       "cookie overrides header",
			input:      &AuthContext{Value: "session=abc123", Type: AuthTypeCookie},
			wantType:   AuthTypeCookie,
			wantHeader: "Cookie",
		},
		{
			name:       "auto-detects cookie and overrides header",
			input:      &AuthContext{Value: "session=abc123"},
			wantType:   AuthTypeCookie,
			wantHeader: "Cookie",
		},
		{
			name:       "preserves custom header for non-cookie",
			input:      &AuthContext{Value: "mykey", Type: AuthTypeAPIKey, Header: "X-API-Key"},
			wantType:   AuthTypeAPIKey,
			wantHeader: "X-API-Key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeAuth(tt.input)
			if tt.input == nil {
				if got != nil {
					t.Fatal("expected nil for nil input")
				}
				return
			}
			if got.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Header != tt.wantHeader {
				t.Errorf("Header = %q, want %q", got.Header, tt.wantHeader)
			}
		})
	}
}

func TestResolveAuth_FlagPriority(t *testing.T) {
	t.Setenv(EnvAuth, "env-token")
	t.Setenv(EnvAuthType, AuthTypeBearer)

	flagAuth := &AuthContext{Value: "Bearer flag-token"}
	got := ResolveAuth(flagAuth, nil)

	if got == nil {
		t.Fatal("expected non-nil auth")
	}
	if got.Value != "Bearer flag-token" {
		t.Errorf("Value = %q, want flag value", got.Value)
	}
}

func TestResolveAuth_EnvFallback(t *testing.T) {
	t.Setenv(EnvAuth, "Bearer env-token-123")
	t.Setenv(EnvAuthType, "")
	t.Setenv(EnvAuthHeader, "")

	got := ResolveAuth(nil, nil)

	if got == nil {
		t.Fatal("expected non-nil auth from env")
	}
	if got.Value != "Bearer env-token-123" {
		t.Errorf("Value = %q, want env value", got.Value)
	}
	if got.Type != AuthTypeBearer {
		t.Errorf("Type = %q, want auto-detected bearer", got.Type)
	}
	if got.Header != DefaultAuthHeader {
		t.Errorf("Header = %q, want default", got.Header)
	}
}

func TestResolveAuth_EnvWithExplicitType(t *testing.T) {
	t.Setenv(EnvAuth, "mytoken")
	t.Setenv(EnvAuthType, AuthTypeAPIKey)
	t.Setenv(EnvAuthHeader, "X-API-Key")

	got := ResolveAuth(nil, nil)

	if got == nil {
		t.Fatal("expected non-nil auth from env")
	}
	if got.Type != AuthTypeAPIKey {
		t.Errorf("Type = %q, want %q", got.Type, AuthTypeAPIKey)
	}
	if got.Header != "X-API-Key" {
		t.Errorf("Header = %q, want X-API-Key", got.Header)
	}
}

func TestResolveAuth_ProfileLoaderFallback(t *testing.T) {
	loader := func() *AuthContext {
		return &AuthContext{Value: "Bearer profile-token", Type: AuthTypeBearer}
	}

	got := ResolveAuth(nil, loader)

	if got == nil {
		t.Fatal("expected non-nil auth from profile loader")
	}
	if got.Value != "Bearer profile-token" {
		t.Errorf("Value = %q, want profile value", got.Value)
	}
}

func TestResolveAuth_NilEverywhere(t *testing.T) {
	t.Setenv(EnvAuth, "")

	got := ResolveAuth(nil, nil)
	if got != nil {
		t.Errorf("expected nil when no auth source available, got %+v", got)
	}
}

func TestResolveAuth_EmptyFlagFallsToEnv(t *testing.T) {
	t.Setenv(EnvAuth, "Bearer env-tok")

	flagAuth := &AuthContext{Value: ""}
	got := ResolveAuth(flagAuth, nil)

	if got == nil {
		t.Fatal("expected env fallback")
	}
	if got.Value != "Bearer env-tok" {
		t.Errorf("Value = %q, want env value", got.Value)
	}
}

func TestAuthContext_Redacted(t *testing.T) {
	tests := []struct {
		name string
		auth *AuthContext
		want string
	}{
		{"nil auth", nil, ""},
		{"empty value", &AuthContext{Value: ""}, ""},
		{"short token", &AuthContext{Value: "tok"}, "[REDACTED]"},
		{"bearer token", &AuthContext{Value: "Bearer eyJhbGciOiJIUzI1NiJ9.long.token"}, "[REDACTED]"},
		{"api key", &AuthContext{Value: "sk-live-abc123def456"}, "[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.auth.Redacted()
			if got != tt.want {
				t.Errorf("Redacted() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthContext_RedactedHeader(t *testing.T) {
	auth := &AuthContext{Header: "Authorization", Value: "Bearer secret"}
	hdr, val := auth.RedactedHeader()
	if hdr != "Authorization" {
		t.Errorf("header = %q, want Authorization", hdr)
	}
	if val != "[REDACTED]" {
		t.Errorf("value = %q, want [REDACTED]", val)
	}

	var nilAuth *AuthContext
	hdr, val = nilAuth.RedactedHeader()
	if hdr != "" || val != "" {
		t.Errorf("nil auth RedactedHeader should return empty, got %q %q", hdr, val)
	}
}

func TestAuthContext_ApplyToRequest(t *testing.T) {
	tests := []struct {
		name       string
		auth       *AuthContext
		wantHeader string
		wantValue  string
	}{
		{
			name:       "bearer auth",
			auth:       &AuthContext{Header: "Authorization", Value: "Bearer tok123"},
			wantHeader: "Authorization",
			wantValue:  "Bearer tok123",
		},
		{
			name:       "api key",
			auth:       &AuthContext{Header: "X-API-Key", Value: "mykey"},
			wantHeader: "X-API-Key",
			wantValue:  "mykey",
		},
		{
			name:       "cookie",
			auth:       &AuthContext{Header: "Cookie", Value: "session=abc123"},
			wantHeader: "Cookie",
			wantValue:  "session=abc123",
		},
		{
			name: "nil auth is safe",
			auth: nil,
		},
		{
			name: "empty value is safe",
			auth: &AuthContext{Header: "Authorization", Value: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			tt.auth.ApplyToRequest(req)

			if tt.wantHeader != "" {
				got := req.Header.Get(tt.wantHeader)
				if got != tt.wantValue {
					t.Errorf("header %q = %q, want %q", tt.wantHeader, got, tt.wantValue)
				}
			}
		})
	}
}

func TestApplyToRequest_NoSideEffectOnNil(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	originalHeaders := len(req.Header)

	var auth *AuthContext
	auth.ApplyToRequest(req)

	if len(req.Header) != originalHeaders {
		t.Error("nil ApplyToRequest should not modify request headers")
	}
}

// TestNormalizeAuth_APIKeyQueryDefaults covers the new apikey-query type
// (TASK-096). Without an explicit --auth-header, the param name should
// default to "api_key"; an explicit value must be preserved.
func TestNormalizeAuth_APIKeyQueryDefaults(t *testing.T) {
	t.Run("default param name when header unset", func(t *testing.T) {
		auth := NormalizeAuth(&AuthContext{
			Type:  AuthTypeAPIKeyQuery,
			Value: "mykey",
		})
		if auth.Header != DefaultAPIKeyQueryParam {
			t.Errorf("default Header: got %q, want %q", auth.Header, DefaultAPIKeyQueryParam)
		}
	})
	t.Run("explicit param name preserved", func(t *testing.T) {
		auth := NormalizeAuth(&AuthContext{
			Type:   AuthTypeAPIKeyQuery,
			Value:  "mykey",
			Header: "api_secret",
		})
		if auth.Header != "api_secret" {
			t.Errorf("explicit Header: got %q, want %q", auth.Header, "api_secret")
		}
	})
}

// TestApplyToRequest_APIKeyQueryMutatesURL is the wire-format regression
// for apikey-query: the credential goes into the URL query string, NOT
// into a request header. This is the single most important contract for
// the new auth type.
func TestApplyToRequest_APIKeyQueryMutatesURL(t *testing.T) {
	t.Run("appends to empty query string", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/api/users", nil)
		auth := &AuthContext{
			Type:   AuthTypeAPIKeyQuery,
			Value:  "secret-key-123",
			Header: "api_key",
		}
		auth.ApplyToRequest(req)
		if got := req.URL.Query().Get("api_key"); got != "secret-key-123" {
			t.Errorf("query api_key: got %q, want secret-key-123", got)
		}
		// And the credential must NOT appear as a header.
		if h := req.Header.Get("api_key"); h != "" {
			t.Errorf("apikey-query must not set a header; got header api_key=%q", h)
		}
		if h := req.Header.Get("Authorization"); h != "" {
			t.Errorf("apikey-query must not touch Authorization header; got %q", h)
		}
	})

	t.Run("preserves existing query params", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/api/users?page=2", nil)
		auth := &AuthContext{
			Type:   AuthTypeAPIKeyQuery,
			Value:  "abc",
			Header: "key",
		}
		auth.ApplyToRequest(req)
		q := req.URL.Query()
		if got := q.Get("page"); got != "2" {
			t.Errorf("existing page param lost: got %q, want 2", got)
		}
		if got := q.Get("key"); got != "abc" {
			t.Errorf("auth param missing: got %q, want abc", got)
		}
	})

	t.Run("idempotent on double-apply", func(t *testing.T) {
		// Defensive: the same request might pass through ApplyToRequest
		// multiple times if a wrapper retries. Result should still have
		// exactly one auth param value.
		req := httptest.NewRequest("GET", "http://example.com/api", nil)
		auth := &AuthContext{
			Type:   AuthTypeAPIKeyQuery,
			Value:  "v1",
			Header: "k",
		}
		auth.ApplyToRequest(req)
		auth.ApplyToRequest(req)
		params := req.URL.Query()["k"]
		if len(params) != 1 || params[0] != "v1" {
			t.Errorf("double-apply should be idempotent; got %v", params)
		}
	})
}

// TestApplyToRequest_HeaderTypesUnchanged verifies the refactor to
// ApplyToRequest from direct Header.Set didn't break the wire format for
// the original auth types (bearer/apikey-header/basic/cookie).
func TestApplyToRequest_HeaderTypesUnchanged(t *testing.T) {
	tests := []struct {
		name       string
		auth       *AuthContext
		wantHeader string
		wantValue  string
	}{
		{
			name:       "bearer",
			auth:       &AuthContext{Type: AuthTypeBearer, Header: "Authorization", Value: "Bearer xyz"},
			wantHeader: "Authorization",
			wantValue:  "Bearer xyz",
		},
		{
			name:       "apikey-header",
			auth:       &AuthContext{Type: AuthTypeAPIKey, Header: "X-API-Key", Value: "mykey"},
			wantHeader: "X-API-Key",
			wantValue:  "mykey",
		},
		{
			name:       "basic",
			auth:       &AuthContext{Type: AuthTypeBasic, Header: "Authorization", Value: "Basic dXNlcjpwYXNz"},
			wantHeader: "Authorization",
			wantValue:  "Basic dXNlcjpwYXNz",
		},
		{
			name:       "cookie",
			auth:       &AuthContext{Type: AuthTypeCookie, Header: "Cookie", Value: "session=abc"},
			wantHeader: "Cookie",
			wantValue:  "session=abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			tt.auth.ApplyToRequest(req)
			if got := req.Header.Get(tt.wantHeader); got != tt.wantValue {
				t.Errorf("%s header: got %q, want %q", tt.wantHeader, got, tt.wantValue)
			}
			// And the URL must remain untouched for header-mode auth.
			if req.URL.RawQuery != "" {
				t.Errorf("%s should not mutate URL query; got %q", tt.name, req.URL.RawQuery)
			}
		})
	}
}
