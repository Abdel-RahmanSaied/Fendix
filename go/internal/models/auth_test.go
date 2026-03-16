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
