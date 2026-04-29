package models

import (
	"net/http"
	"os"
	"strings"
)

const (
	AuthTypeBearer = "bearer"
	AuthTypeAPIKey = "apikey"
	// AuthTypeAPIKeyQuery places the API key in a query-string parameter
	// rather than a request header. Param name comes from AuthContext.Header
	// (a small overload — Header doubles as the query-param name in this
	// mode); defaults to "api_key" if unset.
	AuthTypeAPIKeyQuery = "apikey-query"
	AuthTypeBasic       = "basic"
	AuthTypeCookie      = "cookie"

	EnvAuth       = "FENDIX_AUTH"
	EnvAuthType   = "FENDIX_AUTH_TYPE"
	EnvAuthHeader = "FENDIX_AUTH_HEADER"

	DefaultAuthHeader        = "Authorization"
	DefaultAPIKeyQueryParam  = "api_key"
)

// ResolveAuth resolves authentication from multiple sources in priority order:
//  1. CLI flags (provided AuthContext)
//  2. Environment variables (FENDIX_AUTH, FENDIX_AUTH_TYPE, FENDIX_AUTH_HEADER)
//  3. Config file (~/.fendix/profiles/) — resolved via ProfileLoader if provided
//
// Returns nil if no auth source is available.
func ResolveAuth(flagAuth *AuthContext, profileLoader func() *AuthContext) *AuthContext {
	if flagAuth != nil && flagAuth.Value != "" {
		return NormalizeAuth(flagAuth)
	}

	if envValue := os.Getenv(EnvAuth); envValue != "" {
		auth := &AuthContext{
			Value:  envValue,
			Type:   os.Getenv(EnvAuthType),
			Header: os.Getenv(EnvAuthHeader),
		}
		return NormalizeAuth(auth)
	}

	if profileLoader != nil {
		if auth := profileLoader(); auth != nil && auth.Value != "" {
			return NormalizeAuth(auth)
		}
	}

	return nil
}

// NormalizeAuth fills in defaults: sets the header to Authorization if empty,
// auto-detects auth type if not specified, and overrides header for cookie
// (always "Cookie") and apikey-query (defaults to "api_key" unless user set
// it explicitly). The apikey-query default is applied AFTER the empty-header
// fallback so the user's explicit `--auth-header api_secret` wins.
func NormalizeAuth(auth *AuthContext) *AuthContext {
	if auth == nil {
		return nil
	}
	headerExplicit := auth.Header != ""
	if auth.Header == "" {
		auth.Header = DefaultAuthHeader
	}
	if auth.Type == "" {
		auth.Type = DetectAuthType(auth.Value)
	}
	if auth.Type == AuthTypeCookie {
		auth.Header = "Cookie"
	}
	if auth.Type == AuthTypeAPIKeyQuery && !headerExplicit {
		auth.Header = DefaultAPIKeyQueryParam
	}
	return auth
}

// DetectAuthType infers the authentication scheme from the credential value.
// "Bearer ..." → bearer, "Basic ..." → basic, key=value → cookie, else → bearer.
func DetectAuthType(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))

	switch {
	case strings.HasPrefix(lower, "bearer "):
		return AuthTypeBearer
	case strings.HasPrefix(lower, "basic "):
		return AuthTypeBasic
	case strings.Contains(value, "=") && !strings.Contains(lower, " "):
		return AuthTypeCookie
	default:
		return AuthTypeBearer
	}
}

// Redacted returns "[REDACTED]" for any non-empty credential.
// Auth credentials must never appear in report output.
func (a *AuthContext) Redacted() string {
	if a == nil || a.Value == "" {
		return ""
	}
	return "[REDACTED]"
}

// RedactedHeader returns the header name and a masked value, safe for logging.
func (a *AuthContext) RedactedHeader() (string, string) {
	if a == nil || a.Value == "" {
		return "", ""
	}
	return a.Header, "[REDACTED]"
}

// ApplyToRequest sets the authentication on an HTTP request — either as a
// header (default) or as a query-string parameter (apikey-query mode).
// Safe to call on a nil receiver.
func (a *AuthContext) ApplyToRequest(req *http.Request) {
	if a == nil || a.Value == "" {
		return
	}
	if a.Type == AuthTypeAPIKeyQuery {
		// Mutate the query string in place. url.Values.Set replaces an
		// existing value (idempotent across multiple ApplyToRequest calls
		// on the same request — defensive against accidental double-apply).
		q := req.URL.Query()
		q.Set(a.Header, a.Value)
		req.URL.RawQuery = q.Encode()
		return
	}
	req.Header.Set(a.Header, a.Value)
}
