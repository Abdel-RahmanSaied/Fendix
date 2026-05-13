package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// CheckAuth runs authentication checks on an endpoint.
// When auth is configured, it tests: unauthenticated access, malformed JWT,
// expired JWT, and alg:none JWT confusion.
func CheckAuth(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	if cfg.Auth == nil {
		return nil
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: budget.Transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	var findings []models.Finding

	missingAuth := checkUnauthenticated(ctx, client, cfg, endpoint, epLabel)
	if missingAuth != nil {
		findings = append(findings, *missingAuth)
	}

	// FP-dedup (Track 4 gap surfaced by TwiScope-backend /metrics scan).
	//
	// When the endpoint accepts a request with NO Authorization header
	// AND also accepts a request with a syntactically-invalid header
	// (e.g. "Bearer junk"), the auth handler isn't checking auth at
	// all — every JWT-bypass probe (malformed / expired / alg:none)
	// will also return 200, but those findings are downstream byproducts
	// of the same root cause. Emitting them produces 4 CRITICALs on
	// every public endpoint (Prometheus /metrics, health checks, etc.)
	// when only the first one ("Missing authentication") is actionable.
	//
	// Posture: only suppress JWT-bypass probes when BOTH probes (no
	// auth + garbage auth) succeed. If garbage-auth is rejected but
	// the original missing-auth succeeded, the endpoint does some
	// header-presence check — the JWT-bypass probes are still
	// meaningful (the endpoint distinguishes "no header" from "bad
	// signature", but may still accept the structurally-valid bad
	// tokens). Other endpoints in the scan are unaffected.
	suppressJWTProbes := false
	if missingAuth != nil && isJWTAuth(cfg.Auth) {
		if endpointAcceptsGarbageAuth(ctx, client, endpoint) {
			suppressJWTProbes = true
			slog.Debug("auth check: suppressing JWT-bypass probes (endpoint is fully unauthenticated — accepts no-auth AND garbage-auth)",
				"endpoint", epLabel)
		}
	}

	if isJWTAuth(cfg.Auth) && !suppressJWTProbes {
		findings = append(findings, checkJWTBypasses(ctx, client, cfg, endpoint, epLabel)...)
	}

	slog.Debug("auth check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}

// endpointAcceptsGarbageAuth returns true if a request with an
// obviously-invalid Authorization header still gets a 2xx response.
// Used by the FP-dedup logic above: an endpoint that 200s on both
// no-auth and "Bearer junk-not-a-jwt" isn't checking auth at all,
// so JWT-bypass findings on it are downstream noise from the
// missing-auth root cause.
//
// Network errors return false (conservative — keep the probe in play).
func endpointAcceptsGarbageAuth(ctx context.Context, client *http.Client, endpoint Endpoint) bool {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, nil)
	if err != nil {
		return false
	}
	// Deliberately bogus value: no dots, no base64, no jwt shape.
	req.Header.Set("Authorization", "Bearer fendix-auth-probe-not-a-real-token")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// checkUnauthenticated sends a request without auth credentials.
// If the server returns 200 instead of 401/403, it's a CRITICAL finding.
func checkUnauthenticated(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *models.Finding {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("auth", "auth check: failed to create unauthenticated request", "url", endpoint.FullURL, "error", err)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("auth", "auth check: unauthenticated request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &models.Finding{
			Title:      "Missing authentication on endpoint",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   epLabel,
			Evidence:   fmt.Sprintf("HTTP %d returned without Authorization header", resp.StatusCode),
			Fix:        "Require authentication. Return 401 for unauthenticated requests.",
			References: []string{"CWE-306", "OWASP-A01"},
			Confidence: models.ConfidenceHigh,
		}
	}

	return nil
}

// isJWTAuth returns true if the auth value looks like a JWT bearer token.
func isJWTAuth(auth *models.AuthContext) bool {
	if auth == nil {
		return false
	}
	val := strings.TrimSpace(auth.Value)
	if strings.HasPrefix(strings.ToLower(val), "bearer ") {
		val = strings.TrimSpace(val[7:])
	}
	parts := strings.Split(val, ".")
	return len(parts) == 3
}

// checkJWTBypasses tests three JWT-specific bypass scenarios:
// 1. Malformed JWT → server should reject with 401
// 2. Expired JWT → server should reject with 401
// 3. alg:none JWT confusion → server should reject with 401
func checkJWTBypasses(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) []models.Finding {
	var findings []models.Finding

	if f := checkMalformedJWT(ctx, client, cfg, endpoint, epLabel); f != nil {
		findings = append(findings, *f)
	}
	if f := checkExpiredJWT(ctx, client, cfg, endpoint, epLabel); f != nil {
		findings = append(findings, *f)
	}
	if f := checkAlgNoneJWT(ctx, client, cfg, endpoint, epLabel); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// checkMalformedJWT sends a request with an invalid JWT token.
func checkMalformedJWT(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *models.Finding {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set(cfg.Auth.Header, "Bearer invalid.jwt.token")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &models.Finding{
			Title:      "JWT not validated",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   epLabel,
			Evidence:   fmt.Sprintf("HTTP %d returned with malformed JWT 'Bearer invalid.jwt.token'", resp.StatusCode),
			Fix:        "Validate JWT signature and structure on every request. Reject malformed tokens with 401.",
			References: []string{"CWE-287", "OWASP-A07"},
			Confidence: models.ConfidenceHigh,
		}
	}
	return nil
}

// checkExpiredJWT generates a JWT with exp in the past and tests acceptance.
func checkExpiredJWT(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *models.Finding {
	expiredToken := buildExpiredJWT()
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set(cfg.Auth.Header, "Bearer "+expiredToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &models.Finding{
			Title:      "Expired JWT accepted",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   epLabel,
			Evidence:   fmt.Sprintf("HTTP %d returned with expired JWT (exp set to past)", resp.StatusCode),
			Fix:        "Validate the 'exp' claim in JWT tokens. Reject expired tokens with 401.",
			References: []string{"CWE-613", "OWASP-A07"},
			Confidence: models.ConfidenceHigh,
		}
	}
	return nil
}

// checkAlgNoneJWT sends a JWT with alg:none (no signature) to test for algorithm confusion.
func checkAlgNoneJWT(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *models.Finding {
	algNoneToken := buildAlgNoneJWT()
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set(cfg.Auth.Header, "Bearer "+algNoneToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &models.Finding{
			Title:      "JWT algorithm confusion (alg:none accepted)",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   epLabel,
			Evidence:   fmt.Sprintf("HTTP %d returned with alg:none JWT (unsigned token)", resp.StatusCode),
			Fix:        "Explicitly whitelist allowed JWT algorithms. Never accept alg:none.",
			References: []string{"CWE-327", "OWASP-A02"},
			Confidence: models.ConfidenceHigh,
		}
	}
	return nil
}

// buildExpiredJWT creates a HS256-signed JWT with exp set 1 hour in the past.
func buildExpiredJWT() string {
	header := base64URLEncode(mustJSON(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}))

	payload := base64URLEncode(mustJSON(map[string]interface{}{
		"sub":  "fendix-test",
		"iat":  time.Now().Add(-2 * time.Hour).Unix(),
		"exp":  time.Now().Add(-1 * time.Hour).Unix(),
		"role": "user",
	}))

	signingInput := header + "." + payload
	sig := hmacSHA256([]byte(signingInput), []byte("secret"))

	return signingInput + "." + base64URLEncode(sig)
}

// buildAlgNoneJWT creates an unsigned JWT with alg set to "none".
func buildAlgNoneJWT() string {
	header := base64URLEncode(mustJSON(map[string]string{
		"alg": "none",
		"typ": "JWT",
	}))

	payload := base64URLEncode(mustJSON(map[string]interface{}{
		"sub":  "fendix-test",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
		"role": "admin",
	}))

	return header + "." + payload + "."
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("json.Marshal: %v", err))
	}
	return b
}

func hmacSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
