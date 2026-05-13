# Sprint 08 — OIDC login for `fendix serve`

**Phase:** 3.2 | **Estimate:** 3 days | **Risk:** Med | **Ships:** v0.12.1
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §13 (no SSO/RBAC today)

---

## Why

Static API keys are fine for service-to-service but fail enterprise SSO requirements. This sprint adds OIDC (OpenID Connect) login to `fendix serve` so users can authenticate via Google, Okta, Azure AD, Keycloak, etc.

**SAML is explicitly NOT in scope** — it's a separate week of work and has SP-initiated vs IdP-initiated flow ambiguity. Defer until a customer asks.

---

## Read first

- [Sprint 07](sprint-07-fendix-serve.md) — the server you're extending. Auth middleware design.
- `golang.org/x/oauth2` docs: https://pkg.go.dev/golang.org/x/oauth2
- The OIDC provider helper at `golang.org/x/oauth2/oidc` (wait — confirm this lives somewhere in x/oauth2 or in `coreos/go-oidc`. If not, use the discovery URL directly.)
- RFC 6749 (OAuth2) + RFC 9068 (JWT profile for access tokens) if you've never done this.

---

## New deps

Add to `go.mod`:
- `golang.org/x/oauth2` (BSD-3)
- If OIDC discovery helper isn't bundled: hand-roll a tiny `oidcDiscover(issuerURL)` that fetches `/.well-known/openid-configuration` and parses the JSON. Avoid adding a separate OIDC dep if x/oauth2 doesn't include it.

## New routes

```
GET  /auth/login        — redirect to OIDC provider
GET  /auth/callback     — handle OIDC callback, set session cookie
POST /auth/logout       — clear session
```

## Config

```yaml
serve:
  api_key: ""            # existing
  auth:
    oidc:
      issuer: ""         # e.g. https://accounts.google.com
      client_id: ""
      client_secret: ""
      redirect_url: ""   # e.g. https://fendix.example.com/auth/callback
      session_ttl_hours: 8
      allowed_emails: [] # if set, only these email claims may log in
      allowed_domains: []# if set, only emails ending in these domains
```

## Auth middleware (replaces Sprint 07's static-key-only middleware)

```go
// authMiddleware accepts EITHER:
//   - Authorization: Bearer <static-api-key>
//   - Valid session cookie (if OIDC configured)
//
// Returns 401 on neither. Caller (per-route) decides if a route is
// public (e.g. /api/v1/health, /auth/*).
//
// Principal is exposed via context for routes that need it (e.g. for
// audit logging in a future sprint).
```

## Session signing

8-hour signed cookie. Signing key derived from `api_key` via HMAC-SHA256. Payload = email claim + expiry.

```go
type sessionPayload struct {
    Email   string
    Expires int64
}

func signSession(p sessionPayload, apiKey string) string {
    // Marshal p to JSON, base64-url encode, append HMAC-SHA256(payload, apiKey)
}

func verifySession(cookieVal, apiKey string) (sessionPayload, error) {
    // Split, verify HMAC, decode, check expiry
}
```

**Known limitation:** if `api_key` rotates, all sessions invalidate immediately. Documented in code + CHANGELOG.

## OIDC flow specifics

- **State token:** random 32-byte URL-safe base64, stored in a short-lived (5 min) HTTP-only cookie. Verified on callback.
- **Nonce:** random 32-byte, included in auth request, verified in ID token claims.
- **PKCE:** skip for now (confidential client; brief doesn't require it). Add to a follow-up if a public-client SPA scenario emerges.
- **Discovery:** fetch `/.well-known/openid-configuration` at server start and cache the result. First request after startup may take ~1s; pre-warm.
- **Token validation:** verify ID token signature using JWKS from discovery doc. Verify `iss`, `aud`, `exp`, `iat`, `nonce` claims.

## Allowed-emails / allowed-domains

If `allowed_emails: ["alice@example.com", "bob@example.com"]` is set, only those emails can log in (denylist all others with a 403 + clear error). If `allowed_domains: ["example.com"]` is set, only `*@example.com` may log in. Both unset = anyone with a valid OIDC token can log in (NOT recommended; logged as a warning at startup).

## Tests — `servecmd/oidc_test.go`

Use `httptest.NewServer` to mock an OIDC provider:

```go
// TestOIDC_LoginRedirectsToProvider
// TestOIDC_CallbackSetsSessionCookie
// TestOIDC_CallbackRejectsBadState
// TestOIDC_CallbackRejectsBadNonce
// TestOIDC_SessionCookieAllowsAPIRequests
// TestOIDC_ExpiredSessionReturns401
// TestOIDC_AllowedEmailsFilter
// TestOIDC_AllowedDomainsFilter
// TestOIDC_LogoutClearsCookie
// TestOIDC_APIKeyAndSessionBothWork (backward compat with Sprint 07)
// TestOIDC_DiscoveryFailureAtStartup (server logs warning, continues with static-key only)
```

## Pre-warm discovery

On server startup with OIDC enabled:
1. Fetch `/.well-known/openid-configuration` once
2. Fetch the JWKS document
3. Cache both for 24h
4. If either fails, log a warning but DON'T fail-start — fall back to static-key-only auth so the server is still usable

## CHANGELOG

```markdown
### Added (v0.12.1)

- **OIDC login for `fendix serve`** — users can authenticate via any
  OIDC provider (Google, Okta, Azure AD, Keycloak, etc.). 8-hour
  signed-cookie sessions; signing key derived from `serve.api_key`.

  Config in `.fendix.yaml`:
  ```
  serve.auth.oidc.{issuer, client_id, client_secret, redirect_url}
  serve.auth.oidc.allowed_emails | allowed_domains  (optional gate)
  ```

  Both static API key and session cookies are accepted in parallel —
  service-to-service callers keep using the API key.

  **Not in scope:** SAML SSO, PKCE for public clients, refresh-token
  flows. If `api_key` rotates, all sessions invalidate immediately.
```

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| OIDC provider quirks (Azure AD's `tid` claim, Okta's group format) | Med | Test against Google as ground truth; provide a config schema flexible enough to opt-in to provider-specific claim names. |
| Discovery doc unavailable at startup → server unusable | Med | Pre-warm + fall back to static-key-only with a warning. Do NOT fail-start. |
| JWKS rotates while we have cached keys | Low | 24h cache; on signature failure, re-fetch JWKS once and retry. |
| Session cookie size > 4 KB → some browsers reject | Low | Payload is just email + expiry → well under 1 KB. |

## Definition of done

Standard DoD plus:
- 11+ tests against mocked OIDC provider
- Manual verification against Google OIDC (record steps in PR description)
- README updated with OIDC config example

## Follow-ups

- **Sprint 08.5:** SAML SSO (if customer-driven)
- **Sprint 08.6:** Refresh token flow (so 8h cap isn't user-visible)
- **Sprint 08.7:** RBAC (group-based route allowlist — needs persistence from Sprint 07.5)

## Status

**Not started.**
