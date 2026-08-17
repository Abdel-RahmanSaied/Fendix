package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	ev "github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// cookieFlagsCheck is a passive Check that inspects Set-Cookie headers on a
// single GET and flags missing security attributes (HttpOnly, Secure,
// SameSite) on session-shaped cookies. It is deliberately conservative:
// analytics/preference cookies are ignored outright, deletion cookies are
// skipped, and Secure is only required over https. CWE-1004 / CWE-614 /
// CWE-1275.
type cookieFlagsCheck struct{}

func (cookieFlagsCheck) Name() string                        { return "cookie-flags" }
func (cookieFlagsCheck) Category() string                    { return "cookie" }
func (cookieFlagsCheck) Tier() Tier                          { return TierPassive }
func (cookieFlagsCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// cookieIgnoreList holds lowercase substrings of cookie names that are
// analytics / preference / consent cookies — never session credentials. A
// match here WINS over any session-shaped heuristic (no flag emitted), since a
// long opaque _ga value would otherwise trip the length heuristic.
var cookieIgnoreList = []string{
	"_ga", "_gid", "_gat", "_gcl_au", "_fbp", "_fbc", "ajs_", "mp_",
	"optimizely", "intercom", "__utm", "amplitude", "mixpanel", "_pk_",
	"_clck", "_clsk", "hubspotutk", "locale", "lang", "theme", "currency",
	"timezone", "cookie_consent", "cookieconsent", "consent",
}

// cookieSessionList holds lowercase substrings that strongly indicate a
// session / auth credential cookie. A name match here flags the cookie even if
// its value is short.
var cookieSessionList = []string{
	"session", "sess", "sid", "auth", "token", "jwt", "csrf", "xsrf",
	"remember", "login", "jsessionid", "phpsessid", "asp.net_sessionid",
	"connect.sid", "laravel_session",
}

func (cookieFlagsCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	client := cc.Client

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("cookie-flags", "cookie-flags check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}
	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("cookie-flags", "cookie-flags check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	// Skip only where there is no signal: a missing resource (404/410) or a
	// server fault (5xx) sets cookies from framework/error-page paths, not from
	// a feature surface (FP corpus pattern P2).
	//
	// A 4xx AUTH response is different, and blanket-skipping it was a false
	// negative: a login endpoint answering 401 while issuing a session cookie
	// without HttpOnly is a real, exploitable finding — arguably the single
	// most security-relevant Set-Cookie a scan can observe. Per Rule 3 the
	// evidence is preserved and the confidence scorer de-escalates it via the
	// shared B4 context, exactly like the header and CORS checks.
	if resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusGone ||
		resp.StatusCode >= 500 {
		return nil
	}

	isHTTPS := strings.HasPrefix(strings.ToLower(endpoint.FullURL), "https://")
	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	respContext := responseContextFor(resp.StatusCode, endpoint.Path)

	var findings []ev.Evidence
	// Dedup per (cookie-name, flag) so repeated Set-Cookie for the same name
	// (e.g. set twice in one response) emits at most one finding per flag.
	seen := make(map[string]bool)
	emit := func(name, flag string, f ev.Evidence) {
		key := strings.ToLower(name) + "|" + flag
		if seen[key] {
			return
		}
		seen[key] = true
		// B4: stamp the de-escalation context ("4xx" on an auth-gated response,
		// "static-asset" on a CDN path). Empty on a normal 2xx/3xx API route,
		// which leaves the finding at full confidence.
		f.ResponseContext = respContext
		findings = append(findings, f)
	}

	for _, c := range resp.Cookies() {
		if isDeletionCookie(c) {
			continue
		}
		if !isSessionShapedCookie(c) {
			continue
		}

		// Missing HttpOnly — exposes the cookie to document.cookie / XSS theft.
		if !c.HttpOnly {
			emit(c.Name, "httponly", ev.Evidence{
				Title:      "Session cookie missing HttpOnly flag",
				Severity:   models.SeverityMedium,
				Source:     models.SourceBlackbox,
				Category:   "cookie",
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("Set-Cookie %q has no HttpOnly attribute", c.Name),
				Fix:        fmt.Sprintf("Set the HttpOnly attribute on the %q cookie so client-side script cannot read it.", c.Name),
				References: []string{"CWE-1004"},
				Confidence: models.ConfidenceHigh,
			})
		}

		// Missing Secure — only meaningful over https (Secure is a no-op /
		// not assertable on plain http responses).
		if isHTTPS && !c.Secure {
			emit(c.Name, "secure", ev.Evidence{
				Title:      "Session cookie missing Secure flag",
				Severity:   models.SeverityMedium,
				Source:     models.SourceBlackbox,
				Category:   "cookie",
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("Set-Cookie %q has no Secure attribute over HTTPS", c.Name),
				Fix:        fmt.Sprintf("Set the Secure attribute on the %q cookie so it is only sent over TLS.", c.Name),
				References: []string{"CWE-614"},
				Confidence: models.ConfidenceHigh,
			})
		}

		// SameSite missing/None. net/http parses an ABSENT SameSite attribute
		// to the zero value http.SameSite(0) (no exported const), and an
		// explicit/unrecognized "SameSite" with no value to SameSiteDefaultMode
		// (which is 1 in this Go version, not 0). Treat both — plus None — as
		// weak. Strict/Lax → no finding.
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode || c.SameSite == http.SameSiteNoneMode {
			severity := models.SeverityLow
			detail := "no SameSite attribute (or an unrecognized value)"
			if c.SameSite == http.SameSiteNoneMode {
				detail = "SameSite=None"
				// SameSite=None without Secure is rejected by browsers and is
				// CSRF-permissive — escalate.
				if !c.Secure {
					severity = models.SeverityMedium
				}
			}
			emit(c.Name, "samesite", ev.Evidence{
				Title:      "Session cookie missing or weak SameSite attribute",
				Severity:   severity,
				Source:     models.SourceBlackbox,
				Category:   "cookie",
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("Set-Cookie %q has %s", c.Name, detail),
				Fix:        fmt.Sprintf("Set SameSite=Lax (or Strict) on the %q cookie to mitigate CSRF. If SameSite=None is required, also set Secure.", c.Name),
				References: []string{"CWE-1275"},
				Confidence: models.ConfidenceMedium,
			})
		}
	}

	return findings
}

// isDeletionCookie reports whether a Set-Cookie is clearing the cookie rather
// than setting a live value. Max-Age<0 is an explicit immediate-expire; an
// empty value with an Expires in the past is the legacy clear idiom.
func isDeletionCookie(c *http.Cookie) bool {
	if c.MaxAge < 0 {
		return true
	}
	if c.Value == "" && !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
		return true
	}
	return false
}

// isSessionShapedCookie classifies whether a cookie looks like a session/auth
// credential worth hardening. The ignore-list (analytics/preferences) wins
// over every heuristic.
func isSessionShapedCookie(c *http.Cookie) bool {
	name := strings.ToLower(c.Name)

	for _, ig := range cookieIgnoreList {
		if strings.Contains(name, ig) {
			return false
		}
	}

	for _, s := range cookieSessionList {
		if strings.Contains(name, s) {
			return true
		}
	}

	// Long opaque value that isn't a small integer → likely a token/session id.
	if len(c.Value) >= 16 && !isSmallInteger(c.Value) {
		return true
	}

	return false
}

// isSmallInteger reports whether v is a pure decimal integer (e.g. a unix
// timestamp or counter), which is not session-shaped on its own.
func isSmallInteger(v string) bool {
	if v == "" {
		return false
	}
	_, err := strconv.ParseInt(v, 10, 64)
	return err == nil
}
