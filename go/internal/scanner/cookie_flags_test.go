package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ev "github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// cookieFindingTitles collects finding titles for assertions.
func cookieFindingTitles(fs []ev.Evidence) map[string]ev.Evidence {
	m := make(map[string]ev.Evidence, len(fs))
	for _, f := range fs {
		m[f.Title] = f
	}
	return m
}

// hasRef reports whether a finding's References slice contains want.
func hasRef(f ev.Evidence, want string) bool {
	for _, r := range f.References {
		if r == want {
			return true
		}
	}
	return false
}

// runCookieCheck builds a CheckContext for a test server and runs the check.
// For TLS servers the test client (srv.Client) is wired in so the cert is
// trusted; that client is not SSRF-guarded, which is fine for unit testing the
// cookie classification logic.
func runCookieCheck(t *testing.T, srv *httptest.Server, tls bool) []ev.Evidence {
	t.Helper()
	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	cc := NewCheckContext(cfg)
	if tls {
		cc.Client = srv.Client()
	}
	ep := Endpoint{Method: "GET", Path: "/", FullURL: srv.URL + "/"}
	return cookieFlagsCheck{}.Run(context.Background(), cc, ep)
}

func TestCookieFlags_SessionCookieNoFlagsHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (HttpOnly, Secure, SameSite), got %d: %v", len(findings), findings)
	}

	var httpOnly, secure, sameSite *ev.Evidence
	for i := range findings {
		f := findings[i]
		if f.Category != "cookie" {
			t.Errorf("expected category cookie, got %q for %q", f.Category, f.Title)
		}
		if f.Source != models.SourceBlackbox {
			t.Errorf("expected source blackbox, got %q for %q", f.Source, f.Title)
		}
		switch {
		case hasRef(f, "CWE-1004"):
			httpOnly = &findings[i]
		case hasRef(f, "CWE-614"):
			secure = &findings[i]
		case hasRef(f, "CWE-1275"):
			sameSite = &findings[i]
		}
	}

	if httpOnly == nil {
		t.Fatal("missing HttpOnly finding (CWE-1004)")
	}
	if httpOnly.Severity != models.SeverityMedium {
		t.Errorf("HttpOnly severity: got %s want MEDIUM", httpOnly.Severity)
	}
	if httpOnly.Confidence != models.ConfidenceHigh {
		t.Errorf("HttpOnly confidence: got %s want HIGH", httpOnly.Confidence)
	}

	if secure == nil {
		t.Fatal("missing Secure finding (CWE-614)")
	}
	if secure.Severity != models.SeverityMedium {
		t.Errorf("Secure severity: got %s want MEDIUM", secure.Severity)
	}
	if secure.Confidence != models.ConfidenceHigh {
		t.Errorf("Secure confidence: got %s want HIGH", secure.Confidence)
	}

	if sameSite == nil {
		t.Fatal("missing SameSite finding (CWE-1275)")
	}
	if sameSite.Severity != models.SeverityLow {
		t.Errorf("SameSite severity: got %s want LOW", sameSite.Severity)
	}
	if sameSite.Confidence != models.ConfidenceMedium {
		t.Errorf("SameSite confidence: got %s want MEDIUM", sameSite.Confidence)
	}

	// Endpoint label should be "METHOD PATH".
	if httpOnly.Endpoint != "GET /" {
		t.Errorf("endpoint label: got %q want %q", httpOnly.Endpoint, "GET /")
	}
}

func TestCookieFlags_PlainHTTPSuppressesSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, false)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (Secure suppressed on http), got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if hasRef(f, "CWE-614") {
			t.Errorf("Secure finding should be suppressed on plain http, got %q", f.Title)
		}
	}
}

func TestCookieFlags_HardenedCookie(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; HttpOnly; Secure; SameSite=Strict")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for fully hardened cookie, got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_AnalyticsIgnored(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Long value, no flags, but on the ignore-list — must not flag.
		w.Header().Set("Set-Cookie", "_ga=GA1.2.long.value.123456789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for analytics cookie (ignore-list wins), got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_DeletionCookieIgnored(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=; Max-Age=-1")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for deletion cookie, got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_SameSiteNoneWithoutSecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SameSite=None without Secure over https → SameSite finding escalates
		// to MEDIUM. (HttpOnly + Secure findings also fire here.)
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; SameSite=None")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	var sameSite *ev.Evidence
	for i := range findings {
		if hasRef(findings[i], "CWE-1275") {
			sameSite = &findings[i]
		}
	}
	if sameSite == nil {
		t.Fatalf("missing SameSite finding; got %v", findings)
	}
	if sameSite.Severity != models.SeverityMedium {
		t.Errorf("SameSite=None+!Secure severity: got %s want MEDIUM (escalated)", sameSite.Severity)
	}
}

func TestCookieFlags_4xxSkipped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(404)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 404 response, got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_DuplicateFlagOneFinding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two Set-Cookie for the same name, both hardened on Secure+SameSite
		// but missing HttpOnly. Exactly ONE HttpOnly finding for that name.
		w.Header().Add("Set-Cookie", "sessionid=abc123def456ghi789; Secure; SameSite=Strict")
		w.Header().Add("Set-Cookie", "sessionid=zzz987yyy654xxx321; Secure; SameSite=Strict")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	httpOnlyCount := 0
	for _, f := range findings {
		if hasRef(f, "CWE-1004") {
			httpOnlyCount++
		}
	}
	if httpOnlyCount != 1 {
		t.Fatalf("expected exactly 1 HttpOnly finding for duplicate cookie name, got %d: %v", httpOnlyCount, findings)
	}
}

// sanity: ensure evidence mentions the cookie name + flag (helps triage).
func TestCookieFlags_EvidenceNamesCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, false)
	for _, f := range findings {
		if !strings.Contains(f.Evidence, "sessionid") {
			t.Errorf("evidence should name the cookie: %q", f.Evidence)
		}
	}
	titles := cookieFindingTitles(findings)
	if len(titles) == 0 {
		t.Fatal("expected at least one finding")
	}
}
