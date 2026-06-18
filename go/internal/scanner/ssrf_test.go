package scanner

// Integration tests for the active in-band SSRF check (CWE-918). They drive
// SSRFCheck.Run against loopback httptest servers, so every cfg sets
// AllowPrivate: true. This is the SSRF TEST PARADOX: the netguard guard's
// allowPrivate=false would BLOCK the dial to the 127.0.0.1 test server (and to
// the unroutable canary literals), so the probe could never reach the handler.
// With AllowPrivate:true the egress guard is OFF — that is fine here because we
// are testing the DETECTOR's response-classification logic, NOT the egress
// guard (which has its own dedicated tests in ssrf_regression_test.go).
//
// The two negative tests are LOAD-BEARING and MUST stay green:
//   - TestSSRF_ReflectionNotSSRF: verbatim reflection of the param value is NOT
//     SSRF (the dominant FP — reflection != server-side fetch).
//   - TestSSRF_GenericErrorNoCanaryNoFinding: a generic "connection refused"
//     page that does NOT echo our canary host is NOT SSRF (FP guard a).
//   - TestSSRF_DocumentedBlindLimitFN: encodes the honest known gap — a server
//     that fetches the canary OUT-OF-BAND only (nothing observable in-band)
//     yields NO finding (fendix has no OAST callback server).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// activeSSRFCfg returns the standard active-scan config for these tests.
// AllowPrivate:true is mandatory — see the SSRF test paradox note above.
func activeSSRFCfg() *models.ScanConfig {
	return &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
}

// ssrfEP builds an Endpoint declaring a single URL-shaped query param "url", so
// targetsForEndpoint yields exactly one (url, query) target that the urlParamRe
// filter accepts.
func ssrfEP(server *httptest.Server) Endpoint {
	return Endpoint{
		Method:  "GET",
		Path:    "/fetch",
		FullURL: server.URL + "/fetch",
		Params:  []string{"url"},
	}
}

// TestSSRF_ErrorLeak: handler, when the injected ?url= contains our canary host
// (under the .invalid sentinel), returns a body that echoes the canary host AND
// a fetch-stack error signature ("connection refused"). Both the canary host
// and the error signature present → HIGH/High SSRF finding (signal a).
func TestSSRF_ErrorLeak(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Simulate a server that tried to fetch the supplied URL and dumped the
		// upstream error (including the URL it attempted) into the response.
		if strings.Contains(target, "fendix.invalid") {
			_, _ = w.Write([]byte("Failed fetching " + target + ": dial tcp: connection refused"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 SSRF finding (error-leak), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity for error-leak, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for error-leak, got %s", f.Confidence)
	}
	if f.Category != "ssrf" {
		t.Errorf("expected category=ssrf, got %q", f.Category)
	}
	if !hasRef(f, "CWE-918") {
		t.Errorf("expected CWE-918 reference, got %v", f.References)
	}
	if f.Source != models.SourceBlackbox {
		t.Errorf("expected blackbox source, got %s", f.Source)
	}
}

// TestSSRF_ReflectedFetch: handler, when it sees the SSRF param, "fetches" the
// URL and inlines the URL's unique marker into the body. The marker is absent
// from the benign baseline response → server-side fetch+inline → HIGH (signal
// b, content-fetch).
func TestSSRF_ReflectedFetch(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// The canary URL is http://<canary>.oob.fendix.invalid/?marker=<marker>.
		// A server that actually FETCHES it would inline the fetched content,
		// which here we model as echoing the marker query value back. Crucially
		// we DO NOT reflect the param value verbatim — we extract the marker the
		// way a fetched upstream body would surface it.
		if strings.Contains(target, "fendix.invalid") {
			if u, err := http.NewRequest("GET", target, nil); err == nil {
				marker := u.URL.Query().Get("marker")
				if marker != "" {
					_, _ = w.Write([]byte("<html><body>fetched upstream content: " + marker + "</body></html>"))
					return
				}
			}
		}
		// Benign baseline (no SSRF param / control value): marker never appears.
		_, _ = w.Write([]byte("<html><body>nothing fetched</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 SSRF finding (reflected-fetch), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity for reflected-fetch, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for reflected-fetch, got %s", f.Confidence)
	}
	if !hasRef(f, "CWE-918") {
		t.Errorf("expected CWE-918 reference, got %v", f.References)
	}
}

// TestSSRF_RedirectEcho: handler 302s with a Location header whose host is our
// canary host → MEDIUM finding via cc.NoFollow (signal b, redirect-echo).
func TestSSRF_RedirectEcho(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		// A server-side fetcher that 30x's onward to the supplied URL leaks the
		// canary host in the raw Location header.
		if strings.Contains(target, "fendix.invalid") {
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 SSRF finding (redirect-echo), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity for redirect-echo, got %s", f.Severity)
	}
	if !hasRef(f, "CWE-918") {
		t.Errorf("expected CWE-918 reference, got %v", f.References)
	}
}

// TestSSRF_ReflectionNotSSRF (LOAD-BEARING): handler reflects the param value
// VERBATIM into an HTML body — no fetch-stack error signature, no out-of-baseline
// marker, no redirect. Mere reflection of the input is NOT SSRF → 0 findings.
// This is the dominant false-positive class and the single most important guard.
func TestSSRF_ReflectionNotSSRF(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Echo the raw input back. The canary host WILL appear in the body, but
		// only because we reflected the input — there is no error signature and
		// no fetched marker. Reflection must NOT trip the error-leak guard (which
		// requires an error signature) nor the reflected-fetch guard (the marker
		// reflected here is part of the verbatim input, not a fetched body — but
		// since the whole input is echoed, the marker WOULD appear; the check
		// must therefore use a fetch-distinct marker form, see implementation).
		_, _ = w.Write([]byte("<html><body>You requested: " + target + "</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: verbatim reflection of the param value must produce 0 SSRF findings (reflection != SSRF), got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_GenericErrorNoCanaryNoFinding (LOAD-BEARING, FP guard a): the body
// contains a fetch-stack error signature ("connection refused") but does NOT
// echo our canary host. This is a generic page error unrelated to our probe →
// 0 findings. The error-leak signal REQUIRES the canary host in the body to
// prove the server fetched OUR url.
func TestSSRF_GenericErrorNoCanaryNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Generic backend hiccup, no relation to the injected URL — never echoes
		// the canary host.
		_, _ = w.Write([]byte("<html><body>Backend error: connection refused while talking to the database</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: a generic 'connection refused' page without our canary host must produce 0 findings (FP guard a), got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_NonURLParamSkipped: an endpoint whose only param is non-URL-shaped
// ("comment") → the urlParamRe filter skips it, so no SSRF probes are sent and
// no findings are produced even against a server that WOULD leak.
func TestSSRF_NonURLParamSkipped(t *testing.T) {
	ResetGlobalAuditLog()
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		// Would leak if probed — proves the skip is the filter, not the handler.
		c := r.URL.Query().Get("comment")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fetching " + c + ": connection refused"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	ep := Endpoint{
		Method:  "GET",
		Path:    "/comment",
		FullURL: server.URL + "/comment",
		Params:  []string{"comment"},
	}
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for a non-URL-shaped param (urlParamRe filter), got %d: %+v", len(findings), findings)
	}
	if hit {
		t.Errorf("expected NO request to be sent for a non-URL-shaped param, but the handler was hit")
	}
}

// TestSSRF_NotActiveNoFinding: EnableActive=false → 0 findings, even against a
// blatantly leaking handler.
func TestSSRF_NotActiveNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fetching " + target + ": connection refused"))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: false}
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when EnableActive=false, got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_DocumentedBlindLimitFN (HONEST KNOWN GAP): the server actually
// fetches the canary OUT-OF-BAND (would hit our sentinel host server-side) but
// returns NOTHING observable in-band — no error signature, no inlined marker,
// no redirect, no timing differential. Because fendix has no OAST callback
// server, this true-blind SSRF is UNDETECTABLE. This test ASSERTS the gap so it
// is honest and documented, not hidden.
func TestSSRF_DocumentedBlindLimitFN(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pretend to fetch the URL server-side, swallow the result entirely, and
		// return a constant benign body regardless of input.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Request accepted.</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("DOCUMENTED OOB LIMIT: a true-blind out-of-band SSRF (nothing observable in-band) must produce 0 findings without an OAST server, got %d: %+v", len(findings), findings)
	}
}
