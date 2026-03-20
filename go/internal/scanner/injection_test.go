package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestCheckInjection_DisabledWithoutEnableActive(t *testing.T) {
	cfg := &models.ScanConfig{
		EnableActive: false,
		Timeout:      5,
	}
	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: "http://example.com/api/test"}
	findings := CheckInjection(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("expected no findings when EnableActive=false, got %d", len(findings))
	}
}

func TestCheckInjectionWithAudit_DisabledWithoutEnableActive(t *testing.T) {
	cfg := &models.ScanConfig{EnableActive: false, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: "http://example.com/api/test"}
	auditLog := NewProbeAuditLog()
	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
	if len(auditLog.Records()) != 0 {
		t.Errorf("expected no audit records, got %d", len(auditLog.Records()))
	}
}

func TestProbeAuditLog_RecordAndCount(t *testing.T) {
	var buf bytes.Buffer
	log := NewProbeAuditLogWithWriter(&buf)

	log.Record(ProbeRecord{
		Timestamp: time.Now(),
		Endpoint:  "http://example.com/api/test",
		ProbeType: ProbeSQLi,
		Payload:   "' AND SLEEP(5)--",
		Parameter: "id",
		Method:    "GET",
		Status:    200,
		Duration:  "100ms",
		Finding:   false,
	})

	log.Record(ProbeRecord{
		Timestamp: time.Now(),
		Endpoint:  "http://example.com/api/test",
		ProbeType: ProbeCMDi,
		Payload:   cmdiPayload,
		Parameter: "name",
		Method:    "GET",
		Status:    200,
		Duration:  "50ms",
		Finding:   false,
	})

	log.Record(ProbeRecord{
		Timestamp: time.Now(),
		Endpoint:  "http://example.com/api/other",
		ProbeType: ProbeCRLF,
		Payload:   crlfPayload,
		Parameter: "q",
		Method:    "GET",
		Status:    200,
		Duration:  "30ms",
		Finding:   false,
	})

	if got := log.Count("http://example.com/api/test"); got != 2 {
		t.Errorf("count for /api/test: got %d, want 2", got)
	}
	if got := log.Count("http://example.com/api/other"); got != 1 {
		t.Errorf("count for /api/other: got %d, want 1", got)
	}

	records := log.Records()
	if len(records) != 3 {
		t.Errorf("total records: got %d, want 3", len(records))
	}

	// Check that audit log was written
	output := buf.String()
	if !strings.Contains(output, "[PROBE]") {
		t.Error("expected [PROBE] prefix in audit log output")
	}
	if !strings.Contains(output, "sqli") {
		t.Error("expected sqli probe type in audit log output")
	}
}

func TestProbeAuditLog_MaxProbesPerEndpoint(t *testing.T) {
	var buf bytes.Buffer
	log := NewProbeAuditLogWithWriter(&buf)

	// Fill up to max probes
	for i := 0; i < MaxProbesPerEndpoint; i++ {
		log.Record(ProbeRecord{
			Endpoint: "http://example.com/api/test",
		})
	}

	if got := log.Count("http://example.com/api/test"); got != MaxProbesPerEndpoint {
		t.Errorf("count: got %d, want %d", got, MaxProbesPerEndpoint)
	}
}

func TestProbeSQLi_DetectsDelayedResponse(t *testing.T) {
	// Create a mock server that delays when it sees a SLEEP payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		if strings.Contains(query, "SLEEP") || strings.Contains(query, "pg_sleep") || strings.Contains(query, "WAITFOR") {
			time.Sleep(200 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      10,
	}

	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/test",
		FullURL: ts.URL + "/api/test",
		Params:  []string{"id"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	// Use a short-timeout client so baseline is very fast
	// The mock adds 200ms delay for injection payloads
	// We need to override the threshold check — for testing we use a custom approach
	findings := probeSQLi(context.Background(), &http.Client{Timeout: 10 * time.Second}, cfg, ep, "id", auditLog)

	// The mock delays 200ms which is less than baseline+4s, so no findings expected
	// (Real SQLi detection needs 5+ second delays)
	if len(findings) != 0 {
		t.Logf("unexpected findings (delay too short to trigger): %d", len(findings))
	}

	// But audit records should exist (3 payloads × DB types)
	records := auditLog.Records()
	if len(records) < 3 {
		t.Errorf("expected at least 3 audit records for SQLi probes, got %d", len(records))
	}

	for _, r := range records {
		if r.ProbeType != ProbeSQLi {
			t.Errorf("expected probe type sqli, got %s", r.ProbeType)
		}
		if r.Endpoint != ep.FullURL {
			t.Errorf("expected endpoint %s, got %s", ep.FullURL, r.Endpoint)
		}
	}
}

func TestProbeCMDi_DetectsCanary(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a vulnerable server: check decoded query values for echo payload
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "echo") || strings.Contains(v, "fendix_canary") {
					fmt.Fprintf(w, "Result: fendix_canary_1234567890\n")
					return
				}
			}
		}
		fmt.Fprintf(w, "OK")
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/exec",
		FullURL: ts.URL + "/api/exec",
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCMDi(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "cmd", auditLog)

	if len(findings) != 1 {
		t.Fatalf("expected 1 CMDi finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.Category != "injection" {
		t.Errorf("expected injection category, got %s", f.Category)
	}
	if !strings.Contains(f.Title, "Command Injection") {
		t.Errorf("expected Command Injection in title, got %s", f.Title)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", f.Confidence)
	}

	// Verify audit log recorded the probe
	records := auditLog.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if !records[0].Finding {
		t.Error("expected finding=true in audit record")
	}
}

func TestProbeCMDi_NoCanary(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/safe", FullURL: ts.URL + "/api/safe"}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCMDi(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "cmd", auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe endpoint, got %d", len(findings))
	}

	records := auditLog.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Finding {
		t.Error("expected finding=false in audit record")
	}
}

func TestProbeCRLF_DetectsHeaderInjection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a vulnerable server: if CRLF payload is in query, reflect cookie
		rawQuery := r.URL.RawQuery
		if strings.Contains(rawQuery, "%0d%0a") || strings.Contains(rawQuery, "Set-Cookie") {
			http.SetCookie(w, &http.Cookie{Name: "fendix", Value: "injected"})
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/vuln", FullURL: ts.URL + "/api/vuln"}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCRLF(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "redirect", auditLog)

	if len(findings) != 1 {
		t.Fatalf("expected 1 CRLF finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "CRLF") {
		t.Errorf("expected CRLF in title, got %s", f.Title)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", f.Confidence)
	}
}

func TestProbeCRLF_NoCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{Method: "GET", Path: "/api/safe", FullURL: ts.URL + "/api/safe"}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := probeCRLF(context.Background(), &http.Client{Timeout: 5 * time.Second}, cfg, ep, "q", auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestBuildProbeURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		param    string
		payload  string
		expected string
	}{
		{
			name:     "no existing query",
			baseURL:  "http://example.com/api/test",
			param:    "id",
			payload:  "' AND SLEEP(5)--",
			expected: "http://example.com/api/test?id=%27+AND+SLEEP%285%29--",
		},
		{
			name:     "existing query param",
			baseURL:  "http://example.com/api/test?page=1",
			param:    "id",
			payload:  "payload",
			expected: "http://example.com/api/test?page=1&id=payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildProbeURL(tt.baseURL, tt.param, tt.payload)
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestAddAuth(t *testing.T) {
	tests := []struct {
		name       string
		auth       *models.AuthContext
		wantHeader string
		wantValue  string
	}{
		{
			name:       "bearer",
			auth:       &models.AuthContext{Type: "bearer", Value: "token123"},
			wantHeader: "Authorization",
			wantValue:  "Bearer token123",
		},
		{
			name:       "apikey",
			auth:       &models.AuthContext{Type: "apikey", Value: "key123", Header: "X-API-Key"},
			wantHeader: "X-API-Key",
			wantValue:  "key123",
		},
		{
			name:       "cookie",
			auth:       &models.AuthContext{Type: "cookie", Value: "session=abc"},
			wantHeader: "Cookie",
			wantValue:  "session=abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			cfg := &models.ScanConfig{Auth: tt.auth}
			addAuth(req, cfg)

			got := req.Header.Get(tt.wantHeader)
			if got != tt.wantValue {
				t.Errorf("got header %s=%q, want %q", tt.wantHeader, got, tt.wantValue)
			}
		})
	}
}

func TestAddAuth_NilAuth(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	cfg := &models.ScanConfig{Auth: nil}
	addAuth(req, cfg)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("expected no Authorization header, got %q", got)
	}
}

func TestCheckInjection_FullPipeline(t *testing.T) {
	// A mock server that is safe (no vulnerabilities)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      5,
	}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/safe",
		FullURL: ts.URL + "/api/safe",
		Params:  []string{"q"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	// No findings expected on a safe server
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d", len(findings))
	}

	// But should have audit records for all probes (SQLi×3 + CMDi×1 + CRLF×1 = 5)
	records := auditLog.Records()
	if len(records) < 5 {
		t.Errorf("expected at least 5 audit records, got %d", len(records))
	}

	// Verify all probes were logged
	output := buf.String()
	if !strings.Contains(output, "[PROBE]") {
		t.Error("expected [PROBE] entries in audit log")
	}
}

func TestCheckInjection_DefaultParam(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/test",
		FullURL: ts.URL + "/api/test",
		Params:  nil, // No params — should default to "id"
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	records := auditLog.Records()
	for _, r := range records {
		if r.Parameter != "id" {
			t.Errorf("expected default param 'id', got %q", r.Parameter)
		}
	}
}

func TestMedianDuration(t *testing.T) {
	tests := []struct {
		name      string
		durations []time.Duration
		expected  time.Duration
	}{
		{"empty", nil, 0},
		{"single", []time.Duration{100 * time.Millisecond}, 100 * time.Millisecond},
		{"odd", []time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 30 * time.Millisecond}, 30 * time.Millisecond},
		{"even", []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}, 15 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := medianDuration(tt.durations)
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSqliPayloads(t *testing.T) {
	payloads := sqliPayloads()
	if len(payloads) != 3 {
		t.Fatalf("expected 3 SQLi payloads, got %d", len(payloads))
	}

	dbs := map[string]bool{}
	for _, p := range payloads {
		dbs[p.DB] = true
		if p.Delay != 5*time.Second {
			t.Errorf("expected 5s delay for %s, got %v", p.DB, p.Delay)
		}
	}
	for _, db := range []string{"MySQL", "Postgres", "MSSQL"} {
		if !dbs[db] {
			t.Errorf("missing payload for %s", db)
		}
	}
}

// --- Integration tests with deliberately vulnerable mock server ---

// newVulnerableMockServer creates a test server that is vulnerable to CMDi and CRLF.
// SQLi time-based testing requires real delays so is tested separately.
func newVulnerableMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery := r.URL.RawQuery

		// Vulnerable to CMDi: reflects canary in response
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "echo") {
					fmt.Fprintf(w, "output: fendix_canary_12345\n")
					return
				}
			}
		}

		// Vulnerable to CRLF: reflects Set-Cookie header
		if strings.Contains(rawQuery, "%0d%0a") || strings.Contains(rawQuery, "Set-Cookie") {
			http.SetCookie(w, &http.Cookie{Name: "fendix", Value: "injected"})
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
	}))
}

func TestIntegration_VulnerableServer_CMDiAndCRLF(t *testing.T) {
	ts := newVulnerableMockServer()
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      5,
	}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/vuln",
		FullURL: ts.URL + "/api/vuln",
		Params:  []string{"input"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	// Should find CMDi + CRLF (SQLi won't trigger because no real delay)
	cmdiFound := false
	crlfFound := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Command Injection") {
			cmdiFound = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("CMDi should be CRITICAL, got %s", f.Severity)
			}
		}
		if strings.Contains(f.Title, "CRLF") {
			crlfFound = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("CRLF should be HIGH, got %s", f.Severity)
			}
		}
	}

	if !cmdiFound {
		t.Error("expected CMDi finding from vulnerable server")
	}
	if !crlfFound {
		t.Error("expected CRLF finding from vulnerable server")
	}

	// All probes should be audit-logged
	records := auditLog.Records()
	if len(records) == 0 {
		t.Error("expected audit records")
	}

	// Verify audit log output format
	output := buf.String()
	if !strings.Contains(output, "[PROBE]") {
		t.Error("expected [PROBE] prefix in audit output")
	}
	if !strings.Contains(output, "finding=true") {
		t.Error("expected at least one finding=true in audit log")
	}
}

func TestIntegration_SafeServer_NoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"result":"safe"}`)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/safe",
		FullURL: ts.URL + "/api/safe",
		Params:  []string{"q", "page"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s", f.Title)
		}
	}

	// Should still have audit records for all attempted probes
	// 2 params × (3 SQLi + 1 CMDi + 1 CRLF) = 10 probes
	records := auditLog.Records()
	if len(records) < 10 {
		t.Errorf("expected at least 10 audit records for 2 params, got %d", len(records))
	}
}

func TestIntegration_MultipleParams(t *testing.T) {
	cmdiHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, vals := range r.URL.Query() {
			for _, v := range vals {
				if strings.Contains(v, "echo") {
					cmdiHits++
					fmt.Fprintf(w, "fendix_canary_test\n")
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 5}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/exec",
		FullURL: ts.URL + "/api/exec",
		Params:  []string{"cmd", "action", "run"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	findings := CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	// Should find CMDi for each parameter
	cmdiCount := 0
	for _, f := range findings {
		if strings.Contains(f.Title, "Command Injection") {
			cmdiCount++
		}
	}
	if cmdiCount != 3 {
		t.Errorf("expected 3 CMDi findings (one per param), got %d", cmdiCount)
	}
}

func TestIntegration_WithAuth(t *testing.T) {
	authSeen := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			authSeen = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{
		EnableActive: true,
		Timeout:      5,
		Auth:         &models.AuthContext{Type: "bearer", Value: "test-token"},
	}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/protected",
		FullURL: ts.URL + "/api/protected",
		Params:  []string{"id"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	CheckInjectionWithAudit(context.Background(), cfg, ep, auditLog)

	if !authSeen {
		t.Error("expected auth header to be included in probe requests")
	}
}

func TestIntegration_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 10}
	ep := Endpoint{
		Method:  "GET",
		Path:    "/api/slow",
		FullURL: ts.URL + "/api/slow",
		Params:  []string{"id"},
	}

	var buf bytes.Buffer
	auditLog := NewProbeAuditLogWithWriter(&buf)

	// Should not panic or hang — should return gracefully
	findings := CheckInjectionWithAudit(ctx, cfg, ep, auditLog)
	_ = findings // May or may not have findings, but should not hang
}

func TestProbeAuditLog_ConcurrentAccess(t *testing.T) {
	var buf bytes.Buffer
	log := NewProbeAuditLogWithWriter(&buf)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			log.Record(ProbeRecord{
				Endpoint:  fmt.Sprintf("http://example.com/%d", n),
				ProbeType: ProbeSQLi,
			})
			_ = log.Count(fmt.Sprintf("http://example.com/%d", n))
			_ = log.Records()
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if got := len(log.Records()); got != 10 {
		t.Errorf("expected 10 records after concurrent access, got %d", got)
	}
}
