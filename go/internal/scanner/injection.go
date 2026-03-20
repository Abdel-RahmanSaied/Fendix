package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// MaxProbesPerEndpoint limits how many active probes are sent to a single endpoint.
const MaxProbesPerEndpoint = 20

// ActiveDisclaimer is printed to stderr when --enable-active is used.
const ActiveDisclaimer = `
WARNING: Active scanning enabled (--enable-active).
Active probes send potentially dangerous payloads to the target.
Only use this against systems you own or have explicit authorization to test.
You are solely responsible for ensuring you have permission.
`

// ProbeType identifies the kind of active probe.
type ProbeType string

const (
	ProbeSQLi ProbeType = "sqli"
	ProbeCMDi ProbeType = "cmdi"
	ProbeCRLF ProbeType = "crlf"
)

// ProbeRecord captures a single probe sent during active scanning.
type ProbeRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Endpoint  string    `json:"endpoint"`
	ProbeType ProbeType `json:"probe_type"`
	Payload   string    `json:"payload"`
	Parameter string    `json:"parameter"`
	Method    string    `json:"method"`
	Status    int       `json:"status_code"`
	Duration  string    `json:"duration"`
	Finding   bool      `json:"finding_generated"`
}

// ProbeAuditLog records every active probe for accountability and debugging.
type ProbeAuditLog struct {
	mu      sync.Mutex
	records []ProbeRecord
	writer  io.Writer
}

// NewProbeAuditLog creates a new audit log that writes to stderr.
func NewProbeAuditLog() *ProbeAuditLog {
	return &ProbeAuditLog{
		writer: os.Stderr,
	}
}

// NewProbeAuditLogWithWriter creates an audit log with a custom writer (for testing).
func NewProbeAuditLogWithWriter(w io.Writer) *ProbeAuditLog {
	return &ProbeAuditLog{
		writer: w,
	}
}

// Record adds a probe record to the audit log and writes it to the log writer.
func (a *ProbeAuditLog) Record(r ProbeRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, r)
	fmt.Fprintf(a.writer, "[PROBE] %s %s type=%s param=%q payload=%q status=%d duration=%s finding=%v\n",
		r.Timestamp.Format(time.RFC3339), r.Endpoint, r.ProbeType, r.Parameter, r.Payload, r.Status, r.Duration, r.Finding)
}

// Records returns a copy of all recorded probe entries.
func (a *ProbeAuditLog) Records() []ProbeRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ProbeRecord, len(a.records))
	copy(out, a.records)
	return out
}

// Count returns the number of probes recorded for a given endpoint.
func (a *ProbeAuditLog) Count(endpoint string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.records {
		if r.Endpoint == endpoint {
			n++
		}
	}
	return n
}

// PrintDisclaimer writes the active scanning disclaimer to stderr.
func PrintDisclaimer() {
	fmt.Fprint(os.Stderr, ActiveDisclaimer)
}

// measureBaseline sends 3 requests and returns the median response time.
func measureBaseline(ctx context.Context, client *http.Client, method, url string) (time.Duration, error) {
	var durations []time.Duration
	for i := 0; i < 3; i++ {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return 0, fmt.Errorf("creating baseline request: %w", err)
		}
		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			return 0, fmt.Errorf("baseline request %d failed: %w", i+1, err)
		}
		resp.Body.Close()
		durations = append(durations, elapsed)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	return durations[1], nil // median
}

// sqliPayloads returns time-based blind SQL injection payloads for MySQL, Postgres, and MSSQL.
func sqliPayloads() []struct {
	DB      string
	Payload string
	Delay   time.Duration
} {
	return []struct {
		DB      string
		Payload string
		Delay   time.Duration
	}{
		{DB: "MySQL", Payload: "' AND SLEEP(5)--", Delay: 5 * time.Second},
		{DB: "Postgres", Payload: "' AND pg_sleep(5)--", Delay: 5 * time.Second},
		{DB: "MSSQL", Payload: "'; WAITFOR DELAY '00:00:05'--", Delay: 5 * time.Second},
	}
}

// cmdiPayload is the safe echo-based command injection canary.
const cmdiCanaryPrefix = "fendix_canary_"
const cmdiPayload = "; echo fendix_canary_PROBE"

// crlfPayload injects a Set-Cookie header via CRLF (URL-encoded spaces for valid HTTP).
const crlfPayload = "%0d%0aSet-Cookie:%20fendix=injected"

// CheckInjection runs active injection probes on an endpoint.
// This function MUST only be called when cfg.EnableActive is true.
// It runs SQLi, CMDi, and CRLF probes on each parameter.
func CheckInjection(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	if !cfg.EnableActive {
		return nil
	}

	auditLog := NewProbeAuditLog()
	return CheckInjectionWithAudit(ctx, cfg, endpoint, auditLog)
}

// CheckInjectionWithAudit runs active injection probes with a provided audit log.
func CheckInjectionWithAudit(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint, auditLog *ProbeAuditLog) []models.Finding {
	if !cfg.EnableActive {
		return nil
	}

	client := &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second}
	var findings []models.Finding

	// Determine parameters to test
	params := endpoint.Params
	if len(params) == 0 {
		// If no known params, test with a generic "id" param
		params = []string{"id"}
	}

	for _, param := range params {
		if auditLog.Count(endpoint.FullURL) >= MaxProbesPerEndpoint {
			slog.Warn("max probes reached for endpoint", "endpoint", endpoint.FullURL, "max", MaxProbesPerEndpoint)
			break
		}

		// SQLi probes
		sqlFindings := probeSQLi(ctx, client, cfg, endpoint, param, auditLog)
		findings = append(findings, sqlFindings...)

		// CMDi probes
		cmdFindings := probeCMDi(ctx, client, cfg, endpoint, param, auditLog)
		findings = append(findings, cmdFindings...)

		// CRLF probes
		crlfFindings := probeCRLF(ctx, client, cfg, endpoint, param, auditLog)
		findings = append(findings, crlfFindings...)
	}

	return findings
}

// probeSQLi sends time-based blind SQLi payloads and checks for delayed responses.
func probeSQLi(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, auditLog *ProbeAuditLog) []models.Finding {
	var findings []models.Finding

	// Measure baseline response time
	baseline, err := measureBaseline(ctx, client, endpoint.Method, endpoint.FullURL)
	if err != nil {
		slog.Warn("failed to measure baseline for sqli", "endpoint", endpoint.FullURL, "error", err)
		return nil
	}

	for _, p := range sqliPayloads() {
		if auditLog.Count(endpoint.FullURL) >= MaxProbesPerEndpoint {
			break
		}

		// Build probe URL with payload in query parameter
		probeURL := buildProbeURL(endpoint.FullURL, param, p.Payload)

		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, endpoint.Method, probeURL, nil)
		if err != nil {
			slog.Warn("failed to create sqli probe request", "error", err)
			continue
		}

		// Add auth if configured
		addAuth(req, cfg)

		resp, err := client.Do(req)
		elapsed := time.Since(start)

		record := ProbeRecord{
			Timestamp: start,
			Endpoint:  endpoint.FullURL,
			ProbeType: ProbeSQLi,
			Payload:   p.Payload,
			Parameter: param,
			Method:    endpoint.Method,
			Duration:  elapsed.Round(time.Millisecond).String(),
		}

		if err != nil {
			slog.Warn("sqli probe request failed", "endpoint", endpoint.FullURL, "db", p.DB, "error", err)
			record.Status = 0
			record.Finding = false
			auditLog.Record(record)
			continue
		}
		resp.Body.Close()

		record.Status = resp.StatusCode

		// Check if response was delayed (baseline + 4 seconds threshold per spec)
		threshold := baseline + 4*time.Second
		if elapsed > threshold {
			record.Finding = true
			auditLog.Record(record)

			confidence := models.ConfidenceMedium
			// Run a second probe to confirm
			start2 := time.Now()
			req2, err := http.NewRequestWithContext(ctx, endpoint.Method, probeURL, nil)
			if err == nil {
				addAuth(req2, cfg)
				resp2, err := client.Do(req2)
				elapsed2 := time.Since(start2)
				if err == nil {
					resp2.Body.Close()
					if elapsed2 > threshold {
						confidence = models.ConfidenceHigh
					}
					auditLog.Record(ProbeRecord{
						Timestamp: start2,
						Endpoint:  endpoint.FullURL,
						ProbeType: ProbeSQLi,
						Payload:   p.Payload + " (confirmation)",
						Parameter: param,
						Method:    endpoint.Method,
						Status:    resp2.StatusCode,
						Duration:  elapsed2.Round(time.Millisecond).String(),
						Finding:   elapsed2 > threshold,
					})
				}
			}

			findings = append(findings, models.Finding{
				Title:    fmt.Sprintf("Potential SQL Injection (%s)", p.DB),
				Severity: models.SeverityHigh,
				Source:   models.SourceBlackbox,
				Category: "injection",
				Endpoint: fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
				Evidence: fmt.Sprintf("Time-based blind SQLi: baseline=%s, probe=%s (threshold=%s), param=%q, payload=%q",
					baseline.Round(time.Millisecond), elapsed.Round(time.Millisecond), threshold.Round(time.Millisecond), param, p.Payload),
				Fix:        "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
				References: []string{"CWE-89", "OWASP-A03"},
				Confidence: confidence,
			})
			// Found SQLi with this DB type, skip remaining DB payloads for this param
			break
		}

		record.Finding = false
		auditLog.Record(record)
	}

	return findings
}

// probeCMDi sends a safe echo canary payload and checks for reflection in the response.
func probeCMDi(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, auditLog *ProbeAuditLog) []models.Finding {
	if auditLog.Count(endpoint.FullURL) >= MaxProbesPerEndpoint {
		return nil
	}

	probeURL := buildProbeURL(endpoint.FullURL, param, cmdiPayload)

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, probeURL, nil)
	if err != nil {
		slog.Warn("failed to create cmdi probe request", "error", err)
		return nil
	}
	addAuth(req, cfg)

	resp, err := client.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  endpoint.FullURL,
		ProbeType: ProbeCMDi,
		Payload:   cmdiPayload,
		Parameter: param,
		Method:    endpoint.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		slog.Warn("cmdi probe request failed", "endpoint", endpoint.FullURL, "error", err)
		record.Status = 0
		record.Finding = false
		auditLog.Record(record)
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	resp.Body.Close()

	record.Status = resp.StatusCode

	if strings.Contains(string(body), cmdiCanaryPrefix) {
		record.Finding = true
		auditLog.Record(record)

		evidence := fmt.Sprintf("Command injection confirmed: canary %q found in response body, param=%q", cmdiCanaryPrefix, param)
		if len(body) > 200 {
			body = body[:200]
		}
		evidence += fmt.Sprintf(", response snippet: %s", string(body))

		return []models.Finding{{
			Title:      "Command Injection confirmed",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "injection",
			Endpoint:   fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
			Evidence:   evidence,
			Fix:        "Never pass user input to shell commands. Use safe APIs that avoid shell interpretation.",
			References: []string{"CWE-78", "OWASP-A03"},
			Confidence: models.ConfidenceHigh,
		}}
	}

	record.Finding = false
	auditLog.Record(record)
	return nil
}

// probeCRLF injects CRLF characters into query params and header values, checking for header injection.
func probeCRLF(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, auditLog *ProbeAuditLog) []models.Finding {
	if auditLog.Count(endpoint.FullURL) >= MaxProbesPerEndpoint {
		return nil
	}

	// Inject CRLF payload into the query parameter value (raw, not double-encoded)
	sep := "?"
	if strings.Contains(endpoint.FullURL, "?") {
		sep = "&"
	}
	probeURL := fmt.Sprintf("%s%s%s=%s", endpoint.FullURL, sep, url.QueryEscape(param), crlfPayload)

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, probeURL, nil)
	if err != nil {
		slog.Warn("failed to create crlf probe request", "error", err)
		return nil
	}
	addAuth(req, cfg)

	resp, err := client.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  endpoint.FullURL,
		ProbeType: ProbeCRLF,
		Payload:   crlfPayload,
		Parameter: param,
		Method:    endpoint.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		slog.Warn("crlf probe request failed", "endpoint", endpoint.FullURL, "error", err)
		record.Status = 0
		record.Finding = false
		auditLog.Record(record)
		return nil
	}
	resp.Body.Close()

	record.Status = resp.StatusCode

	// Check if the injected Set-Cookie header was reflected
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "fendix" && cookie.Value == "injected" {
			record.Finding = true
			auditLog.Record(record)

			return []models.Finding{{
				Title:      "Header Injection / CRLF",
				Severity:   models.SeverityHigh,
				Source:     models.SourceBlackbox,
				Category:   "injection",
				Endpoint:   fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
				Evidence:   fmt.Sprintf("CRLF injection confirmed: injected Set-Cookie header reflected in response, param=%q", param),
				Fix:        "Sanitize all user input used in HTTP headers. Strip CR/LF characters.",
				References: []string{"CWE-113", "OWASP-A03"},
				Confidence: models.ConfidenceHigh,
			}}
		}
	}

	record.Finding = false
	auditLog.Record(record)
	return nil
}

// buildProbeURL appends a query parameter with the probe payload (URL-encoded).
func buildProbeURL(baseURL, param, payload string) string {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%s=%s", baseURL, sep, url.QueryEscape(param), url.QueryEscape(payload))
}

// addAuth adds authentication headers to a request if configured.
func addAuth(req *http.Request, cfg *models.ScanConfig) {
	if cfg.Auth == nil {
		return
	}
	header := cfg.Auth.Header
	if header == "" {
		header = "Authorization"
	}

	switch cfg.Auth.Type {
	case "bearer":
		req.Header.Set(header, "Bearer "+cfg.Auth.Value)
	case "apikey":
		req.Header.Set(header, cfg.Auth.Value)
	case "basic":
		req.Header.Set(header, "Basic "+cfg.Auth.Value)
	case "cookie":
		req.Header.Set("Cookie", cfg.Auth.Value)
	default:
		req.Header.Set(header, cfg.Auth.Value)
	}
}

// medianDuration returns the median of a slice of durations.
func medianDuration(durations []time.Duration) time.Duration {
	n := len(durations)
	if n == 0 {
		return 0
	}
	sorted := make([]time.Duration, n)
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if n%2 == 0 {
		return time.Duration(math.Round(float64(sorted[n/2-1]+sorted[n/2]) / 2))
	}
	return sorted[n/2]
}
