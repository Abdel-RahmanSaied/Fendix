package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const maxEvidenceLen = 200

// exposurePattern defines a regex pattern to scan response bodies for sensitive data.
type exposurePattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity models.Severity
	Title    string
	Fix      string
	CWE      string
}

var exposurePatterns = []exposurePattern{
	{
		Name:     "password_field",
		Pattern:  regexp.MustCompile(`(?i)"password"\s*:\s*"[^"]+"`),
		Severity: models.SeverityCritical,
		Title:    "Password exposed in API response",
		Fix:      "Never return password fields in API responses. Remove from serialization or use a DTO.",
		CWE:      "CWE-200",
	},
	{
		Name:     "secret_field",
		Pattern:  regexp.MustCompile(`(?i)"(?:secret|api_key|apikey|api_secret)"\s*:\s*"[^"]{8,}"`),
		Severity: models.SeverityCritical,
		Title:    "Secret or API key exposed in API response",
		Fix:      "Remove secret fields from API responses. Use server-side references instead.",
		CWE:      "CWE-200",
	},
	{
		Name:     "token_field",
		Pattern:  regexp.MustCompile(`(?i)"(?:token|access_token|refresh_token)"\s*:\s*"[a-zA-Z0-9\-_.]{20,}"`),
		Severity: models.SeverityHigh,
		Title:    "Token exposed in API response",
		Fix:      "Avoid returning long-lived tokens in response bodies. Use secure HTTP-only cookies.",
		CWE:      "CWE-200",
	},
	{
		Name:     "stack_trace",
		Pattern:  regexp.MustCompile(`(?:Traceback \(most recent call last\)|at [a-zA-Z0-9$_.<>]+\s*\([^)]*\)|panic:|goroutine \d+|Exception in thread)`),
		Severity: models.SeverityMedium,
		Title:    "Stack trace in error response",
		Fix:      "Disable debug mode in production. Return generic error messages to clients.",
		CWE:      "CWE-209",
	},
	{
		Name:     "internal_ip",
		Pattern:  regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`),
		Severity: models.SeverityLow,
		Title:    "Internal IP address disclosed in response",
		Fix:      "Remove internal IP addresses from API responses and error messages.",
		CWE:      "CWE-200",
	},
	{
		Name:     "version_string",
		Pattern:  regexp.MustCompile(`(?i)(?:version|ver)["\s]*[:=]\s*["']?\d+\.\d+\.\d+`),
		Severity: models.SeverityInfo,
		Title:    "Software version string in response",
		Fix:      "Consider removing version information from API responses.",
		CWE:      "CWE-200",
	},
}

// CheckExposure scans response bodies for sensitive data patterns.
func CheckExposure(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	client := &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		slog.Warn("exposure check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}

	if cfg.Auth != nil {
		req.Header.Set(cfg.Auth.Header, cfg.Auth.Value)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("exposure check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		slog.Warn("exposure check: failed to read body", "url", endpoint.FullURL, "error", err)
		return nil
	}

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	var findings []models.Finding

	for _, pat := range exposurePatterns {
		match := pat.Pattern.Find(body)
		if match != nil {
			evidence := string(match)
			if len(evidence) > maxEvidenceLen {
				evidence = evidence[:maxEvidenceLen] + "..."
			}

			findings = append(findings, models.Finding{
				Title:      pat.Title,
				Severity:   pat.Severity,
				Source:     models.SourceBlackbox,
				Category:   "data_exposure",
				Endpoint:   epLabel,
				Evidence:   evidence,
				Fix:        pat.Fix,
				References: []string{pat.CWE},
				Confidence: models.ConfidenceHigh,
			})
		}
	}

	slog.Debug("exposure check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}
