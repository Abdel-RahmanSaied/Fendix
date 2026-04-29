package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// headerCheck defines what to look for in a single response header.
type headerCheck struct {
	Name     string
	Severity models.Severity
	Category string
	Check    func(value string) *models.Finding
}

// securityHeaders returns the list of header checks per the spec:
// HSTS, X-Content-Type-Options, X-Frame-Options, CSP,
// X-XSS-Protection, Server, X-Powered-By.
func securityHeaders(endpoint string) []headerCheck {
	return []headerCheck{
		{
			Name:     "Strict-Transport-Security",
			Severity: models.SeverityMedium,
			Category: "headers",
			Check: func(value string) *models.Finding {
				if value == "" {
					return &models.Finding{
						Title:      "Missing Strict-Transport-Security header",
						Severity:   models.SeverityMedium,
						Source:     models.SourceBlackbox,
						Category:   "headers",
						Endpoint:   endpoint,
						Evidence:   "Response does not include Strict-Transport-Security header",
						Fix:        "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
						References: []string{"CWE-319"},
						Confidence: models.ConfidenceHigh,
					}
				}
				return nil
			},
		},
		{
			Name:     "X-Content-Type-Options",
			Severity: models.SeverityLow,
			Category: "headers",
			Check: func(value string) *models.Finding {
				if strings.ToLower(value) != "nosniff" {
					return &models.Finding{
						Title:      "Missing or incorrect X-Content-Type-Options header",
						Severity:   models.SeverityLow,
						Source:     models.SourceBlackbox,
						Category:   "headers",
						Endpoint:   endpoint,
						Evidence:   fmt.Sprintf("X-Content-Type-Options: %q (expected 'nosniff')", value),
						Fix:        "Add header: X-Content-Type-Options: nosniff",
						References: []string{"CWE-693"},
						Confidence: models.ConfidenceHigh,
					}
				}
				return nil
			},
		},
		{
			Name:     "X-Frame-Options",
			Severity: models.SeverityLow,
			Category: "headers",
			Check: func(value string) *models.Finding {
				v := strings.ToUpper(value)
				if v != "DENY" && v != "SAMEORIGIN" {
					return &models.Finding{
						Title:      "Missing or incorrect X-Frame-Options header",
						Severity:   models.SeverityLow,
						Source:     models.SourceBlackbox,
						Category:   "headers",
						Endpoint:   endpoint,
						Evidence:   fmt.Sprintf("X-Frame-Options: %q (expected 'DENY' or 'SAMEORIGIN')", value),
						Fix:        "Add header: X-Frame-Options: DENY",
						References: []string{"CWE-1021"},
						Confidence: models.ConfidenceHigh,
					}
				}
				return nil
			},
		},
		{
			Name:     "Content-Security-Policy",
			Severity: models.SeverityMedium,
			Category: "headers",
			Check: func(value string) *models.Finding {
				if value == "" {
					return &models.Finding{
						Title:      "Missing Content-Security-Policy header",
						Severity:   models.SeverityMedium,
						Source:     models.SourceBlackbox,
						Category:   "headers",
						Endpoint:   endpoint,
						Evidence:   "Response does not include Content-Security-Policy header",
						Fix:        "Add a Content-Security-Policy header with appropriate directives",
						References: []string{"CWE-693"},
						Confidence: models.ConfidenceHigh,
					}
				}
				return nil
			},
		},
		{
			Name:     "Server",
			Severity: models.SeverityInfo,
			Category: "headers",
			Check: func(value string) *models.Finding {
				if value != "" && containsVersion(value) {
					return &models.Finding{
						Title:      "Server version disclosed in header",
						Severity:   models.SeverityInfo,
						Source:     models.SourceBlackbox,
						Category:   "headers",
						Endpoint:   endpoint,
						Evidence:   fmt.Sprintf("Server: %s", value),
						Fix:        "Remove version information from Server header or remove the header entirely",
						References: []string{"CWE-200"},
						Confidence: models.ConfidenceHigh,
					}
				}
				return nil
			},
		},
		{
			Name:     "X-Powered-By",
			Severity: models.SeverityInfo,
			Category: "headers",
			Check: func(value string) *models.Finding {
				if value != "" {
					return &models.Finding{
						Title:      "X-Powered-By header discloses technology",
						Severity:   models.SeverityInfo,
						Source:     models.SourceBlackbox,
						Category:   "headers",
						Endpoint:   endpoint,
						Evidence:   fmt.Sprintf("X-Powered-By: %s", value),
						Fix:        "Remove the X-Powered-By header",
						References: []string{"CWE-200"},
						Confidence: models.ConfidenceHigh,
					}
				}
				return nil
			},
		},
	}
}

// containsVersion checks if a header value contains a version number pattern.
func containsVersion(value string) bool {
	for i := 0; i < len(value)-1; i++ {
		if value[i] >= '0' && value[i] <= '9' && (i+1 < len(value)) && value[i+1] == '.' {
			return true
		}
		if value[i] == '/' && i+1 < len(value) && value[i+1] >= '0' && value[i+1] <= '9' {
			return true
		}
	}
	return false
}

// CheckHeaders sends a GET request and checks for missing/misconfigured security headers.
func CheckHeaders(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	client := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: budget.Transport(),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("headers", "headers check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}

	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("headers", "headers check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	checks := securityHeaders(epLabel)

	var findings []models.Finding
	for _, hc := range checks {
		value := resp.Header.Get(hc.Name)
		if finding := hc.Check(value); finding != nil {
			findings = append(findings, *finding)
		}
	}

	slog.Debug("headers check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}
