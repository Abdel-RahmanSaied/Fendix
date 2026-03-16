package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fendix/fendix/internal/models"
)

const evilOrigin = "https://evil.example.com"

// CheckCORS sends a request with an evil Origin header and checks for
// CORS misconfigurations. Covers 4 scenarios:
//  1. Wildcard ACAO + credentials → CRITICAL
//  2. Wildcard ACAO without credentials → MEDIUM
//  3. Reflected arbitrary origin → HIGH
//  4. Non-standard methods allowed → LOW
func CheckCORS(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	client := &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second}

	req, err := http.NewRequestWithContext(ctx, "OPTIONS", endpoint.FullURL, nil)
	if err != nil {
		slog.Warn("CORS check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}

	req.Header.Set("Origin", evilOrigin)
	req.Header.Set("Access-Control-Request-Method", "GET")

	if cfg.Auth != nil {
		req.Header.Set(cfg.Auth.Header, cfg.Auth.Value)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("CORS check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	acam := resp.Header.Get("Access-Control-Allow-Methods")

	var findings []models.Finding

	if acao == "*" && strings.EqualFold(acac, "true") {
		findings = append(findings, models.Finding{
			Title:      "CORS wildcard origin with credentials allowed",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   fmt.Sprintf("Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: %s", acac),
			Fix:        "Never combine wildcard origin with credentials. Specify explicit allowed origins.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceHigh,
		})
	} else if acao == "*" {
		findings = append(findings, models.Finding{
			Title:      "CORS allows any origin",
			Severity:   models.SeverityMedium,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   "Access-Control-Allow-Origin: *",
			Fix:        "Restrict Access-Control-Allow-Origin to specific trusted origins.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceHigh,
		})
	} else if acao == evilOrigin {
		findings = append(findings, models.Finding{
			Title:      "CORS reflects arbitrary origin",
			Severity:   models.SeverityHigh,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   fmt.Sprintf("Access-Control-Allow-Origin reflects attacker origin: %s", evilOrigin),
			Fix:        "Validate Origin against an explicit allowlist. Do not reflect the Origin header.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceHigh,
		})
	}

	if acam != "" {
		standardMethods := map[string]bool{
			"GET": true, "POST": true, "PUT": true, "PATCH": true,
			"DELETE": true, "HEAD": true, "OPTIONS": true,
		}
		for _, method := range strings.Split(acam, ",") {
			method = strings.TrimSpace(strings.ToUpper(method))
			if method != "" && !standardMethods[method] {
				findings = append(findings, models.Finding{
					Title:      "CORS allows non-standard HTTP method",
					Severity:   models.SeverityLow,
					Source:     models.SourceBlackbox,
					Category:   "cors",
					Endpoint:   epLabel,
					Evidence:   fmt.Sprintf("Access-Control-Allow-Methods includes non-standard method: %s", method),
					Fix:        "Remove non-standard methods from Access-Control-Allow-Methods.",
					References: []string{"CWE-942"},
					Confidence: models.ConfidenceMedium,
				})
				break
			}
		}
	}

	slog.Debug("CORS check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}
