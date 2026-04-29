package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const rateLimitProbeCount = 20

// rateLimitHeaders are headers that indicate rate limiting is in place.
var rateLimitHeaders = []string{
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
	"X-Rate-Limit-Limit",
	"X-Rate-Limit-Remaining",
	"X-Rate-Limit-Reset",
	"Retry-After",
	"RateLimit-Limit",
	"RateLimit-Remaining",
	"RateLimit-Reset",
}

// CheckRateLimit sends multiple rapid requests to detect rate limiting.
// If all requests succeed with no 429 or rate-limit headers, it reports a finding.
func CheckRateLimit(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	client := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: budget.Transport(),
	}

	throttledCount := 0
	rateLimitHeaderSeen := false

	for i := 0; i < rateLimitProbeCount; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
		if err != nil {
			continue
		}
		cfg.Auth.ApplyToRequest(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 429 {
			throttledCount++
		}

		for _, h := range rateLimitHeaders {
			if resp.Header.Get(h) != "" {
				rateLimitHeaderSeen = true
				break
			}
		}

		if throttledCount > 0 || rateLimitHeaderSeen {
			break
		}
	}

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)

	if throttledCount == 0 && !rateLimitHeaderSeen {
		var headerList []string
		for _, h := range rateLimitHeaders[:3] {
			headerList = append(headerList, h)
		}
		return []models.Finding{
			{
				Title:    "No rate limiting detected",
				Severity: models.SeverityMedium,
				Source:   models.SourceBlackbox,
				Category: "headers",
				Endpoint: epLabel,
				Evidence: fmt.Sprintf("Sent %d rapid requests with no 429 response or rate-limit headers (%s)",
					rateLimitProbeCount, strings.Join(headerList, ", ")),
				Fix:        "Implement rate limiting. Return 429 Too Many Requests with Retry-After header.",
				References: []string{"CWE-770"},
				Confidence: models.ConfidenceMedium,
			},
		}
	}

	slog.Debug("rate limiting detected", "endpoint", epLabel)
	return nil
}
