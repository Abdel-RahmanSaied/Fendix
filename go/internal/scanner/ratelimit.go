package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const rateLimitProbeCount = 20

// staticFilePathRe matches endpoints that serve a static file rather
// than an API route. Rate-limiting these is not a meaningful security
// control — they're served by CDNs / static-file middleware, not the
// app's API layer. TASK-123 / FP corpus pattern P3: juice-shop
// /.DS_Store produced a noise "no rate limiting" finding.
//
// Conservative match: only common static-asset extensions and a handful
// of well-known dotfiles. Misses are fine — the finding emits as
// before; FPs are not silently introduced by an overly-permissive regex.
var staticFilePathRe = regexp.MustCompile(
	`(?i)(?:` +
		`\.(?:DS_Store|map|ico|woff2?|ttf|otf|css|js|mjs|png|jpe?g|gif|svg|webp|avif|bmp|pdf|zip|gz|tar|wasm)$` +
		`|/(?:robots|humans|security|favicon|sitemap)\.(?:txt|xml)$` +
		`)`,
)

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

// rateLimitCheck implements the Check interface for the rate-limit
// detector. Structural adapter — Run holds the unchanged body of the
// historical CheckRateLimit free function.
type rateLimitCheck struct{}

func (rateLimitCheck) Name() string                        { return "ratelimit" }
func (rateLimitCheck) Category() string                    { return "headers" }
func (rateLimitCheck) Tier() Tier                          { return TierPassive }
func (rateLimitCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckRateLimit sends multiple rapid requests to detect rate limiting.
// If all requests succeed with no 429 or rate-limit headers, it reports a finding.
func CheckRateLimit(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	return rateLimitCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged rate-limit detection body. Outbound requests
// go through the shared SSRF-guarded follow-redirect client (cc.Client);
// the per-job deadline comes from ctx (runCheck).
func (rateLimitCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []models.Finding {
	cfg := cc.Cfg
	// TASK-123: skip rate-limit check on static-file endpoints. The
	// check costs N requests per endpoint and the finding it produces
	// ("no rate limiting on /favicon.ico") is noise that doesn't
	// describe a real attack surface.
	if staticFilePathRe.MatchString(endpoint.Path) {
		slog.Debug("rate-limit check skipped (static-file path)",
			"endpoint", fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path))
		return nil
	}

	client := cc.Client

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
