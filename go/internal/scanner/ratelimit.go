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

// rateLimitMinProbes is the floor of successfully-completed probe
// requests required before we will conclude "no rate limiting observed".
// 5.6 — if the request budget (--max-requests) is exhausted mid-loop or
// the server/transport errors on most probes, too few requests actually
// reach the target to draw any conclusion; emitting a finding then is a
// false "unprotected". Below this floor the check returns nil
// (inconclusive). Half the probe count, but never fewer than 5.
const rateLimitMinProbes = rateLimitProbeCount / 2

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
func (rateLimitCheck) Category() string                    { return "rate_limiting" }
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
	// 5.6 — count probes that actually completed (got an HTTP response).
	// Requests that fail to build or error out (budget exhaustion,
	// transport errors) do NOT count, so we don't conclude "unprotected"
	// from a handful of requests that never reached the target.
	successfulProbes := 0

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
		successfulProbes++

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

	if throttledCount > 0 || rateLimitHeaderSeen {
		slog.Debug("rate limiting detected", "endpoint", epLabel)
		return nil
	}

	// 5.6 — inconclusive guard. If too few probes completed (budget
	// exhausted mid-loop or repeated transport errors), we cannot
	// distinguish "unprotected" from "we never really hit it". Return nil
	// rather than emit a false finding.
	if successfulProbes < rateLimitMinProbes {
		slog.Debug("rate-limit check inconclusive (too few probes completed)",
			"endpoint", epLabel, "completed", successfulProbes, "floor", rateLimitMinProbes)
		return nil
	}

	// 5.4 / 5.7 — honest scoping. A bounded burst can only show the
	// ABSENCE of limiting within N requests; it cannot prove a per-minute
	// or per-hour limiter is missing. Title + evidence say so explicitly
	// and confidence stays Medium.
	var headerList []string
	for _, h := range rateLimitHeaders[:3] {
		headerList = append(headerList, h)
	}
	return []models.Finding{
		{
			Title:    fmt.Sprintf("No rate limiting observed within %d requests", successfulProbes),
			Severity: models.SeverityMedium,
			Source:   models.SourceBlackbox,
			Category: "rate_limiting",
			Endpoint: epLabel,
			Evidence: fmt.Sprintf(
				"Sent %d rapid requests with no 429 response and no rate-limit headers (%s). "+
					"Scope note: this bounded burst cannot prove the absence of slower per-minute/per-hour limiters — "+
					"it only shows no limiting within %d requests.",
				successfulProbes, strings.Join(headerList, ", "), successfulProbes),
			Fix:        "Implement rate limiting. Return 429 Too Many Requests with Retry-After header.",
			References: []string{"CWE-770"},
			Confidence: models.ConfidenceMedium,
		},
	}
}
