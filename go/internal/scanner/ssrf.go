package scanner

// In-band Server-Side Request Forgery (CWE-918) active check.
//
// This check detects whether the TARGET makes server-side requests to a
// client-controlled URL. It is DISTINCT from the internal netguard SSRF guard
// (httpclient.go / internal/netguard), which protects fendix's OWN outbound
// egress from being steered at private/metadata hosts. Here we are the
// attacker: we feed a URL-shaped parameter a canary destination and watch the
// target's response for evidence that the SERVER fetched it.
//
// ============================================================================
// KNOWN LIMITS (honest, documented false negatives — deliberate scope):
//
//   - NO TRUE OAST/BLIND DETECTION. fendix ships no out-of-band callback
//     (collaborator/interactsh) server, so a "blind" SSRF that fetches our
//     sentinel host with NO observable in-band side effect (no error leak, no
//     inlined content, no redirect echo, no timing differential) is
//     UNDETECTABLE here. A --oob-host hook is future work. This gap is asserted
//     by TestSSRF_DocumentedBlindLimitFN so it stays honest, not hidden.
//   - CLOUD-METADATA (IMDS) IS CONFIRMED ONLY INDIRECTLY. We never fetch real
//     169.254.169.254 data — that would require the target to proxy it back to
//     us in-band (the reflected-fetch path). We do not special-case IMDS or
//     assert AWS/GCP/Azure credentials were exfiltrated.
//   - ERROR-SUPPRESSING / IDENTICAL-RESPONSE servers evade detection. A target
//     that fetches server-side but returns a constant body regardless of the
//     fetch outcome leaks nothing in-band (the documented-blind case).
//   - SECOND-ORDER SSRF is out of scope. We inspect the immediate response to a
//     single request; a fetch triggered later (queue/cron/webhook delivery) on
//     a different request is not observed.
//   - TIMING IS NOISY. The timing-differential signal is confirmation-only,
//     capped at MEDIUM, never fires when a stronger signal already did, and is
//     gated behind a small budget-bounded sample.
//
// ============================================================================
// FALSE-POSITIVE GUARDS (load-bearing — these ARE the check):
//
//   (a) ERROR-LEAK requires BOTH a curated fetch-stack error signature AND our
//       unique canary host in the body. A generic "connection refused" page
//       that does not echo our canary host is NOT flagged (it proves only that
//       *something* failed, not that the server fetched OUR url).
//   (b) REFLECTED-FETCH requires the unique marker to be ABSENT from a benign
//       baseline AND the canary host to be ABSENT from the body. The latter
//       distinguishes a server-side FETCH (which inlines upstream content but
//       not our literal URL) from mere VERBATIM REFLECTION of the param (which
//       echoes the whole injected URL, canary host included). Reflection is the
//       dominant SSRF false positive; this guard kills it.
//
// Sentinel host: the ".invalid" TLD is reserved by RFC 2606 and is guaranteed
// to never resolve, be registered, or be owned by anyone — so the canary is a
// safe, non-routable destination. The TEST-NET-1 literal 192.0.2.1 (RFC 5737)
// is similarly reserved for documentation and is never a live host.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ssrfSentinelHost is the reserved-TLD base under which every canary host is
// constructed. RFC 2606 guarantees .invalid never resolves and can never be
// owned, so injecting a URL under it is a safe, non-routable probe.
const ssrfSentinelHost = "oob.fendix.invalid"

// ssrfTestNetLiteral is an RFC 5737 TEST-NET-1 address reserved for
// documentation; it is never a live host, so a server that errors trying to
// reach it leaks a fetch-stack error without us touching any real system.
const ssrfTestNetLiteral = "192.0.2.1"

// ssrfBodyLimit caps how much of each response body we read into memory.
const ssrfBodyLimit = 1 << 20 // 1 MiB

// urlParamRe matches parameter names that conventionally carry a URL/host/path
// destination — the surface where SSRF actually lives. Probing only these
// (rather than every declared param) keeps the per-endpoint probe budget
// meaningful and avoids spraying URL payloads at obviously-non-URL fields like
// "comment" or "quantity". Matched as whole words / case-insensitively against
// segments of the param name (so "imageUrl", "callback_url", "redirectUri" all
// hit). An all-params opt-in is intentionally deferred (future work).
var urlParamRe = regexp.MustCompile(`(?i)(^|[^a-z])(url|uri|link|src|dest|redirect|callback|webhook|host|domain|feed|target|fetch|proxy|next|return|continue|image|img|file|path|resource|api|endpoint|site|page|out|to|u)([^a-z]|$)`)

// isURLShapedParam reports whether a parameter name looks like it carries a URL
// or host destination, per urlParamRe.
func isURLShapedParam(name string) bool {
	return urlParamRe.MatchString(name)
}

// ssrfErrorPatterns matches outbound fetch-stack error leakage in a response
// body — the signatures a server emits when its server-side HTTP client fails
// to reach the destination we supplied. Curated across Go/Java/Python/Node/libc
// stacks and kept tight to avoid matching unrelated prose. A match is necessary
// but NOT sufficient: signal (a) also requires our canary host in the body.
var ssrfErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)connection refused|ECONNREFUSED`),
	regexp.MustCompile(`(?i)no route to host|EHOSTUNREACH`),
	regexp.MustCompile(`(?i)dial tcp|getaddrinfo|Name or service not known`),
	regexp.MustCompile(`(?i)UnknownHostException|java\.net\.ConnectException`),
	regexp.MustCompile(`(?i)failed to connect|could not resolve host`),
	regexp.MustCompile(`(?i)requests\.exceptions\.(ConnectionError|Timeout)|urllib\.error`),
	regexp.MustCompile(`(?i)connection timed out|ETIMEDOUT`),
}

// matchSSRFError returns the first fetch-stack error signature found in the
// body, or "" if none match.
func matchSSRFError(body string) string {
	for _, re := range ssrfErrorPatterns {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// SSRFCheck is the active in-band SSRF (CWE-918) check. For each URL-shaped
// target it sends canary fetch probes and classifies the target's response via
// three in-band signals with precedence (a) error-leak > (b) reflected-fetch >
// (c) timing. At most one finding is emitted per (param, location).
type SSRFCheck struct{}

func (SSRFCheck) Name() string     { return "ssrf" }
func (SSRFCheck) Category() string { return "ssrf" }
func (SSRFCheck) Tier() Tier       { return TierActive }
func (SSRFCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// Run probes every URL-shaped (param, location) target. Active discipline
// mirrors probeCMDi / reflectedXSSCheck: a ctx.Done()/budget check before each
// probe, a ProbeRecord per probe, and auth applied via cfg.Auth.ApplyToRequest.
// Skips non-2xx/3xx baseline endpoints (a 404 surface is not a feature, same as
// headers/cors). At most one finding per target, precedence (a)>(b)>(c).
func (SSRFCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []models.Finding {
	if cc == nil || cc.Cfg == nil || !cc.Cfg.EnableActive {
		return nil
	}

	var findings []models.Finding
	maxProbes := effectiveMaxProbes(cc.Cfg)

	// SSRF lives in URL-shaped params; filter the target set first (all-params
	// opt-in is deferred future work). Header/body URL params are eligible too.
	// We filter BEFORE the baseline request so a non-URL-param endpoint costs
	// zero requests — there is nothing to probe, so we never touch the target.
	var targets []probeTarget
	for _, t := range targetsForEndpoint(ep) {
		if isURLShapedParam(t.Name) {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return findings
	}

	// Skip endpoints whose baseline isn't a real 2xx/3xx feature (e.g. a 404)
	// — mirrors the headers/cors behaviour of not probing dead surfaces.
	if !ssrfBaselineServiceable(ctx, cc, ep) {
		return findings
	}

	for _, t := range targets {
		// Active discipline: soft-stop on cancellation, then budget cap —
		// both checked before sending any probe (mirrors probeCMDi).
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if cc.Audit.Count(ep.FullURL) >= maxProbes {
			logagg.Warn("ssrf", "max probes reached for endpoint", "endpoint", ep.FullURL, "max", maxProbes)
			return findings
		}

		if f, ok := probeSSRF(ctx, cc, ep, t.Name, t.Location); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

// ssrfBaselineServiceable sends one benign control request and reports whether
// the endpoint answers with a 2xx/3xx (a real feature). A non-following client
// is used so a 3xx still counts as serviceable. Returns false on transport
// error or a 4xx/5xx baseline. Records a ProbeRecord for accountability.
func ssrfBaselineServiceable(ctx context.Context, cc *CheckContext, ep Endpoint) bool {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, ep.Method, ep.FullURL, nil)
	if err != nil {
		return false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeSSRF,
		Payload:   "(baseline)",
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		record.Status = 0
		cc.Audit.Record(record)
		return false
	}
	resp.Body.Close()
	record.Status = resp.StatusCode
	cc.Audit.Record(record)
	return resp.StatusCode >= 200 && resp.StatusCode <= 399
}

// probeSSRF runs the in-band SSRF signals against one (param, location) target
// and returns the first finding by precedence (a error-leak > b reflected-fetch
// > c timing). Returns (finding, true) on a hit, (zero, false) otherwise.
func probeSSRF(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation) (models.Finding, bool) {
	// Unique per-target canary so a hit cannot collide with static page text and
	// the marker cannot be guessed/special-cased by the target.
	canary := "fendix-ssrf-" + randHex(8)
	canaryHost := canary + "." + ssrfSentinelHost
	marker := canary // the marker reused as the reflected-fetch token

	// (b) baseline body for the reflected-fetch ABSENT-from-baseline guard: a
	// benign control fetch whose body must NOT already contain the marker. We
	// capture it once and reuse it for the content-fetch decision below.
	baselineBody := ssrfControlBody(ctx, cc, ep, param, loc)

	// ---- Signal (a): ERROR-LEAK + (b): REFLECTED-FETCH (content) ----
	// One probe carries the canary host AND the marker, so a single response can
	// satisfy either the error-leak or the content-fetch path. Precedence (a)>(b)
	// is enforced by checking the error signature first.
	//
	// The canary URL embeds the marker in the query so a server that FETCHES it
	// surfaces upstream content (the marker) without echoing our literal host.
	canaryURL := "http://" + canaryHost + "/?marker=" + marker
	if f, ok := ssrfFetchProbe(ctx, cc, ep, param, loc, canaryURL, canaryHost, marker, baselineBody); ok {
		return f, true
	}

	// A second error-leak probe with the RFC 5737 TEST-NET literal: some targets
	// reject the bogus .invalid hostname at DNS but will try (and fail) to dial a
	// syntactically-valid IP, leaking a connect-time error that still echoes the
	// literal we supplied.
	testnetURL := "http://" + ssrfTestNetLiteral + "/"
	if f, ok := ssrfFetchProbe(ctx, cc, ep, param, loc, testnetURL, ssrfTestNetLiteral, "", baselineBody); ok {
		return f, true
	}

	// ---- Signal (b): REDIRECT-ECHO (raw 3xx Location → canary host) ----
	if f, ok := ssrfRedirectProbe(ctx, cc, ep, param, loc, canaryURL, canaryHost); ok {
		return f, true
	}

	// ---- Signal (c): TIMING (confirmation-only, never if a/b fired) ----
	if f, ok := ssrfTimingProbe(ctx, cc, ep, param, loc); ok {
		return f, true
	}

	return models.Finding{}, false
}

// ssrfControlBody sends one benign control request (the param set to a harmless
// value, NOT our canary) and returns the response body. Used as the
// ABSENT-from-baseline reference for the reflected-fetch guard (b). Returns ""
// on any error — an empty baseline simply means "marker certainly absent".
func ssrfControlBody(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation) string {
	req, err := buildProbeRequest(ctx, ep, param, "https://example.com/", loc)
	if err != nil {
		return ""
	}
	cc.Cfg.Auth.ApplyToRequest(req)
	resp, err := cc.Client.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, ssrfBodyLimit))
	resp.Body.Close()
	return string(body)
}

// ssrfFetchProbe sends one canary URL probe via the body-following client and
// classifies the response for signal (a) error-leak then (b) reflected-fetch.
//
//   - (a) fires when the body contains BOTH a fetch-stack error signature AND
//     the canary host (proving the server fetched OUR url, not a generic error).
//   - (b) fires when the body contains the marker, the marker was ABSENT from
//     the baseline, AND the canary host is NOT echoed verbatim (distinguishing a
//     server-side fetch from mere reflection of the injected URL). marker may be
//     "" to skip the content-fetch path (e.g. the TEST-NET literal probe).
func ssrfFetchProbe(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation, injectURL, canaryHost, marker, baselineBody string) (models.Finding, bool) {
	body, status, ok := ssrfSendBody(ctx, cc, ep, param, loc, injectURL)
	if !ok {
		return models.Finding{}, false
	}

	// (a) ERROR-LEAK: error signature AND our canary host both present.
	if sig := matchSSRFError(body); sig != "" && strings.Contains(body, canaryHost) {
		evidence := fmt.Sprintf(
			"Outbound fetch error leakage: response (status=%d) contains fetch-stack error %q AND our canary host %q, proving the server attempted to fetch the injected URL %q. %s",
			status, sig, canaryHost, injectURL, paramLabel(param, loc),
		)
		return models.Finding{
			Title:    "SSRF — outbound fetch error leakage",
			Severity: models.SeverityHigh,
			Source:   models.SourceBlackbox,
			Category: "ssrf",
			Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
			Evidence: evidence,
			Fix: "Do not fetch user-supplied URLs. Enforce an allow-list of destination hosts/schemes, " +
				"resolve+pin the IP and reject private/link-local/metadata ranges, and disable redirects on the server-side fetcher.",
			References: []string{"CWE-918", "OWASP-A10"},
			Confidence: models.ConfidenceHigh,
		}, true
	}

	// (b) REFLECTED-FETCH (content): marker inlined, absent from baseline, and
	// the canary host NOT echoed verbatim (would indicate plain reflection).
	if marker != "" &&
		strings.Contains(body, marker) &&
		!strings.Contains(baselineBody, marker) &&
		!strings.Contains(body, canaryHost) {
		evidence := fmt.Sprintf(
			"Reflected fetch: unique marker %q appears in the response (status=%d) but was absent from the benign baseline, and our literal canary host was NOT echoed — the server fetched the canary URL %q and inlined its content. %s",
			marker, status, injectURL, paramLabel(param, loc),
		)
		return models.Finding{
			Title:    "SSRF — server-side fetch of attacker-controlled URL",
			Severity: models.SeverityHigh,
			Source:   models.SourceBlackbox,
			Category: "ssrf",
			Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
			Evidence: evidence,
			Fix: "Do not fetch user-supplied URLs. Enforce an allow-list of destination hosts/schemes, " +
				"resolve+pin the IP and reject private/link-local/metadata ranges, and never inline fetched content back into the response.",
			References: []string{"CWE-918", "OWASP-A10"},
			Confidence: models.ConfidenceHigh,
		}, true
	}

	return models.Finding{}, false
}

// ssrfRedirectProbe sends the canary URL via the NON-following client and fires
// (b, redirect-echo, MEDIUM) when the raw 3xx Location header carries our canary
// host — a server-side fetcher that 30x's onward to the supplied URL.
func ssrfRedirectProbe(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation, injectURL, canaryHost string) (models.Finding, bool) {
	if cc.Audit.Count(ep.FullURL) >= effectiveMaxProbes(cc.Cfg) {
		return models.Finding{}, false
	}
	select {
	case <-ctx.Done():
		return models.Finding{}, false
	default:
	}

	start := time.Now()
	req, err := buildProbeRequest(ctx, ep, param, injectURL, loc)
	if err != nil {
		logagg.Warn("ssrf", "failed to create redirect-echo probe request", "error", err)
		return models.Finding{}, false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeSSRF,
		Payload:   injectURL,
		Parameter: param,
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("ssrf", "redirect-echo probe request failed", "endpoint", ep.FullURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return models.Finding{}, false
	}
	resp.Body.Close()
	record.Status = resp.StatusCode

	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		location := resp.Header.Get("Location")
		if location != "" && strings.Contains(location, canaryHost) {
			record.Finding = true
			cc.Audit.Record(record)
			return models.Finding{
				Title:    "SSRF — server-side fetch of attacker-controlled URL",
				Severity: models.SeverityMedium,
				Source:   models.SourceBlackbox,
				Category: "ssrf",
				Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
				Evidence: fmt.Sprintf(
					"Redirect echo: status=%d Location=%q carries our canary host %q — the server-side fetcher forwards to the supplied URL. %s",
					resp.StatusCode, location, canaryHost, paramLabel(param, loc),
				),
				Fix: "Do not fetch or redirect to user-supplied URLs. Enforce an allow-list of destination hosts/schemes " +
					"and disable redirect following on the server-side fetcher.",
				References: []string{"CWE-918", "OWASP-A10"},
				Confidence: models.ConfidenceMedium,
			}, true
		}
	}

	cc.Audit.Record(record)
	return models.Finding{}, false
}

// ssrfTimingProbe is the confirmation-only timing-differential signal (MEDIUM).
// It only fires when neither (a) nor (b) did (precedence) and is intentionally
// minimal + budget-bounded: timing is noisy. It measures a benign baseline
// (median of a small N via measureBaseline) and one probe pointed at a host that
// would hang to connect-timeout; if the probe greatly exceeds baseline+threshold
// the target is likely fetching server-side. Conservative threshold keeps the
// FP rate low; this is the weakest signal in the precedence chain.
//
// In practice the .invalid sentinel fails fast (NXDOMAIN) rather than hanging,
// so this rarely fires in the loopback test environment — which is correct: a
// host we can't make hang produces no timing differential. The branch exists so
// real targets with a slow-failing fetcher are still surfaced at MEDIUM.
func ssrfTimingProbe(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation) (models.Finding, bool) {
	maxProbes := effectiveMaxProbes(cc.Cfg)
	// Need at least the baseline samples (3) plus one timing probe; bail if the
	// budget can't cover them rather than overshoot the operator's cap.
	if cc.Audit.Count(ep.FullURL)+4 > maxProbes {
		return models.Finding{}, false
	}
	select {
	case <-ctx.Done():
		return models.Finding{}, false
	default:
	}

	baseline, err := measureBaseline(ctx, cc.Client, cc.Cfg, ep.Method, ep.FullURL)
	if err != nil {
		logagg.Warn("ssrf", "failed to measure baseline for timing", "endpoint", ep.FullURL, "error", err)
		return models.Finding{}, false
	}

	// A host under the sentinel TLD that a server-side fetcher would block on
	// while trying to connect. We measure the median of a small sample.
	hangURL := "http://" + "fendix-ssrf-timing-" + randHex(8) + "." + ssrfSentinelHost + "/"
	var samples []time.Duration
	const n = 2
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return models.Finding{}, false
		default:
		}
		start := time.Now()
		req, err := buildProbeRequest(ctx, ep, param, hangURL, loc)
		if err != nil {
			return models.Finding{}, false
		}
		cc.Cfg.Auth.ApplyToRequest(req)
		resp, err := cc.Client.Do(req)
		elapsed := time.Since(start)
		record := ProbeRecord{
			Timestamp: start,
			Endpoint:  ep.FullURL,
			ProbeType: ProbeSSRF,
			Payload:   hangURL,
			Parameter: param,
			Method:    ep.Method,
			Duration:  elapsed.Round(time.Millisecond).String(),
		}
		if err != nil {
			record.Status = 0
			cc.Audit.Record(record)
			// A transport error (fast NXDOMAIN at our own guard, refused dial)
			// is NOT a timing signal — abandon the timing branch.
			return models.Finding{}, false
		}
		resp.Body.Close()
		record.Status = resp.StatusCode
		cc.Audit.Record(record)
		samples = append(samples, elapsed)
	}

	probe := medianDuration(samples)
	// Conservative threshold: the probe must exceed baseline by a wide margin to
	// be attributable to a server-side connect-timeout rather than jitter.
	const ssrfTimingThreshold = 4 * time.Second
	if probe > baseline+ssrfTimingThreshold {
		return models.Finding{
			Title:    "SSRF — timing differential",
			Severity: models.SeverityMedium,
			Source:   models.SourceBlackbox,
			Category: "ssrf",
			Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
			Evidence: fmt.Sprintf(
				"Timing differential: baseline median=%s, canary-fetch median=%s (threshold=%s) — the server appears to block while fetching the supplied unroutable URL. Confirmation-only signal. %s",
				baseline.Round(time.Millisecond), probe.Round(time.Millisecond), ssrfTimingThreshold, paramLabel(param, loc),
			),
			Fix: "Do not fetch user-supplied URLs. Enforce an allow-list of destination hosts/schemes and a short, " +
				"bounded connect timeout on the server-side fetcher.",
			References: []string{"CWE-918", "OWASP-A10"},
			Confidence: models.ConfidenceMedium,
		}, true
	}

	return models.Finding{}, false
}

// ssrfSendBody sends one probe (param=injectURL at loc) via the body-following
// client, records a ProbeRecord, and returns (body, status, ok). ok=false on a
// budget exhaustion, cancellation, build, or transport error.
func ssrfSendBody(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation, injectURL string) (string, int, bool) {
	if cc.Audit.Count(ep.FullURL) >= effectiveMaxProbes(cc.Cfg) {
		return "", 0, false
	}
	select {
	case <-ctx.Done():
		return "", 0, false
	default:
	}

	start := time.Now()
	req, err := buildProbeRequest(ctx, ep, param, injectURL, loc)
	if err != nil {
		logagg.Warn("ssrf", "failed to create ssrf probe request", "error", err)
		return "", 0, false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.Client.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeSSRF,
		Payload:   injectURL,
		Parameter: param,
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("ssrf", "ssrf probe request failed", "endpoint", ep.FullURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return "", 0, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, ssrfBodyLimit))
	resp.Body.Close()
	record.Status = resp.StatusCode
	cc.Audit.Record(record)
	return string(body), resp.StatusCode, true
}
