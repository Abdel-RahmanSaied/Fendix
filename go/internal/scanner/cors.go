package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const (
	evilOrigin    = "https://evil.example.com"
	evilDomain    = "evil.example.com"
	attackerCom   = "attacker.com"
	nullOriginVal = "null"
)

// corsCheck implements the Check interface for the CORS misconfiguration
// scanner. Structural adapter — Run holds the unchanged body of the
// historical CheckCORS free function.
type corsCheck struct{}

func (corsCheck) Name() string                        { return "cors" }
func (corsCheck) Category() string                    { return "cors" }
func (corsCheck) Tier() Tier                          { return TierPassive }
func (corsCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckCORS sends a request with an evil Origin header and checks for
// CORS misconfigurations. Covers 4 scenarios:
//  1. Wildcard ACAO + credentials → CRITICAL
//  2. Wildcard ACAO without credentials → MEDIUM
//  3. Reflected arbitrary origin → HIGH
//  4. Non-standard methods allowed → LOW
func CheckCORS(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	return corsCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// probeOrigins returns the set of attacker-controlled Origin values to test
// against an endpoint. Beyond the bare attacker origin (exact-match), it derives
// suffix/prefix/substring bypass candidates from the target host so the common
// permissive-regex misconfigs are caught (Phase 4a / 4.1). The literal "null"
// origin is included to flag servers that reflect sandboxed-iframe / data-URI
// origins (Phase 4a / 4.4). targetHost is parsed from endpoint.FullURL; when it
// is empty (unparseable URL) the host-derived probes are skipped.
func probeOrigins(fullURL string) []string {
	origins := []string{evilOrigin, nullOriginVal}

	targetHost := ""
	if u, err := url.Parse(fullURL); err == nil {
		targetHost = u.Hostname()
	}
	if targetHost != "" {
		origins = append(origins,
			// suffix bypass: target appears as a subdomain of the attacker domain
			fmt.Sprintf("https://%s.%s", targetHost, evilDomain),
			// prefix/substring: target as a subdomain of an attacker-owned domain
			fmt.Sprintf("https://%s.%s", targetHost, attackerCom),
			// substring of attacker host: target embedded in the attacker label
			fmt.Sprintf("https://attacker-%s", targetHost),
		)
	}
	return origins
}

// Run sends CORS probes for a handful of attacker-controlled origins, on both
// the OPTIONS preflight and the endpoint's real (simple-request) method, and
// reports reflected-origin / null-origin / wildcard misconfigurations. Findings
// are deduped by misconfig class so the same issue seen on both preflight and
// simple request is reported once. Client construction is identical to the
// historical free function (guardedClient).
func (corsCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []models.Finding {
	cfg := cc.Cfg
	client := guardedClient(cfg)
	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)

	// One probe per origin on the preflight (OPTIONS) and on the real method
	// (simple request). Some servers reflect Origin only on the actual request,
	// not the preflight (Phase 4a / 4.3).
	methods := []string{http.MethodOptions}
	simpleMethod := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	if simpleMethod == "" {
		simpleMethod = http.MethodGet
	}
	if simpleMethod != http.MethodOptions {
		methods = append(methods, simpleMethod)
	}

	// Phase 1 — probe and record signals. We gather across all probes before
	// emitting, so the broader misconfig classes can subsume the narrower ones
	// (a server that reflects ANY origin trivially reflects "null" too; reporting
	// both would be redundant noise). Each signal also captures whether it was
	// observed with credentials, which escalates its severity.
	var (
		sawWildcard      bool // ACAO: *
		sawWildcardCreds bool // ACAO: * AND ACAC: true
		sawReflected     bool // ACAO == an attacker probe origin (exact)
		sawReflectedCred bool
		reflectedEvid    string
		sawNull          bool // ACAO: null (only when we sent Origin: null)
		sawNullCred      bool
		acamSeen         string // first non-empty Access-Control-Allow-Methods
	)

	for _, probeMethod := range methods {
		for _, origin := range probeOrigins(endpoint.FullURL) {
			req, err := http.NewRequestWithContext(ctx, probeMethod, endpoint.FullURL, nil)
			if err != nil {
				logagg.Warn("cors", "CORS check: failed to create request", "url", endpoint.FullURL, "error", err)
				continue
			}
			req.Header.Set("Origin", origin)
			if probeMethod == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", "GET")
			}
			cfg.Auth.ApplyToRequest(req)

			resp, err := client.Do(req)
			if err != nil {
				logagg.Warn("cors", "CORS check: request failed", "url", endpoint.FullURL, "error", err)
				continue
			}

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := resp.Header.Get("Access-Control-Allow-Credentials")
			acam := resp.Header.Get("Access-Control-Allow-Methods")
			status := resp.StatusCode
			resp.Body.Close()

			// Status-gate narrowing (Phase 4a / 4.5): only 404 and 5xx gate
			// evaluation out. A CORS misconfig on a 404 page is unreachable
			// (FP corpus pattern P2). But auth-gated 401/403/405 responses that
			// still emit reflecting CORS headers ARE real misconfigs — the
			// headers gate cross-origin traffic independently of the probe's
			// auth outcome, so keep evaluating them.
			if status == http.StatusNotFound || status >= 500 {
				slog.Debug("CORS check skipped (404/5xx response)",
					"endpoint", epLabel, "status", status, "method", probeMethod)
				continue
			}

			credentialed := strings.EqualFold(acac, "true")
			if acam != "" && acamSeen == "" {
				acamSeen = acam
			}

			switch {
			case acao == "*":
				sawWildcard = true
				sawWildcardCreds = sawWildcardCreds || credentialed
			case origin == nullOriginVal && strings.EqualFold(acao, nullOriginVal):
				// null-origin acceptance (Phase 4a / 4.4). Sandboxed iframes
				// and data-URIs send Origin: null; reflecting it is exploitable.
				sawNull = true
				sawNullCred = sawNullCred || credentialed
			case origin != nullOriginVal && strings.EqualFold(acao, origin):
				// Reflected arbitrary origin (Phase 4a / 4.1, 4.2). Detection is
				// EXACT case-insensitive equality to the probe origin, never a
				// substring match — that avoids the false-positive class where a
				// legitimate allowlisted origin merely contains the attacker host.
				sawReflected = true
				sawReflectedCred = sawReflectedCred || credentialed
				if reflectedEvid == "" {
					reflectedEvid = acao
				}
			}
		}
	}

	// Phase 2 — emit findings from the collected signals, narrower classes
	// suppressed by broader ones.
	var findings []models.Finding

	switch {
	case sawWildcardCreds:
		findings = append(findings, models.Finding{
			Title:      "CORS wildcard origin with credentials allowed",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
			Fix:        "Never combine wildcard origin with credentials. Specify explicit allowed origins.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceHigh,
		})
	case sawWildcard:
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
	case sawReflected:
		// Reflecting an arbitrary attacker origin subsumes the null-origin case.
		f := models.Finding{
			Title:      "CORS reflects arbitrary origin",
			Severity:   models.SeverityHigh,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   fmt.Sprintf("Access-Control-Allow-Origin reflects attacker origin: %s", reflectedEvid),
			Fix:        "Validate Origin against an explicit allowlist. Do not reflect the Origin header.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceHigh,
		}
		if sawReflectedCred {
			// Reflected arbitrary origin WITH credentials is account-takeover
			// grade (Phase 4a / 4.2) → CRITICAL.
			f.Title = "CORS reflects arbitrary origin with credentials"
			f.Severity = models.SeverityCritical
			f.Evidence = fmt.Sprintf("Access-Control-Allow-Origin reflects attacker origin: %s with Access-Control-Allow-Credentials: true", reflectedEvid)
		}
		findings = append(findings, f)
	case sawNull:
		f := models.Finding{
			Title:      "CORS accepts null origin",
			Severity:   models.SeverityHigh,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   "Access-Control-Allow-Origin: null",
			Fix:        "Never allow the null origin. Validate Origin against an explicit allowlist.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceHigh,
		}
		if sawNullCred {
			f.Severity = models.SeverityCritical
			f.Evidence = "Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true"
		}
		findings = append(findings, f)
	}

	// Method-policy findings are independent of the origin verdict: wildcard
	// methods (Phase 4a / 4.6) and genuinely non-standard tokens.
	findings = appendMethodFindings(findings, acamSeen, epLabel)

	slog.Debug("CORS check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}

// appendMethodFindings evaluates the Access-Control-Allow-Methods header and
// appends at most one method-policy finding. A wildcard ("*", or "*" among the
// listed tokens) is its own finding class (Phase 4a / 4.6); the historical
// non-standard-token detection is preserved for genuinely odd methods. Called
// once per endpoint, so no cross-probe dedup is needed.
func appendMethodFindings(findings []models.Finding, acam, epLabel string) []models.Finding {
	if acam == "" {
		return findings
	}

	standardMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "PATCH": true,
		"DELETE": true, "HEAD": true, "OPTIONS": true,
	}

	if strings.TrimSpace(acam) == "*" {
		return append(findings, models.Finding{
			Title:      "CORS allows all methods (wildcard)",
			Severity:   models.SeverityMedium,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   "Access-Control-Allow-Methods: *",
			Fix:        "List only the HTTP methods the endpoint requires instead of a wildcard.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceMedium,
		})
	}

	for _, method := range strings.Split(acam, ",") {
		method = strings.TrimSpace(strings.ToUpper(method))
		if method == "*" {
			return append(findings, models.Finding{
				Title:      "CORS allows all methods (wildcard)",
				Severity:   models.SeverityMedium,
				Source:     models.SourceBlackbox,
				Category:   "cors",
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("Access-Control-Allow-Methods includes wildcard method: %s", acam),
				Fix:        "List only the HTTP methods the endpoint requires instead of a wildcard.",
				References: []string{"CWE-942"},
				Confidence: models.ConfidenceMedium,
			})
		}
		if method != "" && !standardMethods[method] {
			return append(findings, models.Finding{
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
		}
	}
	return findings
}
