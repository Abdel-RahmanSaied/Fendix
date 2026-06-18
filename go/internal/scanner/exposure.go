package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const maxEvidenceLen = 200

// exposurePattern defines a regex pattern to scan response bodies for
// sensitive data. When Guard is non-nil it receives the matched bytes
// and may veto the match (return false → not a finding); used to drop
// masked/placeholder values that would otherwise FP.
type exposurePattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity models.Severity
	Title    string
	Fix      string
	CWE      string
	Guard    func(match []byte) bool
}

// 4.14: a real stack frame requires a dotted package/identifier path
// followed by a (file.ext:line) location. The file extension + ":digit"
// anchor is what separates a true frame from prose like "at home
// (tomorrow)". The Python/Go/Java framing markers stay as literals.
var stackFrameLocRe = `\([^)]*\.(?:java|kt|js|jsx|ts|tsx|scala|py|go|rb|php|cs|cpp|c|swift|rs):\d+`

var exposurePatterns = []exposurePattern{
	{
		Name:     "password_field",
		Pattern:  regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		Severity: models.SeverityCritical,
		Title:    "Password exposed in API response",
		Fix:      "Never return password fields in API responses. Remove from serialization or use a DTO.",
		CWE:      "CWE-200",
		Guard:    passwordNotMasked,
	},
	{
		Name:     "secret_field",
		Pattern:  regexp.MustCompile(`(?i)"(?:secret|api_key|apikey|api_secret|client_secret|private_key)"\s*:\s*"[^"]{8,}"`),
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
	// 4.13: value-shape secrets, independent of any JSON key name.
	{
		Name:     "jwt_value",
		Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		Severity: models.SeverityHigh,
		Title:    "JWT exposed in API response",
		Fix:      "Do not return JWTs in response bodies where they aren't expected; treat as a credential leak and rotate signing keys if compromised.",
		CWE:      "CWE-200",
	},
	{
		Name:     "aws_access_key",
		Pattern:  regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
		Severity: models.SeverityCritical,
		Title:    "AWS access key exposed in API response",
		Fix:      "Rotate the exposed AWS access key immediately and remove it from the response.",
		CWE:      "CWE-200",
	},
	{
		Name:     "pem_private_key",
		Pattern:  regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`),
		Severity: models.SeverityCritical,
		Title:    "Private key exposed in API response",
		Fix:      "Remove the private key from the response and rotate it immediately.",
		CWE:      "CWE-200",
	},
	{
		Name: "stack_trace",
		// 4.14: real stack frame (dotted path + file.ext:line) OR a known
		// framing marker. Tightened from the old "at IDENT(...)" which FP'd
		// on prose like "at home (today)".
		Pattern:  regexp.MustCompile(`(?:Traceback \(most recent call last\)|at [a-zA-Z0-9$_.<>]+\s*` + stackFrameLocRe + `|panic:|goroutine \d+|Exception in thread)`),
		Severity: models.SeverityMedium,
		Title:    "Stack trace in error response",
		Fix:      "Disable debug mode in production. Return generic error messages to clients.",
		CWE:      "CWE-209",
	},
	{
		Name: "internal_ip",
		// 4.14: \b-anchored with each octet constrained to 0-255 so it no
		// longer FPs on version strings ("10.20.30") or prices ("$192.168").
		Pattern:  regexp.MustCompile(`\b(?:10\.` + ipOctet + `\.` + ipOctet + `\.` + ipOctet + `|172\.(?:1[6-9]|2\d|3[01])\.` + ipOctet + `\.` + ipOctet + `|192\.168\.` + ipOctet + `\.` + ipOctet + `)\b`),
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

// ipOctet matches a single dotted-quad octet constrained to 0-255.
const ipOctet = `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`

// maskCharsRe matches a value that is composed entirely of a single
// masking character class (*, x/X, bullet, #), used by passwordNotMasked.
var maskCharsRe = regexp.MustCompile(`^(?:\*+|[xX]+|\x{2022}+|#+)$`)

// placeholderValues are well-known non-secret stand-ins.
var placeholderValues = map[string]struct{}{
	"redacted": {}, "hidden": {}, "null": {}, "not-set": {},
	"notset": {}, "changeme": {}, "***": {}, "n/a": {}, "none": {},
}

// passwordNotMasked vets a `"password":"..."` match: returns false (drop
// the finding) when the captured value is empty, an all-mask string, or
// a known placeholder. 4.12.
func passwordNotMasked(match []byte) bool {
	sub := passwordValueRe.FindSubmatch(match)
	if sub == nil || len(sub) < 2 {
		return true // shouldn't happen; fail open (keep the match)
	}
	val := strings.TrimSpace(string(sub[1]))
	if val == "" {
		return false
	}
	if maskCharsRe.MatchString(val) {
		return false
	}
	if _, ok := placeholderValues[strings.ToLower(val)]; ok {
		return false
	}
	return true
}

// passwordValueRe re-extracts the password value from an already-matched
// password_field byte slice so the guard can inspect just the value.
var passwordValueRe = regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]*)"`)

// exposureCheck implements the Check interface for the response-body
// sensitive-data scanner. Structural adapter — Run holds the unchanged
// body of the historical CheckExposure free function.
type exposureCheck struct{}

func (exposureCheck) Name() string                        { return "exposure" }
func (exposureCheck) Category() string                    { return "data_exposure" }
func (exposureCheck) Tier() Tier                          { return TierPassive }
func (exposureCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckExposure scans response bodies for sensitive data patterns.
func CheckExposure(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	return exposureCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged data-exposure detection body. Outbound
// requests go through the shared SSRF-guarded follow-redirect client
// (cc.Client); the per-job deadline comes from ctx (runCheck).
func (exposureCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []models.Finding {
	cfg := cc.Cfg
	client := cc.Client

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("exposure", "exposure check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}

	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("exposure", "exposure check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		logagg.Warn("exposure", "exposure check: failed to read body", "url", endpoint.FullURL, "error", err)
		return nil
	}

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	var findings []models.Finding

	for _, pat := range exposurePatterns {
		match := pat.Pattern.Find(body)
		if match != nil {
			// 4.12: optional guard can veto a match (e.g. masked password).
			if pat.Guard != nil && !pat.Guard(match) {
				continue
			}
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
