package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// configLeakPaths is the deny-list of paths whose 200-response means
// a config file was served by the live target. These are paths the
// crawler's wordlist (CommonPaths + .env-style brute-force) routinely
// discovers, and a non-404 response on any of them is a CRITICAL
// finding regardless of body content — the existence of a 200 is the
// vulnerability, not what the body contains.
//
// Keyed by basename + a few directory-prefix patterns (for .git/* and
// .aws/* which exist as directories with multiple sensitive files).
// Match strategy in matchesConfigLeakPath:
//   - exact basename match (case-sensitive, since servers are typically
//     case-sensitive on POSIX)
//   - prefix match for the directory-style entries (".git/", ".aws/")
//
// TASK-133 / Phase 17d. Closes the inversion FP-CORPUS.md D2: today
// these paths produce noisy "missing CSP" / "no rate limiting" LOW
// findings; with this check they produce one CRITICAL "exposed config
// file" finding instead, and the existing dedup pass collapses the
// noisier per-path findings naturally because their (title, category,
// severity) tuple is shared across the affected paths.
var configLeakBasenames = map[string]string{
	// Environment / app config
	".env":             "Environment configuration file exposed",
	".env.local":       "Environment configuration file exposed",
	".env.production":  "Environment configuration file exposed",
	".env.development": "Environment configuration file exposed",
	".env.staging":     "Environment configuration file exposed",
	".env.backup":      "Environment configuration backup exposed",
	".envrc":           "direnv configuration file exposed",
	// Web-server config
	".htaccess":  "Apache .htaccess file exposed",
	".htpasswd":  "Apache .htpasswd credentials file exposed",
	"web.config": "IIS web.config file exposed",
	// Package-manager credentials
	".npmrc":        "npm authentication tokens exposed",
	".pypirc":       "PyPI authentication tokens exposed",
	".netrc":        "netrc credentials file exposed",
	"composer.lock": "PHP Composer lockfile exposed (lower risk; informational)",
	// CI / config-as-code that should be in source control, never on the live server
	".dockerenv":                  "Docker environment file exposed",
	"docker-compose.override.yml": "Docker Compose override file exposed",
	// Editor / IDE / OS leftovers
	".DS_Store": "macOS .DS_Store file exposed (directory listing leak)",
}

// configLeakPrefixes matches when the discovered path starts with the
// prefix — for directory-style leaks (the whole .git or .aws tree
// served by mis-aliased nginx locations).
var configLeakPrefixes = map[string]string{
	".git/":    "Git repository internals exposed",
	".aws/":    "AWS credentials directory exposed",
	".ssh/":    "SSH key directory exposed",
	".idea/":   "JetBrains IDE configuration exposed",
	".vscode/": "VSCode workspace configuration exposed",
}

// configLeakFix is the canonical remediation message — the response
// path doesn't matter; the fix is always the same.
const configLeakFix = "Remove this file from the public web root, OR configure the server (nginx/Apache/etc) to deny requests for hidden / config files. Rotate any credentials this file may have exposed."

// configLeakCheck implements the Check interface for the config-file
// leak detector. Structural adapter — Run holds the unchanged body of
// the historical CheckConfigLeak free function.
type configLeakCheck struct{}

func (configLeakCheck) Name() string                        { return "configleak" }
func (configLeakCheck) Category() string                    { return "data_exposure" }
func (configLeakCheck) Tier() Tier                          { return TierPassive }
func (configLeakCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckConfigLeak hits the endpoint and emits a CRITICAL "exposed
// config file" finding when (a) the endpoint's path matches a known
// config-file leak pattern AND (b) the response is 200-series (the
// server is actually serving the file).
//
// Cheap to run — single HEAD-style GET, no probes, no body parse
// beyond a length check. Designed to slot into the worker pool as the
// first check so noisier downstream checks (headers / cors /
// ratelimit) can be deduped naturally by the existing pipeline when
// they fire on the same path.
func CheckConfigLeak(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	return configLeakCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged config-leak detection body. Outbound requests
// go through the shared SSRF-guarded follow-redirect client (cc.Client);
// the per-job deadline comes from ctx (runCheck).
func (configLeakCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []models.Finding {
	cfg := cc.Cfg
	if endpoint.FullURL == "" {
		return nil
	}
	leakPath, title, ok := matchesConfigLeakPath(endpoint.Path)
	if !ok {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("configleak", "configleak request build failed", "endpoint", endpoint.FullURL, "err", err)
		return nil
	}
	if cfg != nil && cfg.Auth != nil {
		cfg.Auth.ApplyToRequest(req)
	}

	client := cc.Client

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("configleak", "configleak request failed", "endpoint", endpoint.FullURL, "err", err)
		return nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Only 2xx is a leak. 3xx / 4xx / 5xx all mean the server isn't
	// serving the file (redirect to login, blocked, etc.).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	// 4.15: DO NOT capture the served-file body in evidence. The 200
	// status + path is sufficient proof of the leak, and persisting a
	// leaked secret-file body into a finding is itself a leak (and the
	// hand-rolled redactor was broken for JSON / compound .env keys).
	// We measure the body length (bounded read) for a size descriptor
	// only — the bytes are discarded, never stored.
	const bodyLenCap = 1 << 20 // 1 MiB ceiling for the size probe
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, bodyLenCap))

	line := endpoint.Path
	return []models.Finding{{
		Title:      title,
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Category:   "data_exposure",
		Endpoint:   endpoint.Path,
		Evidence:   fmt.Sprintf("HTTP %d on %s (config file served; body %d bytes, not captured)", resp.StatusCode, leakPath, n),
		Fix:        configLeakFix,
		References: []string{"CWE-538"}, // Insertion of Sensitive Information into Externally-Accessible File
		Confidence: models.ConfidenceHigh,
		Line:       &line,
	}}
}

// matchesConfigLeakPath inspects endpointPath for any known leak
// pattern. Returns (canonical-leak-path, finding-title, true) when
// matched.
//
// Lookup order: basename exact match → prefix match. Lookup is
// case-sensitive (matches typical POSIX server behaviour); leading
// slashes, query strings, and HTTP-method prefixes are normalised
// away before matching.
func matchesConfigLeakPath(endpointPath string) (string, string, bool) {
	cleaned := normalizeForConfigLeak(endpointPath)
	if cleaned == "" {
		return "", "", false
	}

	base := path.Base(cleaned)
	if title, ok := configLeakBasenames[base]; ok {
		return cleaned, title, true
	}

	// Prefix match — strip leading "/" for comparison.
	trimmed := strings.TrimPrefix(cleaned, "/")
	for prefix, title := range configLeakPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return cleaned, title, true
		}
	}
	return "", "", false
}

// normalizeForConfigLeak strips method prefix, query string,
// fragment, and any trailing slashes from an Endpoint.Path before we
// inspect it. Doesn't validate; just normalises.
func normalizeForConfigLeak(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// "GET /foo" → "/foo"
	for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		if strings.HasPrefix(p, method) {
			p = strings.TrimSpace(strings.TrimPrefix(p, method))
			break
		}
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}
