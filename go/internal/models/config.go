package models

import "time"

// AuthContext holds authentication credentials for scan requests.
// Credentials are masked as [REDACTED] in all report output.
type AuthContext struct {
	Type   string // bearer | apikey | basic | cookie
	Value  string
	Header string // default: Authorization
}

// ScanConfig holds all configuration for a scan run.
// It is populated from CLI flags and passed to the orchestrator.
type ScanConfig struct {
	URL          string
	SpecPath     string
	CodePath     string
	Auth         *AuthContext
	AuthUser2    *AuthContext
	EnableActive bool
	// MaxProbesPerEndpoint caps the number of active probes sent to a single
	// endpoint. Zero means "use the scanner's default" (currently 20).
	MaxProbesPerEndpoint int
	Workers              int
	Timeout              int
	DelayMs              int
	Checks               []string
	Verbose              bool
	IgnorePath           string
	BaselinePath         string
	SaveBaselinePath     string
	OutputPath           string
	Format               string
	FailOn               string
	// WordlistPath overrides the built-in CommonPaths brute-force list.
	// Plain text, one path per line; lines starting with `#` and blank lines
	// are ignored; a leading `/` is added if missing.
	WordlistPath string
	// CrawlDepth controls recursive HTML link following from --url.
	// 0 disables HTML crawl; 1 (default) follows links from the home page.
	// Values >1 follow links from those pages too. Same-host only; visited
	// set prevents loops; --max-endpoints caps total discovery.
	CrawlDepth int
	// MaxEndpoints caps the total endpoint count after dedupe. 0 means
	// "no cap"; default is 500. Prevents runaway scans on large sites.
	MaxEndpoints int
	// MaxRequests caps the total HTTP request count across all checks for
	// the entire scan. 0 (default) means "no cap". When the cap is hit, the
	// scan soft-stops: in-flight requests finish, no new jobs are scheduled,
	// and the orchestrator emits a `budget summary` line with sent/rejected
	// counts. Enforced by an http.RoundTripper wrapper plus a worker-pool
	// ctx cancel; see internal/budget.
	MaxRequests int64
	// MaxDuration is the hard upper bound on scan wall-clock time. 0
	// (default) means "no cap". When set, the orchestrator wraps the run
	// context with `context.WithTimeout(parent, MaxDuration)`; deadline
	// expiry triggers the same soft-stop path as MaxRequests.
	MaxDuration time.Duration
	// RespectRobots controls how robots.txt Disallow directives are
	// interpreted. Default false: disallowed paths are queued as endpoint
	// hints (the security-tool default — those paths are exactly the URLs
	// operators don't want exposed). When true: disallowed paths are
	// filtered out of the discovered endpoint list, matching the
	// polite-crawler convention required for scanning third-party
	// production targets.
	RespectRobots bool
	// DebugBundlePath, when set, writes a redacted .tar.gz at scan end
	// containing the scan config (auth values masked), environment
	// versions, probe audit log, buffered DEBUG slog stream, and findings.
	// Empty disables the bundle. See internal/diagnostic.
	DebugBundlePath string
	// NoPlugins disables out-of-tree plugin discovery and execution
	// (TASK-113). When false (default), the orchestrator walks
	// .fendix/plugins/ + ~/.fendix/plugins/ after the embedded
	// blackbox/whitebox checks and feeds plugin findings through the
	// same correlation/dedup pipeline.
	NoPlugins bool
	// NoNativeDeps disables the in-process Go dep-CVE scanner
	// (TASK-119 / internal/scanner/deps/govulncheck). When false
	// (default), the orchestrator runs the native scanner against any
	// go.mod found under CodePath before spawning the Python whitebox
	// engine; native findings flow through the same dedup pipeline so
	// the transitional Python deps.py output collapses into one entry
	// per OSV. Set true to skip the native path (debugging, or when
	// the vuln DB is unreachable and the Python fallback is preferred).
	NoNativeDeps bool
	// UsePipAudit, when true, makes the Python dep-CVE pass shell out
	// to the pip-audit binary instead of using the native OSV.dev
	// /v1/query client. Falls back to OSV.dev with a stderr warning
	// if pip-audit is not on PATH (never fails-closed silently).
	// Surfaced by Sprint 01 of the enterprise-readiness plan to close
	// the audit's §15.5 trust gap (pip-audit naming vs. implementation).
	UsePipAudit bool
	// PythonEngine opts in to spawning the Python whitebox engine
	// (TASK-118). Default false — Phase 17b moved the secrets and
	// semgrep checks to native Go (TASK-115/TASK-116) and dropped the
	// embedded Python distribution from the binary, so the default
	// scan path is Python-free. Set true to re-enable the auth /
	// injection / deps Python checks; requires either a local
	// `python/` source tree or an explicit FENDIX_ENGINE env var
	// pointing at one (the binary no longer carries an embedded copy).
	PythonEngine bool

	// Lang controls the HTML reporter's language (Sprint 10). Today's
	// values: "en" (default) and "ar". Other formats (JSON, SARIF) stay
	// English because they're machine-consumed. Unknown values fall
	// back to English at render time; the CLI wrapper warns when a
	// passed --lang isn't a supported translation.
	Lang string
	// AllowPrivate disables the SSRF egress guard (internal/netguard) so the
	// scanner may connect to private/loopback/link-local addresses and the
	// cloud metadata IP. Default false: those addresses are refused at dial
	// time (anti-SSRF / anti-DNS-rebinding) and redirects into them are
	// re-blocked per hop. The scan command sets this from
	// --allow-private-targets and auto-enables it when the operator's own
	// --url target already resolves to a private/loopback IP (scanning your
	// own internal/staging/localhost target must keep working).
	AllowPrivate bool
}
