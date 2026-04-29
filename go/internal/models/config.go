package models

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
	Workers      int
	Timeout      int
	DelayMs      int
	Checks       []string
	Verbose      bool
	IgnorePath   string
	BaselinePath     string
	SaveBaselinePath string
	OutputPath       string
	Format       string
	FailOn       string
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
}
