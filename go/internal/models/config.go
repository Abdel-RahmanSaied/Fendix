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
}
