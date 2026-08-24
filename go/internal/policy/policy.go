// Package policy loads `.fendix.yaml` — the repo-committable policy
// file that lets AppSec teams pin Fendix's scan behavior in source
// control instead of via a long shell-script of CLI flags.
//
// Precedence (lowest to highest):
//
//  1. Cobra defaults (e.g. workers=10).
//  2. Policy file values (set on Apply when the user did NOT pass
//     the corresponding CLI flag).
//  3. Explicit CLI flags (override policy file when present).
//
// The policy file is intentionally a STRICT subset of the scan-flag
// surface: only the values teams reasonably want to commit are
// reflected here. One-shot flags like `--baseline`, `--save-baseline`,
// `--debug-bundle` are intentionally NOT in the schema — those are
// per-invocation runtime knobs, not policy.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the canonical filename. Looked up from the scan
// command's working directory when --config is not passed and the
// file exists.
const DefaultPath = ".fendix.yaml"

// SupportedVersion is the policy-schema version this build understands.
// Newer files will be rejected to surface the upgrade requirement
// loudly rather than silently ignoring fields the binary doesn't know.
const SupportedVersion = 1

// Errors from the policy layer.
var (
	ErrUnsupportedVersion = errors.New("policy file version is not supported by this fendix build")
	ErrInvalidFailOn      = errors.New("policy.fail_on must be CRITICAL, HIGH, MEDIUM, LOW, or empty")
)

// Policy is the parsed `.fendix.yaml`. Pointer fields distinguish
// "explicitly set in the file" from "absent" — Apply only writes a
// value to ScanConfig when the field is present in the file AND the
// user didn't pass the corresponding CLI flag.
type Policy struct {
	Version int    `yaml:"version"`
	FailOn  string `yaml:"fail_on,omitempty"`

	Scan    *ScanSection    `yaml:"scan,omitempty"`
	Crawler *CrawlerSection `yaml:"crawler,omitempty"`
	Budgets *BudgetsSection `yaml:"budgets,omitempty"`
	Auth    *AuthSection    `yaml:"auth,omitempty"`

	// IgnorePath maps to the `--ignore` CLI flag; teams typically
	// commit a `.fendix-ignore` alongside `.fendix.yaml` and want the
	// path explicit in the policy.
	IgnorePath string `yaml:"ignore_path,omitempty"`
}

// ScanSection mirrors the scan-runtime knobs that make sense to
// commit. enable_active is a deliberate inclusion: teams that *want*
// active probing in CI shouldn't have to remember the flag every
// time. Per the safety contract, --enable-active still requires an
// explicit user/policy opt-in (default false).
type ScanSection struct {
	EnableActive *bool   `yaml:"enable_active,omitempty"`
	Workers      *int    `yaml:"workers,omitempty"`
	TimeoutSec   *int    `yaml:"timeout,omitempty"`
	DelayMs      *int    `yaml:"delay_ms,omitempty"`
	Format       *string `yaml:"format,omitempty"`
	// DeescalateTests reports findings in test/fixture code as INFO rather
	// than WARN (v1.1 B3). Committable because "do we gate on test-code
	// findings?" is a team triage policy, not a per-invocation knob. Defaults
	// to the CLI default (true) when absent.
	DeescalateTests *bool `yaml:"deescalate_tests,omitempty"`
	// EnforceConfidence gates --fail-on on the deterministic confidence band
	// (v1.2.2 FIX-08). Committable for the same reason deescalate_tests is:
	// "how much corroboration do we demand before failing a build?" is a team
	// triage policy, not a per-invocation knob. Defaults to the CLI default
	// (true) when absent.
	EnforceConfidence *bool `yaml:"enforce_confidence,omitempty"`
}

// CrawlerSection covers endpoint discovery knobs that affect the scan
// surface and reliability. WordlistPath is a string (no pointer) — an
// empty path means "use the built-in CommonPaths" which matches the
// CLI flag's default behavior.
type CrawlerSection struct {
	CrawlDepth    *int   `yaml:"crawl_depth,omitempty"`
	MaxEndpoints  *int   `yaml:"max_endpoints,omitempty"`
	WordlistPath  string `yaml:"wordlist_path,omitempty"`
	RespectRobots *bool  `yaml:"respect_robots,omitempty"`
}

// BudgetsSection covers the global request/duration soft caps from
// TASK-095. Teams gate CI runs on these to keep scan cost predictable.
type BudgetsSection struct {
	MaxRequests *int64         `yaml:"max_requests,omitempty"`
	MaxDuration *time.Duration `yaml:"max_duration,omitempty"`
}

// AuthSection points at a profile in ~/.fendix/profiles/. The literal
// secret value is intentionally NOT a field — committable policy must
// not contain credentials. A `profile` reference is fine because it
// expands at scan time against the user's local profiles dir.
type AuthSection struct {
	Profile string `yaml:"profile,omitempty"`
}

// Load reads and parses a policy file. Returns nil if path is empty
// or the file does not exist (the latter is only an error when the
// caller passed --config explicitly; that condition is the caller's
// responsibility to surface). Returns ErrUnsupportedVersion when the
// file's version is greater than SupportedVersion or missing.
func Load(path string) (*Policy, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // surface typos / unknown fields loudly
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if p.Version <= 0 {
		return nil, fmt.Errorf("%w: %s missing required `version: 1` line", ErrUnsupportedVersion, path)
	}
	if p.Version > SupportedVersion {
		return nil, fmt.Errorf("%w: %s declares version %d but this fendix build supports up to version %d", ErrUnsupportedVersion, path, p.Version, SupportedVersion)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return &p, nil
}

// Validate reports schema-level errors. Called by Load; exposed for
// tests and for the (future) `fendix validate-policy` subcommand.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	switch p.FailOn {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW":
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidFailOn, p.FailOn)
	}
	return nil
}

// CLISet declares which CLI flag names the user passed explicitly.
// Apply only writes a policy value to a ScanConfig field when the
// matching CLI flag is NOT in this set — that's how CLI overrides
// policy. Pass cobra's flag.Changed() result for each flag name.
type CLISet map[string]bool

// Has reports whether the named flag was explicitly set on the CLI.
// Nil-safe: a nil CLISet is treated as "no flags explicitly set",
// which makes the Policy fully apply (useful in tests).
func (s CLISet) Has(name string) bool {
	if s == nil {
		return false
	}
	return s[name]
}

// ApplyTo writes the policy onto a ScanConfig-shaped target via a
// small per-field setter callback bag. The callbacks live in the
// scan command (or wherever ScanConfig is defined) so this package
// has no compile-time coupling to internal/models. Each setter is
// only invoked when the policy field is present AND the corresponding
// CLI flag is NOT in `cli`. Returns the number of fields written.
//
// Setter callbacks are nil-safe — pass nil to skip a field (useful
// in tests that exercise only a subset of the schema).
type ApplyTo struct {
	SetFailOn        func(string)
	SetEnableActive  func(bool)
	SetWorkers       func(int)
	SetTimeoutSec    func(int)
	SetDelayMs       func(int)
	SetFormat        func(string)
	SetCrawlDepth    func(int)
	SetMaxEndpoints  func(int)
	SetWordlistPath  func(string)
	SetRespectRobots func(bool)
	SetMaxRequests   func(int64)
	SetMaxDuration   func(time.Duration)
	SetIgnorePath    func(string)
	SetAuthProfile   func(string)

	SetDeescalateTests   func(bool)
	SetEnforceConfidence func(bool)
}

// Run applies p onto target via the setter callbacks, respecting
// CLI overrides. Returns the count of fields written. p == nil is a
// no-op (returns 0).
func (a ApplyTo) Run(p *Policy, cli CLISet) int {
	if p == nil {
		return 0
	}
	n := 0
	apply := func(flag string, fn func()) {
		if cli.Has(flag) {
			return
		}
		fn()
		n++
	}
	if p.FailOn != "" && a.SetFailOn != nil {
		apply("fail-on", func() { a.SetFailOn(p.FailOn) })
	}
	if p.IgnorePath != "" && a.SetIgnorePath != nil {
		apply("ignore", func() { a.SetIgnorePath(p.IgnorePath) })
	}
	if p.Scan != nil {
		s := p.Scan
		if s.EnableActive != nil && a.SetEnableActive != nil {
			apply("enable-active", func() { a.SetEnableActive(*s.EnableActive) })
		}
		if s.Workers != nil && a.SetWorkers != nil {
			apply("workers", func() { a.SetWorkers(*s.Workers) })
		}
		if s.TimeoutSec != nil && a.SetTimeoutSec != nil {
			apply("timeout", func() { a.SetTimeoutSec(*s.TimeoutSec) })
		}
		if s.DelayMs != nil && a.SetDelayMs != nil {
			apply("delay", func() { a.SetDelayMs(*s.DelayMs) })
		}
		if s.Format != nil && a.SetFormat != nil {
			apply("format", func() { a.SetFormat(*s.Format) })
		}
		if s.DeescalateTests != nil && a.SetDeescalateTests != nil {
			apply("deescalate-tests", func() { a.SetDeescalateTests(*s.DeescalateTests) })
		}
		if s.EnforceConfidence != nil && a.SetEnforceConfidence != nil {
			apply("enforce-confidence", func() { a.SetEnforceConfidence(*s.EnforceConfidence) })
		}
	}
	if p.Crawler != nil {
		c := p.Crawler
		if c.CrawlDepth != nil && a.SetCrawlDepth != nil {
			apply("crawl-depth", func() { a.SetCrawlDepth(*c.CrawlDepth) })
		}
		if c.MaxEndpoints != nil && a.SetMaxEndpoints != nil {
			apply("max-endpoints", func() { a.SetMaxEndpoints(*c.MaxEndpoints) })
		}
		if c.WordlistPath != "" && a.SetWordlistPath != nil {
			apply("wordlist", func() { a.SetWordlistPath(c.WordlistPath) })
		}
		if c.RespectRobots != nil && a.SetRespectRobots != nil {
			apply("respect-robots", func() { a.SetRespectRobots(*c.RespectRobots) })
		}
	}
	if p.Budgets != nil {
		b := p.Budgets
		if b.MaxRequests != nil && a.SetMaxRequests != nil {
			apply("max-requests", func() { a.SetMaxRequests(*b.MaxRequests) })
		}
		if b.MaxDuration != nil && a.SetMaxDuration != nil {
			apply("max-duration", func() { a.SetMaxDuration(*b.MaxDuration) })
		}
	}
	if p.Auth != nil && p.Auth.Profile != "" && a.SetAuthProfile != nil {
		apply("profile", func() { a.SetAuthProfile(p.Auth.Profile) })
	}
	return n
}
