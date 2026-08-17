package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoad_NilOnEmptyPath(t *testing.T) {
	p, err := Load("")
	if err != nil {
		t.Fatalf("Load(''): %v", err)
	}
	if p != nil {
		t.Errorf("expected nil policy on empty path, got %+v", p)
	}
}

func TestLoad_NilOnMissingFile(t *testing.T) {
	// Missing file is not an error — caller passed --config explicitly
	// or fell through to DefaultPath. Either way: no policy means use
	// CLI defaults.
	p, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if p != nil {
		t.Errorf("expected nil policy on missing file, got %+v", p)
	}
}

func TestLoad_FullSchema(t *testing.T) {
	yaml := `version: 1
fail_on: HIGH
ignore_path: .fendix-ignore
scan:
  enable_active: true
  workers: 32
  timeout: 20
  delay_ms: 50
  format: sarif
crawler:
  crawl_depth: 2
  max_endpoints: 1000
  wordlist_path: ./wordlists/big.txt
  respect_robots: true
budgets:
  max_requests: 5000
  max_duration: 5m
auth:
  profile: production
`
	path := writeFile(t, t.TempDir(), "policy.yaml", yaml)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
	if p.Version != 1 {
		t.Errorf("Version = %d, want 1", p.Version)
	}
	if p.FailOn != "HIGH" {
		t.Errorf("FailOn = %q, want HIGH", p.FailOn)
	}
	if p.IgnorePath != ".fendix-ignore" {
		t.Errorf("IgnorePath mismatch: %q", p.IgnorePath)
	}
	if p.Scan == nil || p.Scan.EnableActive == nil || *p.Scan.EnableActive != true {
		t.Errorf("Scan.EnableActive not parsed: %+v", p.Scan)
	}
	if p.Scan.Workers == nil || *p.Scan.Workers != 32 {
		t.Errorf("Scan.Workers mismatch")
	}
	if p.Crawler == nil || p.Crawler.CrawlDepth == nil || *p.Crawler.CrawlDepth != 2 {
		t.Errorf("Crawler.CrawlDepth mismatch: %+v", p.Crawler)
	}
	if p.Crawler.WordlistPath != "./wordlists/big.txt" {
		t.Errorf("WordlistPath mismatch: %q", p.Crawler.WordlistPath)
	}
	if p.Budgets == nil || p.Budgets.MaxRequests == nil || *p.Budgets.MaxRequests != 5000 {
		t.Errorf("Budgets.MaxRequests mismatch: %+v", p.Budgets)
	}
	if p.Budgets.MaxDuration == nil || *p.Budgets.MaxDuration != 5*time.Minute {
		t.Errorf("Budgets.MaxDuration mismatch: %v", p.Budgets.MaxDuration)
	}
	if p.Auth == nil || p.Auth.Profile != "production" {
		t.Errorf("Auth.Profile mismatch: %+v", p.Auth)
	}
}

func TestLoad_MissingVersion(t *testing.T) {
	path := writeFile(t, t.TempDir(), "policy.yaml", "fail_on: HIGH\n")
	_, err := Load(path)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion on missing version, got %v", err)
	}
}

func TestLoad_FutureVersion(t *testing.T) {
	path := writeFile(t, t.TempDir(), "policy.yaml", "version: 99\nfail_on: HIGH\n")
	_, err := Load(path)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion on future version, got %v", err)
	}
}

func TestLoad_InvalidFailOn(t *testing.T) {
	path := writeFile(t, t.TempDir(), "policy.yaml", "version: 1\nfail_on: SUPER_CRITICAL\n")
	_, err := Load(path)
	if !errors.Is(err, ErrInvalidFailOn) {
		t.Fatalf("expected ErrInvalidFailOn, got %v", err)
	}
}

func TestLoad_UnknownFieldRejected(t *testing.T) {
	// KnownFields(true) catches typos that would otherwise silently
	// be ignored — most common cause of "I set this but it didn't take".
	path := writeFile(t, t.TempDir(), "policy.yaml", "version: 1\nfial_on: HIGH\n")
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected error on unknown field 'fial_on'")
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	path := writeFile(t, t.TempDir(), "policy.yaml", "version: [not-a-number}}}")
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected error on malformed YAML")
	}
}

// captureSetters returns an ApplyTo whose setters record into the
// returned map for assertion.
func captureSetters(captured map[string]any) ApplyTo {
	return ApplyTo{
		SetFailOn:        func(v string) { captured["fail-on"] = v },
		SetEnableActive:  func(v bool) { captured["enable-active"] = v },
		SetWorkers:       func(v int) { captured["workers"] = v },
		SetTimeoutSec:    func(v int) { captured["timeout"] = v },
		SetDelayMs:       func(v int) { captured["delay"] = v },
		SetFormat:        func(v string) { captured["format"] = v },
		SetCrawlDepth:    func(v int) { captured["crawl-depth"] = v },
		SetMaxEndpoints:  func(v int) { captured["max-endpoints"] = v },
		SetWordlistPath:  func(v string) { captured["wordlist"] = v },
		SetRespectRobots: func(v bool) { captured["respect-robots"] = v },
		SetMaxRequests:   func(v int64) { captured["max-requests"] = v },
		SetMaxDuration:   func(v time.Duration) { captured["max-duration"] = v },
		SetIgnorePath:    func(v string) { captured["ignore"] = v },
		SetAuthProfile:   func(v string) { captured["profile"] = v },

		SetDeescalateTests: func(v bool) { captured["deescalate-tests"] = v },
	}
}

func TestApplyTo_NilPolicyIsNoOp(t *testing.T) {
	captured := map[string]any{}
	n := captureSetters(captured).Run(nil, nil)
	if n != 0 {
		t.Errorf("expected 0 fields applied for nil policy, got %d", n)
	}
	if len(captured) != 0 {
		t.Errorf("expected no setters called for nil policy, got %v", captured)
	}
}

func TestApplyTo_AllFieldsAppliedWhenNoCLIOverrides(t *testing.T) {
	enable := true
	workers := 32
	timeout := 20
	delay := 50
	format := "sarif"
	depth := 2
	maxEP := 1000
	respect := true
	maxReq := int64(5000)
	maxDur := 5 * time.Minute
	p := &Policy{
		Version:    1,
		FailOn:     "HIGH",
		IgnorePath: ".fendix-ignore",
		Scan: &ScanSection{
			EnableActive: &enable,
			Workers:      &workers,
			TimeoutSec:   &timeout,
			DelayMs:      &delay,
			Format:       &format,
		},
		Crawler: &CrawlerSection{
			CrawlDepth:    &depth,
			MaxEndpoints:  &maxEP,
			WordlistPath:  "/tmp/words.txt",
			RespectRobots: &respect,
		},
		Budgets: &BudgetsSection{
			MaxRequests: &maxReq,
			MaxDuration: &maxDur,
		},
		Auth: &AuthSection{Profile: "production"},
	}
	captured := map[string]any{}
	n := captureSetters(captured).Run(p, nil)
	if n != 14 {
		t.Errorf("expected 14 fields applied, got %d (captured: %v)", n, captured)
	}
	if captured["fail-on"] != "HIGH" {
		t.Errorf("fail-on not applied")
	}
	if captured["enable-active"] != true {
		t.Errorf("enable-active not applied")
	}
	if captured["max-duration"] != 5*time.Minute {
		t.Errorf("max-duration not applied")
	}
}

func TestApplyTo_CLIOverridesPolicyForExplicitlySetFlags(t *testing.T) {
	enable := true
	workers := 32
	p := &Policy{
		Version: 1,
		FailOn:  "HIGH",
		Scan: &ScanSection{
			EnableActive: &enable,
			Workers:      &workers,
		},
	}
	cli := CLISet{
		"fail-on":       true, // user passed --fail-on
		"enable-active": true, // user passed --enable-active=false
	}
	captured := map[string]any{}
	n := captureSetters(captured).Run(p, cli)
	// fail-on and enable-active should be skipped (user CLI wins);
	// workers should still be applied.
	if n != 1 {
		t.Errorf("expected 1 field applied, got %d (captured: %v)", n, captured)
	}
	if _, ok := captured["fail-on"]; ok {
		t.Errorf("fail-on should be CLI-overridden, but setter was called")
	}
	if _, ok := captured["enable-active"]; ok {
		t.Errorf("enable-active should be CLI-overridden, but setter was called")
	}
	if captured["workers"] != 32 {
		t.Errorf("workers should still apply (no CLI override)")
	}
}

func TestApplyTo_NilSetterSkipsField(t *testing.T) {
	// SetWorkers is nil → workers field is silently skipped (not
	// counted toward the applied total). Lets callers exercise only
	// the subset of fields they care about.
	v := 32
	p := &Policy{Version: 1, Scan: &ScanSection{Workers: &v}}
	captured := map[string]any{}
	a := ApplyTo{
		SetWorkers: nil, // explicit
		SetFailOn:  captureSetters(captured).SetFailOn,
	}
	n := a.Run(p, nil)
	if n != 0 {
		t.Errorf("expected 0 fields applied (only SetWorkers wired and it's nil), got %d", n)
	}
}

func TestCLISet_NilHas(t *testing.T) {
	var s CLISet
	if s.Has("anything") {
		t.Errorf("nil CLISet should report no flags set")
	}
}

func TestValidate_EmptyOrNilPolicy(t *testing.T) {
	if err := (*Policy)(nil).Validate(); err != nil {
		t.Errorf("nil policy should validate clean, got %v", err)
	}
	if err := (&Policy{}).Validate(); err != nil {
		t.Errorf("empty policy should validate clean (fail_on='' is valid), got %v", err)
	}
}
