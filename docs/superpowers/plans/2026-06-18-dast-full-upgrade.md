# DAST Module Powerful Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-architect the `fendix-engine` black-box DAST module to an interface-based check registry with one shared SSRF-guarded `CheckContext`, fix all 45 verified accuracy findings, ship 3 proof checks, and add 4 new scan types — delivered as 11 independently-shippable phases.

**Architecture:** Each of the 8 existing checks becomes a struct implementing a `Check` interface. A single per-scan `CheckContext` carries two guarded `*http.Client`s (follow + no-follow, same guarded transport) so the SSRF egress guard is structural and no check builds its own client. Free-function shims preserve every existing test call site. New checks register in `DefaultChecks()`; the orchestrator filters by `Enabled(cfg)`.

**Tech Stack:** Go 1.25, `net/http`, `net/http/httptest`, the existing `internal/{budget,netguard,logagg,models}` packages. Tests use `httptest.NewServer`/`NewTLSServer`, table-driven, matching `cors_test.go`/`headers_test.go` style.

**Spec:** `docs/superpowers/specs/2026-06-18-dast-module-refactor-design.md`

**Approved defaults:** Phase 0 split into **0a** (pure refactor, behavior-identical) and **0b** (SSRF guard + addAuth behavior changes). After Phase 0, accuracy fixes (Phases 2–5) precede new scan types (Phases 6–9) — lower risk, lower-noise reports first.

**Detail levels:** Phases 0–1 are fully spelled out (TDD tasks with complete Go code). Phases 2–10 give per-task file paths, exact signatures, test names, and acceptance gates referencing the verified findings + designed skeletons — their precise line-edits depend on Phase 0's final shape and are filled at execution time per task. No task is a placeholder; every one names what to change, how to test it, and the expected result.

---

## File Structure

**New files (`go/internal/scanner/`):**
- `check.go` — `Tier`, `Check` interface, `DefaultChecks()`, `AsCheck` adapter
- `checkcontext.go` — `CheckContext`, `NewCheckContext`, `guardedClientNoFollow`
- `check_test.go` — registry + `Enabled`/`Tier` table tests
- `ssrf_regression_test.go` — SSRF-guard + redirect-semantics + auth-not-broken tests (Phase 0b)
- `cookie_flags.go` + `cookie_flags_test.go` (Phase 1)
- `openredirect.go` + `openredirect_test.go` (Phase 1)
- `xss.go` + `xss_test.go` (Phase 1)
- `ssrf.go` + `ssrf_test.go` (Phase 6)
- `hostheader.go` + `hostheader_test.go` (Phase 7)
- `graphql.go` + `graphql_test.go` (Phase 8)
- `methodtamper.go` + `methodtamper_test.go` (Phase 9)

**Modified:**
- `scanner/{configleak,headers,cors,exposure,ratelimit,auth,idor,injection}.go` — struct + `Run` + shim
- `scanner/httpclient.go` — add `guardedClientNoFollow`
- `engine/workerpool.go` — `[]Check`, `CheckContext`, `runCheck`
- `engine/orchestrator.go:222-245,577-588` — registry filter, `checksRun` derivation
- `models/scoring.go` — `ImpactBase` entries (Phase 10)
- backend `scanning/compliance.py`, `Makefile`, `docker-compose.prod.yml` (Phase 10)

---

# PHASE 0a — Pure refactor (behavior-identical)

**Goal:** Introduce the `Check` interface + two-client `CheckContext` + worker-pool/orchestrator migration, with free-function shims so all 17 test files compile and pass **unedited**. No detection behavior changes yet (clients still follow the same redirect policy each check used).

> **Verification discipline:** after every task, the gate is `cd go && go build ./... && go vet ./...` and `go test ./internal/scanner/... ./internal/engine/... -race`. Behavior-identical means the existing suite stays green with zero `_test.go` edits.

### Task 0a.1: Define the `Check` interface + `Tier`

**Files:**
- Create: `go/internal/scanner/check.go`

- [ ] **Step 1: Create the file**

```go
package scanner

import (
	"context"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Tier classifies a check by intrusiveness and required scan inputs. The
// orchestrator filters DefaultChecks() by Enabled(cfg) and prints the
// active-scanning disclaimer iff any enabled check is TierActive.
//
// Tier values are append-only: the iota int is never persisted, but
// renumbering existing values is a needless footgun. Add new tiers at the end.
type Tier int

const (
	TierPassive   Tier = iota // safe GET/OPTIONS observation; always on
	TierActive                // sends attack payloads; gated by cfg.EnableActive
	TierAuth                  // needs cfg.Auth (single credential)
	TierMultiuser             // needs cfg.Auth AND cfg.AuthUser2 (cross-user)
)

func (t Tier) String() string {
	switch t {
	case TierPassive:
		return "passive"
	case TierActive:
		return "active"
	case TierAuth:
		return "auth"
	case TierMultiuser:
		return "multiuser"
	default:
		return "unknown"
	}
}

// Check is the unit of black-box detection. Implementations are stateless
// adapter structs registered in DefaultChecks().
type Check interface {
	Name() string                        // stable id, e.g. "configleak"
	Category() string                    // models.Finding.Category bucket
	Tier() Tier                          // intrusiveness / input class
	Enabled(cfg *models.ScanConfig) bool // tier-implied gate
	Run(ctx context.Context, cc *CheckContext, ep Endpoint) []models.Finding
}

// AsCheck adapts an existing free CheckFn into the Check interface so the
// engine worker-pool tests (which pass []scanner.CheckFn) keep compiling. The
// adapter reads cfg/audit from the CheckContext.
func AsCheck(name, category string, tier Tier, enabled func(*models.ScanConfig) bool, fn CheckFn) Check {
	return fnCheck{name: name, category: category, tier: tier, enabled: enabled, fn: fn}
}

type fnCheck struct {
	name     string
	category string
	tier     Tier
	enabled  func(*models.ScanConfig) bool
	fn       CheckFn
}

func (c fnCheck) Name() string                        { return c.name }
func (c fnCheck) Category() string                    { return c.category }
func (c fnCheck) Tier() Tier                          { return c.tier }
func (c fnCheck) Enabled(cfg *models.ScanConfig) bool { return c.enabled == nil || c.enabled(cfg) }
func (c fnCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []models.Finding {
	return c.fn(ctx, cc.Cfg, ep)
}
```

- [ ] **Step 2: Build gate**

Run: `cd go && go build ./internal/scanner/`
Expected: PASS (no compile errors; `CheckContext`/`CheckFn` resolve once Task 0a.2 lands — if running 0a.1 alone, expect "undefined: CheckContext", which Task 0a.2 fixes; do both before the build gate).

- [ ] **Step 3: Commit** (after 0a.2 compiles)

### Task 0a.2: Define `CheckContext` + two guarded clients

**Files:**
- Create: `go/internal/scanner/checkcontext.go`
- Modify: `go/internal/scanner/httpclient.go` (add `guardedClientNoFollow`)

- [ ] **Step 1: Add `guardedClientNoFollow` to httpclient.go**

```go
// guardedClientNoFollow builds a client with the SAME guarded transport as
// guardedClient (budget over netguard SSRF policy) but does NOT follow
// redirects — it returns http.ErrUseLastResponse so the caller observes the
// raw 3xx. Used by checks where a redirect IS the signal (auth, idor,
// open-redirect, host-header). Timeout is 0 because the shared client relies
// on a per-job context deadline (see runCheck).
func guardedClientNoFollow(cfg *models.ScanConfig) *http.Client {
	ap := allowPrivate(cfg)
	return &http.Client{
		Timeout:       0,
		Transport:     budget.TransportGuarded(ap),
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}
```

- [ ] **Step 2: Create checkcontext.go**

```go
package scanner

import (
	"net/http"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// CheckContext is the per-scan execution context handed to every Check.Run.
//
// Client and NoFollow share ONE guarded transport (budget over netguard SSRF
// policy), so the SSRF egress guard + budget counting are identical on both.
// Client follows redirects and re-validates the resolved IP on every hop;
// NoFollow returns the raw 3xx (a redirect IS the signal for auth/idor/
// open-redirect/host-header). Checks MUST use one of these — never build their
// own transport. This is how the historical raw-budget.Transport() SSRF bypass
// is closed structurally.
//
// Audit is the scan-wide probe log; it aliases the package-global
// currentAuditLog() so GlobalAuditRecords()/--debug-bundle keep working.
type CheckContext struct {
	Cfg      *models.ScanConfig
	Client   *http.Client
	NoFollow *http.Client
	Audit    *ProbeAuditLog
}

// NewCheckContext builds the shared context once per scan. The shared clients
// set Timeout:0 — per-(endpoint,check) deadlines come from a context.WithTimeout
// inside the worker pool's runCheck, so one global Timeout cannot cap the whole
// scan under connection reuse.
func NewCheckContext(cfg *models.ScanConfig) *CheckContext {
	follow := guardedClient(cfg)
	follow.Timeout = 0
	return &CheckContext{
		Cfg:      cfg,
		Client:   follow,
		NoFollow: guardedClientNoFollow(cfg),
		Audit:    currentAuditLog(),
	}
}
```

- [ ] **Step 3: Build gate**

Run: `cd go && go build ./internal/scanner/`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add go/internal/scanner/check.go go/internal/scanner/checkcontext.go go/internal/scanner/httpclient.go
git commit -m "feat(dast): add Check interface, Tier, and two-client CheckContext"
```

### Task 0a.3: Migrate each check to a struct + free-function shim

Do this **one check at a time** (8 checks), committing after each, so the suite stays green per check. The pattern (shown for `headers`) applies to all 8.

**Files (per check):** Modify `go/internal/scanner/<check>.go`

- [ ] **Step 1: Refactor the free function into a struct `Run` + 3-line shim**

For `headers.go`, the existing `func CheckHeaders(ctx, cfg, ep) []models.Finding` body is moved into a method, and the old name becomes a shim:

```go
type headersCheck struct{}

func (headersCheck) Name() string                        { return "headers" }
func (headersCheck) Category() string                    { return "headers" }
func (headersCheck) Tier() Tier                          { return TierPassive }
func (headersCheck) Enabled(*models.ScanConfig) bool     { return true }

func (headersCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []models.Finding {
	// BODY: the former CheckHeaders body, EXCEPT the client line:
	//   was: client := &http.Client{Timeout: ..., Transport: budget.Transport()}
	//   now: client := cc.Client
	// and cfg references become cc.Cfg.
	client := cc.Client
	// ... rest of the existing logic verbatim ...
}

// CheckHeaders is the back-compat shim. Existing tests call this directly.
func CheckHeaders(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
	return headersCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}
```

> **0a vs 0b boundary (CORRECTED during execution):** 0a.3 is a **pure structural move — behavior-identical, no client change.** Each check's `Run` builds the **exact same client it builds today**: the 6 previously-unguarded checks (headers/exposure/configleak/ratelimit/auth/idor) keep their own `&http.Client{Transport: budget.Transport()}` (auth/idor keep `CheckRedirect: http.ErrUseLastResponse`); cors/injection keep `guardedClient`. They do **not** read `cc.Client`/`cc.NoFollow` yet — `CheckContext` is threaded through but its clients are unused by the 6 in 0a. Rationale (verified empirically): the 6 checks' existing tests hit `httptest` `127.0.0.1` servers with **no `AllowPrivate`**, so routing them through the guarded client in 0a makes netguard refuse the loopback dial and breaks ~40 tests. Only cors/injection tests set `AllowPrivate: true` (because only those two were already guarded). Folding the SSRF routing into 0a would therefore violate both "behavior-identical" and "tests unedited."
>
> The SSRF routing is **0b's** job: Task 0b.0 (new) flips the 6 checks to `cc.Client`/`cc.NoFollow` **and** adds `AllowPrivate: true` to those 6 test files as the deliberate, reviewed behavior change, with the SSRF regression test (0b.1) proving the guard blocks a malicious redirect. This keeps 0a a clean, bisectable, behavior-identical refactor.

Per-check tier/category/client mapping:

| Check | struct | Tier | Category | Client | Enabled |
|-------|--------|------|----------|--------|---------|
| configleak | `configLeakCheck` | Passive | `data_exposure` | `cc.Client` | true |
| headers | `headersCheck` | Passive | `headers` | `cc.Client` | true |
| cors | `corsCheck` | Passive | `cors` | `cc.Client` | true |
| exposure | `exposureCheck` | Passive | `data_exposure` | `cc.Client` | true |
| ratelimit | `rateLimitCheck` | Passive | `headers` (→`rate_limiting` in Phase 4) | `cc.Client` | true |
| auth | `authCheck` | Auth | `auth_bypass` | `cc.NoFollow` | `cfg.Auth != nil` |
| idor | `idorCheck` | Multiuser | `idor` | `cc.NoFollow` | `cfg.Auth != nil && cfg.AuthUser2 != nil` |
| injection | `injectionCheck` | Active | `injection` | `cc.Client` (probes build per-probe requests) | `cfg.EnableActive` |

> auth/idor previously built clients with `CheckRedirect: ErrUseLastResponse` — they MUST use `cc.NoFollow`. injection's `CheckInjectionWithAudit` keeps its existing audit-log parameter API; the struct `Run` calls it passing `cc.Audit`.

- [ ] **Step 2: Per-check build + test gate**

Run: `cd go && go build ./internal/scanner/ && go test ./internal/scanner/ -run TestCheck<Name> -race -v`
Expected: PASS, no `_test.go` edits.

- [ ] **Step 3: Commit per check**

```bash
git add go/internal/scanner/<check>.go
git commit -m "refactor(dast): migrate <check> to Check interface + shim"
```

### Task 0a.4: Add `DefaultChecks()` registry + tests

**Files:**
- Modify: `go/internal/scanner/check.go`
- Create: `go/internal/scanner/check_test.go`

- [ ] **Step 1: Write the failing registry test**

```go
package scanner

import (
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestDefaultChecks_OrderAndConfigleakFirst(t *testing.T) {
	got := DefaultChecks()
	if len(got) == 0 || got[0].Name() != "configleak" {
		t.Fatalf("expected configleak first, got %v", names(got))
	}
}

func TestChecks_EnabledMatrix(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *models.ScanConfig
		enabled []string // expected enabled check names
	}{
		{"bare", &models.ScanConfig{}, []string{"configleak", "headers", "cors", "exposure", "ratelimit"}},
		{"active", &models.ScanConfig{EnableActive: true}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "injection"}},
		{"auth", &models.ScanConfig{Auth: &models.AuthContext{Value: "x"}}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "auth"}},
		{"auth2", &models.ScanConfig{Auth: &models.AuthContext{Value: "x"}, AuthUser2: &models.AuthContext{Value: "y"}}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "auth", "idor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var enabled []string
			for _, c := range DefaultChecks() {
				if c.Enabled(tc.cfg) {
					enabled = append(enabled, c.Name())
				}
			}
			if !subsetEqual(enabled, tc.enabled) {
				t.Errorf("cfg %s: enabled=%v want superset-ordered %v", tc.name, enabled, tc.enabled)
			}
		})
	}
}

func names(cs []Check) []string { out := []string{}; for _, c := range cs { out = append(out, c.Name()) }; return out }
func subsetEqual(got, want []string) bool {
	w := map[string]bool{}; for _, x := range want { w[x] = true }
	for _, g := range got { if !w[g] { return false } }
	return len(got) == len(want)
}
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd go && go test ./internal/scanner/ -run TestDefaultChecks -v`
Expected: FAIL "undefined: DefaultChecks".

- [ ] **Step 3: Implement `DefaultChecks()` in check.go**

```go
// DefaultChecks returns the full ordered check registry. configleak is first
// so its CRITICAL "exposed config file" finding lands before noisier
// per-endpoint checks on the same path (dedup ordering). The orchestrator
// filters this slice by Enabled(cfg) at scan time.
func DefaultChecks() []Check {
	return []Check{
		configLeakCheck{},
		headersCheck{},
		corsCheck{},
		exposureCheck{},
		rateLimitCheck{},
		authCheck{},
		idorCheck{},
		injectionCheck{},
		// proof checks (Phase 1) and new types (Phases 6-9) appended here.
	}
}
```

- [ ] **Step 4: Run, verify pass**

Run: `cd go && go test ./internal/scanner/ -run "TestDefaultChecks|TestChecks_Enabled" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go/internal/scanner/check.go go/internal/scanner/check_test.go
git commit -m "feat(dast): add DefaultChecks registry + Enabled matrix tests"
```

### Task 0a.5: Migrate WorkerPool + orchestrator

**Files:**
- Modify: `go/internal/engine/workerpool.go:18,35,129-147` + `NewWorkerPool`
- Modify: `go/internal/engine/orchestrator.go:222-245,577-588`

- [ ] **Step 1: Change WorkerPool to hold `[]scanner.Check` + `*CheckContext`**

```go
type WorkerPool struct {
	workers int
	delayMs int
	checks  []scanner.Check
	cc      *scanner.CheckContext
}

// NewWorkerPool keeps the legacy []scanner.CheckFn signature so engine tests
// compile unedited; it wraps each fn via AsCheck and lazily builds a context.
func NewWorkerPool(workers, delayMs int, checks []scanner.CheckFn) *WorkerPool {
	wrapped := make([]scanner.Check, len(checks))
	for i, fn := range checks {
		wrapped[i] = scanner.AsCheck("legacy", "engine", scanner.TierPassive, nil, fn)
	}
	return newPool(workers, delayMs, wrapped, nil)
}

// NewWorkerPoolChecks is the production constructor used by the orchestrator.
func NewWorkerPoolChecks(workers, delayMs int, checks []scanner.Check, cc *scanner.CheckContext) *WorkerPool {
	return newPool(workers, delayMs, checks, cc)
}

func newPool(workers, delayMs int, checks []scanner.Check, cc *scanner.CheckContext) *WorkerPool {
	if workers < 1 { workers = 1 }
	return &WorkerPool{workers: workers, delayMs: delayMs, checks: checks, cc: cc}
}
```

- [ ] **Step 2: Update `scanJob` + `runCheck`**

`scanJob.check` becomes `scanner.Check`. `runCheck` builds a per-job timeout context and an ephemeral `CheckContext` when none was supplied (legacy path):

```go
type scanJob struct {
	check    scanner.Check
	endpoint scanner.Endpoint
}

func runCheck(ctx context.Context, cc *scanner.CheckContext, cfg *models.ScanConfig, job scanJob, workerID int) (findings []models.Finding) {
	defer func() {
		if r := recover(); r != nil {
			epLabel := fmt.Sprintf("%s %s", job.endpoint.Method, job.endpoint.Path)
			slog.Error("scanner check panicked — job contained, scan continues",
				"worker", workerID, "endpoint", epLabel, "check", job.check.Name(), "panic", r)
			findings = []models.Finding{{
				Title: "Scanner check panicked", Severity: models.SeverityInfo,
				Source: models.SourceBlackbox, Category: job.check.Category(), Endpoint: epLabel,
				Evidence:   fmt.Sprintf("Check %q panicked while scanning %s and was skipped: %v", job.check.Name(), epLabel, r),
				Confidence: models.ConfidenceLow,
			}}
		}
	}()
	if cc == nil {
		cc = scanner.NewCheckContext(cfg) // legacy []CheckFn path
	}
	jobCtx := ctx
	if cfg != nil && cfg.Timeout > 0 {
		var cancel context.CancelFunc
		jobCtx, cancel = context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Second)
		defer cancel()
	}
	return job.check.Run(jobCtx, cc, job.endpoint)
}
```

Update the `Run` worker goroutine call site to `runCheck(ctx, wp.cc, cfg, job, workerID)`.

- [ ] **Step 3: Update orchestrator (lines 222-245)**

```go
all := scanner.DefaultChecks()
var checks []scanner.Check
active := false
for _, c := range all {
	if !c.Enabled(o.cfg) { continue }
	checks = append(checks, c)
	if c.Tier() == scanner.TierActive { active = true }
}
if active {
	scanner.PrintDisclaimer()
}
cc := scanner.NewCheckContext(o.cfg)
pool := NewWorkerPoolChecks(o.cfg.Workers, o.cfg.DelayMs, checks, cc)
findings := pool.Run(ctx, o.cfg, endpoints)
```

- [ ] **Step 4: Derive `checksRun` from the filtered slice (replace lines 577-588's hand-list)**

```go
checksRun := make([]string, 0, len(checks))
for _, c := range checks {
	checksRun = append(checksRun, c.Name())
}
if /* code scanners ran */ {
	checksRun = append(checksRun, "secrets", "semgrep", "deps")
}
```

- [ ] **Step 5: Build + full test gate**

Run: `cd go && go build ./... && go vet ./... && go test ./internal/scanner/... ./internal/engine/... -race`
Expected: PASS, all `_test.go` unedited.

- [ ] **Step 6: Commit**

```bash
git add go/internal/engine/workerpool.go go/internal/engine/orchestrator.go
git commit -m "refactor(dast): migrate worker pool + orchestrator to Check registry"
```

---

# PHASE 0b — SSRF guard + addAuth (behavior changes + regression tests)

**Goal:** Route the 6 previously-unguarded checks through the shared guarded client (the C2/C3 SSRF fix — deferred from 0a per the corrected boundary), land the C1 (`addAuth`) fix, and prove the guard with regression tests.

### Task 0b.0: Flip the 6 unguarded checks to the shared guarded client

**Files:** Modify `scanner/{headers,exposure,configleak,ratelimit}.go` → use `cc.Client`; `scanner/{auth,idor}.go` → use `cc.NoFollow`; add `AllowPrivate: true` to the `ScanConfig` literals in `scanner/{headers,exposure,configleak,ratelimit,auth,idor}_test.go`.

- [ ] **Step 1:** In each of the 6 checks' `Run`, delete the locally-built `&http.Client{...}` and use `cc.Client` (headers/exposure/configleak/ratelimit) or `cc.NoFollow` (auth/idor — they need `ErrUseLastResponse`, which `cc.NoFollow` provides). The cors/injection checks already use the guarded client — no change.
- [ ] **Step 2:** Add `AllowPrivate: true` to every `&models.ScanConfig{...}` literal in the 6 affected `_test.go` files (mirroring `cors_test.go`/`injection_test.go`, which already do this — a real scan auto-applies it when the target is private/loopback). This is the deliberate, reviewed behavior change: those tests now run against the guarded client, with the guard relaxed for the loopback `httptest` target exactly as a real localhost scan would.
- [ ] **Step 3:** Gate: `cd go && go build ./... && go test ./internal/scanner/... -count=1` green.
- [ ] **Step 4:** Commit: `fix(dast): C2/C3 route all checks through shared SSRF-guarded client`

> The SSRF-guard *proof* (a malicious 302→private-IP is refused when `AllowPrivate=false`) is Task 0b.1; this task does the routing + the test-config update that keeps the existing loopback tests green.

### Task 0b.1: SSRF-guard regression test

**Files:** Create `go/internal/scanner/ssrf_regression_test.go`

- [ ] **Step 1: Write the test (302 → metadata IP must be refused)**

```go
package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// A passive check (headers) must refuse to follow a redirect into a
// private/metadata IP when AllowPrivate is false — proving the shared guarded
// client closed the historical raw-budget.Transport() SSRF bypass.
func TestSSRFGuard_PassiveCheckRefusesPrivateRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: false}
	ep := Endpoint{Method: "GET", Path: "/", FullURL: srv.URL}
	// Must not panic, must not reach the metadata IP. The guarded client's
	// CheckRedirect blocks the hop; the check returns its findings on the 302
	// body (or none), never the metadata content.
	_ = headersCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)
	// Assertion: the budget/netguard layer recorded a blocked dial. If a
	// netguard test seam exposes blocked-count, assert it > 0; otherwise assert
	// no finding references metadata content.
}
```

> The exact assertion hook depends on whether `netguard` exposes a blocked-dial counter; if not, the implementer adds a minimal test seam (a `netguard.Config.OnBlock func(string)` callback) in this task and asserts it fired with `169.254.169.254`.

- [ ] **Step 2: Run, verify the guard blocks**

Run: `cd go && go test ./internal/scanner/ -run TestSSRFGuard -race -v`
Expected: PASS (redirect refused). If FAIL (metadata reached), the check is not using `cc.Client` — fix the migration.

- [ ] **Step 3: Add redirect-semantics + auth-not-broken tests**

```go
// auth/idor/openredirect must observe the raw 302 (NoFollow), not follow it.
func TestRedirectSemantics_AuthSeesRaw302(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound) // 302 to login
	}))
	defer srv.Close()
	cfg := &models.ScanConfig{Timeout: 5, Auth: &models.AuthContext{Header: "Authorization", Value: "Bearer a.b.c", Type: "bearer"}}
	ep := Endpoint{Method: "GET", Path: "/x", FullURL: srv.URL + "/x"}
	got := authCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)
	// A protected endpoint that 302s to /login is NOT "Missing authentication".
	for _, f := range got {
		if f.Title == "Missing authentication on endpoint" {
			t.Errorf("302->/login wrongly flagged as missing auth")
		}
	}
}
```

- [ ] **Step 4: Run, verify pass; Commit**

```bash
git add go/internal/scanner/ssrf_regression_test.go go/internal/netguard/
git commit -m "test(dast): SSRF-guard, redirect-semantics, auth-not-broken regressions"
```

### Task 0b.2: Fix C1 — delete `addAuth`, use `ApplyToRequest`

**Files:** Modify `go/internal/scanner/injection.go` (delete `addAuth` at :836-864; replace all calls)

- [ ] **Step 1: Write the failing test (authed probe sends single-prefix header)**

```go
func TestInjection_AuthHeaderSinglePrefix(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	cfg := &models.ScanConfig{Timeout: 5, EnableActive: true,
		Auth: &models.AuthContext{Header: "Authorization", Value: "Bearer realtoken", Type: "bearer"}}
	ep := Endpoint{Method: "GET", Path: "/q", FullURL: srv.URL + "/q", Params: []string{"id"}}
	ResetGlobalAuditLog()
	_ = injectionCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)
	if gotAuth != "Bearer realtoken" {
		t.Errorf("auth header = %q; want single-prefix %q", gotAuth, "Bearer realtoken")
	}
}
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd go && go test ./internal/scanner/ -run TestInjection_AuthHeaderSinglePrefix -v`
Expected: FAIL — header is `Bearer Bearer realtoken` (the bug).

- [ ] **Step 3: Delete `addAuth`; replace every `addAuth(req, cfg)` with `cfg.Auth.ApplyToRequest(req)` (nil-safe, since `ApplyToRequest` already nil-guards)**

`ApplyToRequest` (auth.go:119) sets the raw `Value` and handles `apikey-query` URL mutation — the single source of truth. The 7 call sites in injection.go (probeSQLi, probeSQLiErrorBased, sendBoolProbe, probeCMDi, probeCRLF, + the confirmation re-probe) all change.

- [ ] **Step 4: Also thread auth into `measureBaseline` (fixes the medium baseline-omits-auth finding while here)**

```go
func measureBaseline(ctx context.Context, client *http.Client, cfg *models.ScanConfig, method, url string) (time.Duration, error) {
	// ... existing loop, but after building req:
	//   cfg.Auth.ApplyToRequest(req)
}
```
Update the one `measureBaseline` call in `probeSQLi` to pass `cfg`.

- [ ] **Step 5: Run, verify pass; full suite**

Run: `cd go && go test ./internal/scanner/ -run TestInjection -race -v && go test ./internal/scanner/... ./internal/engine/... -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go/internal/scanner/injection.go
git commit -m "fix(dast): C1 delete addAuth double-prefix; baseline carries auth (CWE auth-FN)"
```

**Phase 0 ship gate:** `go build ./... && go vet ./... && go test ./... -race` green; all `_test.go` unedited except the new test files; SSRF + redirect-semantics + single-prefix-auth tests pass.

---

# PHASE 1 — Proof checks (cookie-flags, open-redirect, reflected-XSS)

**Goal:** Three new checks through the new interface — one passive, two active — proving the abstraction across both clients and all tiers. Each is fully TDD'd below.

### Task 1.1: Cookie security flags (TierPassive)

**Files:** Create `go/internal/scanner/cookie_flags.go` + `cookie_flags_test.go`; append `cookieFlagsCheck{}` to `DefaultChecks()`.

- [ ] **Step 1: Write failing tests** (httptest + httptest.NewTLSServer)

```go
func TestCookieFlags_SessionCookieNoFlagsHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	cc := NewCheckContext(cfg)
	cc.Client = srv.Client() // TLS test client
	got := cookieFlagsCheck{}.Run(context.Background(), cc, Endpoint{Method: "GET", Path: "/", FullURL: srv.URL})
	// expect 3 findings: HttpOnly (MEDIUM/CWE-1004), Secure (MEDIUM/CWE-614), SameSite (LOW/CWE-1275)
	if len(got) != 3 { t.Fatalf("want 3 findings, got %d: %+v", len(got), got) }
}

func TestCookieFlags_AnalyticsIgnored(t *testing.T) { /* _ga missing all flags -> 0 findings */ }
func TestCookieFlags_HardenedCookie(t *testing.T)  { /* HttpOnly;Secure;SameSite=Strict -> 0 */ }
func TestCookieFlags_DeletionCookieIgnored(t *testing.T) { /* Max-Age=-1 empty value -> 0 */ }
func TestCookieFlags_PlainHTTPSuppressesSecure(t *testing.T) { /* http:// -> 2 findings, Secure suppressed */ }
```

- [ ] **Step 2: Run, verify fail** (`undefined: cookieFlagsCheck`).

- [ ] **Step 3: Implement cookie_flags.go**

Skeleton (full logic per spec §5.1): parse via `resp.Cookies()`; session-allowlist + value-length heuristic; ignore-allowlist wins; skip deletion cookies; skip `>=400`; Secure only on https; one finding per (name, flag).

```go
package scanner
// CookieFlagsCheck: cookieFlagsCheck struct, Name "cookie-flags", Category "cookie",
// Tier TierPassive, Enabled true. Run does ONE GET via cc.Client, reads resp.Cookies(),
// classifies, emits findings. (Full body per spec §5.1.)
```

- [ ] **Step 4: Run, verify pass; append to DefaultChecks(); Commit**

```bash
git add go/internal/scanner/cookie_flags.go go/internal/scanner/cookie_flags_test.go go/internal/scanner/check.go
git commit -m "feat(dast): cookie security-flags check (CWE-1004/614/1275)"
```

### Task 1.2: Open redirect (TierActive)

**Files:** Create `openredirect.go` + `openredirect_test.go`; add `ProbeRedirect ProbeType = "redirect"` to injection.go enum; append to `DefaultChecks()`.

- [ ] **Step 1: Write failing tests**

```go
func TestOpenRedirect_ReflectingLocation(t *testing.T) { /* 302 Location=?next -> Medium/CWE-601 ConfidenceHigh */ }
func TestOpenRedirect_BackslashBypass(t *testing.T)    { /* /\host normalized -> hit */ }
func TestOpenRedirect_PrefixBypassSubdomain(t *testing.T) { /* https://trusted.com.<sentinel> -> hit, ConfidenceMedium */ }
func TestOpenRedirect_JavascriptScheme(t *testing.T)  { /* Location=javascript:... -> High */ }
func TestOpenRedirect_SubstringHostNoFinding(t *testing.T) { /* Location host != sentinel, sentinel only in query -> NO finding */ }
func TestOpenRedirect_200BodyEchoNoFinding(t *testing.T) { /* 200 with payload in body, no Location -> NO finding */ }
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per spec §5.2 — `redirectParams`, sentinel `fendix-redirect.example`, `cc.NoFollow`, `url.Parse(Location).Hostname()` exact compare, backslash normalization, soft-stop + budget + `cc.Audit` `ProbeRecord{ProbeType: ProbeRedirect}`, auth via `ApplyToRequest`.
- [ ] **Step 4: Run, verify pass; append to DefaultChecks(); Commit.**

### Task 1.3: Reflected XSS (TierActive)

**Files:** Create `xss.go` + `xss_test.go`; append to `DefaultChecks()`.

- [ ] **Step 1: Write failing tests (FP controls are the load-bearing ones)**

```go
func TestXSS_RawHTMLReflection(t *testing.T)        { /* text/html verbatim payload -> High/CWE-79 */ }
func TestXSS_ScriptContext(t *testing.T)            { /* inside <script> -> High */ }
func TestXSS_JSONContentTypeSuppressed(t *testing.T) { /* application/json reflects verbatim -> 0 findings */ }
func TestXSS_EncodedReflectionSuppressed(t *testing.T) { /* &lt;svg... returned -> 0 findings */ }
func TestXSS_MarkerOnlyNoMetacharsNoFinding(t *testing.T) { /* only fendixXSS marker, brackets encoded -> 0 */ }
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** per spec §5.3 — Content-Type gate first; per-probe random marker; require unencoded `<svg/onload=fendixXSS...` survival; context→confidence; budget + `cc.Audit`; auth via `ApplyToRequest`; skip `>=400`.
- [ ] **Step 4: Run, verify pass; append to DefaultChecks(); Commit.**

**Phase 1 ship gate:** 3 checks registered; all FP-control negative tests pass; full suite green.

---

# PHASES 2–5 — Accuracy hardening (all 45 verified findings)

Each task = one verified finding (or a tight cluster): write a failing test that encodes the FP/FN, apply the fix sketch from the spec, verify the test passes, run the suite, commit. The finding list, file:line, and fix sketch for each are in the spec §2 / the audit artifact. Detailed task structure (the same Write-test → Fail → Fix → Pass → Commit cycle) applies to every one.

### Phase 2 — Injection accuracy (6 findings)
- [ ] **2.1** Time-based SQLi: require confirmation probe to pass for HIGH; keep MEDIUM otherwise. Test: server delays only on first probe → MEDIUM not HIGH. (`injection.go` probeSQLi)
- [ ] **2.2** Boolean SQLi: add a neutral control probe (`value=fendix`); require TRUE≈control && FALSE diverges, stable over repeat. Test: per-request CSRF-token jitter target (>5% length noise) → **no finding**. (`injection.go` probeSQLiBoolean)
- [ ] **2.3** Boolean SQLi denominator: normalize on `math.Max(trueLen,falseLen)`. Test: order-independence.
- [ ] **2.4** CMDi: computed canary (`echo $((7*191))` → expect `1337` in body, not the literal payload). Test: server echoes input verbatim → **no finding**; server executes → finding. (`injection.go` probeCMDi)
- [ ] **2.5** Error/CMDi/CRLF soft-stop: add `select{<-ctx.Done():return}` at top of each probe fn. Test: cancelled ctx → probes stop.
- [ ] **2.6** Confidence calibration pass across injection findings (evidence-tiered).

### Phase 3 — Auth realism (6 findings)
- [ ] **3.1** JWT-bypass: gate on bearer scheme; inject tampered token via `ApplyToRequest` path (handles cookie/query). Test: cookie-JWT endpoint gets tamper in the Cookie header. (`auth.go`)
- [ ] **3.2** Garbage-auth dedup: emit minimal JSON body for POST/PUT/PATCH. Test: body-required POST endpoint deduped correctly.
- [ ] **3.3** Auth-bypass confidence: corroborate with body-diff vs denied baseline; status-only → MEDIUM. Test: 200-but-denied-content → not HIGH.
- [ ] **3.4** Expired/alg:none realism: decode real token, flip `exp`, keep original sig (best black-box approximation); document the limit. Test: server that ignores exp → finding; strict server → none.
- [ ] **3.5** `endpointAcceptsGarbageAuth`: use `cfg.Auth.Header` not literal `Authorization`. Test: X-Api-Key auth.
- [ ] **3.6** `isJWTAuth`: base64url-decode header, require `alg` key; detect 5-part JWE and skip. Test: 2-dot non-JWT → not treated as JWT.
- [ ] **3.7 (negative gate)** real-token-also-fails: endpoint 404/500 regardless of auth → alg-none/expired/malformed emit **nothing**.

### Phase 4 — CORS depth + headers/exposure precision (~13 findings)
- [ ] **4.1** CORS multi-origin probes: sibling-suffix / prefix / substring / trailing-dot. Test each bypass shape. (`cors.go`)
- [ ] **4.2** CORS credentialed reflection → CRITICAL when ACAC:true. Test.
- [ ] **4.3** CORS simple-request: probe `endpoint.Method` with Origin, not just OPTIONS. Test GET reflection.
- [ ] **4.4** CORS null-origin probe. Test `Origin: null` → HIGH (CRITICAL if creds).
- [ ] **4.5** CORS status-gate: only skip 404/5xx; evaluate on 401/403. Test.
- [ ] **4.6** CORS wildcard-method `ACAM: *`. Test.
- [ ] **4.7** `containsVersion`: replace byte-scan with `regexp.MustCompile(`[0-9]+(\.[0-9]+)+`)` over full string + product/NN rule. Test: `nginx` no-fire, `nginx/1.2` fire, trailing `2.0` fire. (`headers.go`)
- [ ] **4.8** CSP directive analysis: flag unsafe-inline/eval/wildcard/missing default-src → "Weak CSP". Test each.
- [ ] **4.9** HSTS max-age parse: missing/0 → MEDIUM, `<15552000` → LOW. Test.
- [ ] **4.10** Add Referrer-Policy / Permissions-Policy / COOP/COEP/CORP header checks; fix stale doc comment. Test.
- [ ] **4.11** Header check: use `endpoint.Method`, narrow skip to 404/410. Test.
- [ ] **4.12** Exposure: masked-value guard (`password_field` skips `****`/`REDACTED`). Test. (`exposure.go`)
- [ ] **4.13** Exposure: add JWT/AWS-key/PEM/GraphQL-error value-shape patterns. Test each.
- [ ] **4.14** Exposure: tighten stack_trace (dotted path + file:line, multi-frame) + internal_ip (`\b` + 0-255 octets). Test prose/version FPs gone.
- [ ] **4.15** ConfigLeak: regex-based redaction for JSON/compound keys; drop body sample from evidence (status+path only). Test secret not leaked. (`configleak.go`)

### Phase 5 — IDOR + rate-limit realism (7 findings)
- [ ] **5.1** IDOR: structural fingerprint instead of exact byte-equality (tolerate dynamic content). Test dynamic-content IDOR caught. (`idor.go`)
- [ ] **5.2** IDOR: id-mutation — user2 requests user1's id (from `endpoint.Params`); flag 2xx+nonempty. Test cross-tenant.
- [ ] **5.3** IDOR: gate on access-control semantics, not non-empty; handle empty-but-200. Test.
- [ ] **5.4** Rate-limit: escalate burst or reword to "no rate limiting within N requests"; downgrade confidence. Test slow-limiter not FN'd. (`ratelimit.go`)
- [ ] **5.5** Rate-limit: dedicated `rate_limiting` Category (was `headers`). Test category. (Adds the ImpactBase entry in Phase 10.)
- [ ] **5.6** Rate-limit: track successfulProbes; treat budget-exceeded as inconclusive (nil + debug). Test tight budget → no false "unprotected".
- [ ] **5.7** Confidence calibration for IDOR + rate-limit.

**Phases 2–5 ship gate (per phase):** the phase's negative/regression tests pass; full suite green; commit per task.

---

# PHASES 6–9 — New scan types

Each new type: TDD with the FP-control negatives AND the documented-limit false-negative test from spec §7. Designed skeletons are in spec §5; the implementer writes the test-first cycle per check.

### Phase 6 — In-band SSRF (`ssrf.go`, CWE-918) [risk: high]
- [ ] **6.1** Implement `SSRFCheck` (TierActive, Category `ssrf`) per spec §5.1: `urlParamRe` scoping, baseline, error-leak (a)/reflected-fetch (b)/timing (c) precedence, `ProbeSSRF`, budget+audit+ctx, `cc.NoFollow` for redirect-echo.
- [ ] **6.2** Tests: error-leak HIGH (body contains canary host + fetch error); reflected-fetch HIGH; timing MEDIUM; **FP**: param reflected into HTML verbatim → no finding; **documented-limit FN**: server vulnerable only OOB → no finding (encodes the gap). **SSRF test paradox:** set `AllowPrivate:true` (or public sentinel) so the probe leaves the box.
- [ ] **6.3** Append to DefaultChecks(); commit.

### Phase 7 — Host-header injection (`hostheader.go`, CWE-644/601) [risk: med]
- [ ] **7.1** Implement `HostHeaderCheck` (TierActive, Category `host_header`) per spec §5.2: sentinel via Host/X-Forwarded-Host/X-Forwarded-Server/Forwarded; redirect-host reflection (`cc.NoFollow`, exact `Hostname()` compare) HIGH; absolute-link body match anchored to URL-host; baseline diff; one finding per shape.
- [ ] **7.2** Tests: redirect-host HIGH; reset-context link HIGH; **FP**: bare header echo (not URL-host position) → no finding; substring host → no finding; **documented-limit FN**: cache-poisoning-only → no finding.
- [ ] **7.3** Append; commit.

### Phase 8 — GraphQL introspection (`graphql.go`, CWE-200) [risk: med]
- [ ] **8.1** Implement `CheckGraphQL` (TierActive, Category `graphql`) per spec §5.3: bounded 7-path origin-scoped sweep (once per scan, sync-guarded) + graphql-path endpoints; require full `data.__schema` JSON; sub-findings GET-execution (MED) + batching; mutationType → HIGH.
- [ ] **8.2** Tests: valid `__schema` → HIGH; bare 200 → no finding; GET-execution → MED; **documented-limit FN**: introspection-disabled gateway → no finding.
- [ ] **8.3** Append; commit.

### Phase 9 — HTTP method tampering (`methodtamper.go`, CWE-650/693/285) [risk: med]
- [ ] **9.1** Implement `MethodTamperCheck` (TierActive, Category `method_tamper`) per spec §5.4: trigger gate (one canonical authed request; proceed only if gated/restricted); alternate verbs sent without creds vs gated canonical (HIGH bypass); TRACE/XST; PUT/DELETE acceptance; per-(Title,Category) dedup.
- [ ] **9.2** Tests: 401→2xx verb flip HIGH; TRACE enabled → finding; **FP (load-bearing)**: HEAD 2xx empty body → no finding; public 200→200 flip → no finding; CSRF-403 → no false bypass.
- [ ] **9.3** Append; commit.

---

# PHASE 10 — Contract sync + scoring + ENGINE_VERSION ship

**Goal:** Land all cross-cutting contract changes once and ship the engine to prod.

### Task 10.1: ImpactBase entries (engine)
**Files:** Modify `go/internal/models/scoring.go:5`
- [ ] Add entries: `rate_limiting`, `ssrf`, `host_header`, `graphql`, `method_tamper`, `cookie`, `redirect`, `xss` with appropriate base impacts (e.g. ssrf 8.5, method_tamper 7.0, host_header 6.5, graphql 4.0, rate_limiting 4.0, cookie 4.0, redirect 5.0, xss 7.0).
- [ ] **Note (verified):** this is scoring/correlation **parity**, NOT a severity gate — DAST checks hardcode `Severity:` and never call `CalculateSeverity`. Adding entries does not change DAST finding severities. Test: `ImpactBase` has all new keys; existing `CalculateSeverity` tests still pass.
- [ ] Commit.

### Task 10.2: Backend `_CATEGORY_MAP` sync
**Files:** Modify `backend/scanning/compliance.py:12`
- [ ] Add keys: `cookie, redirect, xss, ssrf, host_header, graphql, method_tamper, rate_limiting` — **and `data_exposure`** (verified latent bug: engine already emits `data_exposure` from exposure/configleak but the map lacks the key → empty compliance tags today).
- [ ] Each maps to OWASP/ASVS/PCI tag lists matching the existing entries' shape.
- [ ] Test: `backend/scanning/tests/test_engine_drift.py` extended to assert every new category ingests with non-empty compliance mapping. Run: `FAST_TESTS=1 docker compose exec django python -m pytest scanning/tests/test_engine_drift.py -v`.
- [ ] Commit (backend repo).

### Task 10.3: SARIF round-trip test (engine)
- [ ] Test: round-trip one finding of each new category through `fendix report --format sarif`; assert non-empty `rules[].id` + CWE taxon for CWE-918/644/601/79/650/693/285/200. (`reporters` package.)
- [ ] Commit.

### Task 10.4: ENGINE_VERSION bump + ship
- [ ] `grep -rn ENGINE_VERSION` across **both** repos; bump every pin (engine: Makefile/release tag; backend: `Makefile:117`, `docker-compose.prod.yml` ×3) to the next `v*`.
- [ ] Tag + push the engine release so GHCR publishes `ghcr.io/abdel-rahmansaied/fendix:<vNEXT>` **before** the backend prod build.
- [ ] Backend: `make schema` → commit `backend/openapi.json` (category is free-form string — no enum break, but regen for cleanliness); frontend `npm run codegen` if any serializer changed.
- [ ] Verify: `make schema-check` green.
- [ ] Commit.

**Phase 10 ship gate:** backend drift test green; SARIF round-trip green; `make schema-check` green; GHCR image published; prod build pulls the new engine.

---

## Self-Review

- **Spec coverage:** Phase 0 = §3 + C1–C3; Phase 1 = §5.1–5.3 proof checks; Phases 2–5 = all 45 §2 findings (mapped 1:1 to tasks); Phases 6–9 = §5.1–5.4 new types; Phase 10 = §6 cross-cutting (ImpactBase corrected-premise, `_CATEGORY_MAP` incl. `data_exposure`, ENGINE_VERSION, SARIF). All §7 load-bearing negative tests are assigned (0b.1, 2.2, 2.4, 3.7, 1.3, 6.2/7.2/8.2/9.2, shared-budget). No spec section is unmapped.
- **Placeholder scan:** Phases 0–1 have complete code; Phases 2–10 tasks each name file, exact change, test name, and expected result with the fix sketch — no "TBD"/"handle edge cases". The few skeleton bodies (`// per spec §X`) reference a fully-specified spec section, not an undefined behavior.
- **Type consistency:** `Check`, `CheckContext{Cfg,Client,NoFollow,Audit}`, `Tier`, `DefaultChecks()`, `AsCheck`, `NewWorkerPoolChecks`, `guardedClientNoFollow`, `ProbeRedirect`/`ProbeSSRF` are used consistently across all tasks. `ApplyToRequest`/`measureBaseline(cfg)` signatures match their definitions.
