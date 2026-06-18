# DAST Module — Architecture Refactor + 3 Proof Checks (Design Spec)

> **Date:** 2026-06-18
> **Repo:** `fendix-engine` (Go black-box scanner, `go/internal/scanner`)
> **Scope:** Interface-based check architecture, single shared SSRF-guarded HTTP client injected via `CheckContext`, full migration of all 8 existing checks, and 3 proof checks (cookie-flags, open-redirect, reflected-XSS) added through the new path.
> **Method:** Grounded in a 65-agent audit + adversarial-verification + design workflow (52 findings audited, 7 refuted, 45 confirmed/partial). This spec carries only verified findings and pressure-tested signatures.

---

## 1. Problem & Goals

The **Scanning — Web / DAST** module (`go/internal/scanner`) is the black-box engine: 8 check functions (`CheckConfigLeak`, `CheckHeaders`, `CheckCORS`, `CheckExposure`, `CheckRateLimit`, `CheckAuth`, `CheckIDOR`, `CheckInjection`) fanned across discovered endpoints by `engine.WorkerPool`. It is mature in places (corpus-driven FP suppression, a strong injection module) but structurally brittle:

- The check list is a **hand-built `[]scanner.CheckFn` slice** in `orchestrator.go:222-241`, with active/auth/multi-user gating inlined as `if` appends. Adding a scan type means editing the orchestrator.
- **6 of 8 checks build their own raw `&http.Client{Transport: budget.Transport()}`**, bypassing the `netguard` SSRF egress guard that `guardedClient` applies — a **confirmed critical**: the scanner can be steered into SSRF against cloud-metadata / RFC1918 hosts via attacker-controlled redirects.
- The active/passive distinction is **implicit** (each check self-gates), so there is no single place that knows a check's intrusiveness.

**Primary goal (chosen):** *Architecture refactor first.* Make adding scan types cheap and make the SSRF-guard posture structural — then add types on top. This refactor also lands a set of cheap, high-value correctness fixes that fall out of the new structure for free, and ships 3 proof checks that exercise the new path across all tiers.

**Non-goals (deferred to follow-up plans):** the bulk of detection-accuracy fixes (CORS depth, IDOR id-mutation, JWT realism, exposure-pattern expansion) and the larger new scan types (SSRF-detection, host-header injection, GraphQL introspection, HTTP method tampering). They are catalogued in §7 as the roadmap this refactor unlocks.

---

## 2. Evaluation Results (verified)

A multi-agent audit applied the SAST/DAST-accuracy lens (false-negative = missed vuln; false-positive = noise) to every check, then an adversarial verifier tried to *refute* each finding (with live Go/`httptest` repros where cheap). **45 of 52 survived** (3 critical, 8 high, 18 medium, 12 low, 4 info). The verifiers also corrected several initial hypotheses — e.g. the baseline-omits-auth bug was **downgraded to medium** (a fast unauth baseline makes time-based detection *easier*, not harder), and 7 findings were refuted outright.

### 2.1 Critical (must fix in this refactor)

| # | Finding | File | Why it matters |
|---|---|---|---|
| C1 | **`addAuth` double-prefixes bearer/basic creds** | `injection.go:846-858` | `Type="bearer"` + `Value="Bearer xyz"` (the *documented* shape from `--auth` help + `DetectAuthType`/`NormalizeAuth`) → emits `Authorization: Bearer Bearer xyz`. Servers reject it, so **every injection probe against an authenticated endpoint runs effectively unauthenticated** and hits the 401/403 path instead of the vulnerable handler. Silent, blanket FN on the highest-value surface. **Fix:** delete `addAuth`; use `cfg.Auth.ApplyToRequest(req)` (nil-guarded) — the single source of truth, which also handles `apikey-query` URL mutation. |
| C2 | **6 of 8 checks dial through raw `budget.Transport()` with no netguard** | `configleak.go:105`, `auth.go:28`, `idor.go:27`, `exposure.go:82`, `ratelimit.go:61`, `headers.go:174` | SSRF egress guard absent on the unguarded path. **Fixed structurally** by injecting one guarded client via `CheckContext` (§3). |
| C3 | **Redirect-following raw clients have no `CheckRedirect`** | `configleak.go:105`, `exposure.go:82`, `headers.go:174`, `ratelimit.go:61` | Go's default client follows 30x into private/metadata IPs with **zero re-validation**. The scanner becomes an SSRF exfil channel. **Fixed** by the guarded follow-client (which re-applies IP policy on every hop). |

### 2.2 High (8) — most fixed by the refactor; rest noted as fast-follow

SSRF-bypass instances on `CheckHeaders` / `CheckExposure`+`ConfigLeak` / `CheckIDOR`+`CheckRateLimit` (all → fixed by C2/C3 structurally); the architecture findings ("no per-endpoint SSRF pre-validation outside the transport"; "shared guarded client is a behavior change, not a no-op") — **both explicitly addressed by the design + SSRF regression tests in §3.4**. Detection-accuracy highs (boolean-SQLi FP surface, `password_field` masked-value FP, missing body-secret patterns JWT/AWS/PEM) are scoped to the follow-up accuracy plan, except where a fix is trivial and rides along (see §6).

### 2.3 Medium/Low/Info — the accuracy roadmap

18 medium + 12 low + 4 info findings span: injection (baseline-auth M, CMDi reflection-FP M, boolean-SQLi denominator L, soft-stop INFO), auth (JWT-scheme assumptions M, single-signal over-confidence M, `isJWTAuth` heuristic L, garbage-auth body L), CORS (suffix-bypass M, credentialed-reflection severity M, simple-request M, null-origin M, status-gate M, wildcard-method L), exposure/configleak (evidence redaction M, stack-trace FP M, secret-in-evidence M, internal-IP FP L), IDOR/rate-limit (byte-equality M, id-mutation M, burst FN M, empty-200 M, category L), headers (CSP presence-only M, HSTS weak L, missing modern headers L, `containsVersion` FP/FN INFO). **These are the catalogued roadmap (§7).** This refactor fixes only the ones that fall out for free (§6).

> **Decision:** the refactor lands C1–C3 + the free-rider fixes. The remaining medium/low/info accuracy findings become a sequenced follow-up plan, because mixing a structural refactor with 40+ behavior changes would make the diff unreviewable and the regression risk unbounded. The architecture is what makes those fixes cheap and isolated afterward.

---

## 3. Architecture

### 3.1 The `Check` interface + `Tier` model

New file `go/internal/scanner/check.go`:

```go
package scanner

// Tier classifies a check by intrusiveness and required scan inputs.
// The orchestrator filters DefaultChecks() by Enabled(cfg) and prints the
// active-scanning disclaimer iff any enabled check is TierActive.
type Tier int

const (
	TierPassive   Tier = iota // safe GET/OPTIONS observation; always on
	TierActive                // sends attack payloads; gated by cfg.EnableActive
	TierAuth                  // needs cfg.Auth (single credential)
	TierMultiuser             // needs cfg.Auth AND cfg.AuthUser2 (cross-user)
)

func (t Tier) String() string { /* passive|active|auth|multiuser|unknown */ }

// Check is the unit of black-box detection. Implementations are stateless
// adapter structs registered in DefaultChecks().
type Check interface {
	Name() string                        // stable id, e.g. "configleak"
	Category() string                    // models.Finding.Category bucket
	Tier() Tier                          // intrusiveness / input class
	Enabled(cfg *models.ScanConfig) bool // tier-implied gate
	Run(ctx context.Context, cc *CheckContext, ep Endpoint) []models.Finding
}
```

`Enabled(cfg)` replaces the orchestrator's inline `if cfg.Auth != nil` / `if cfg.EnableActive` appends. Each check answers for itself: injection/xss → `cfg.EnableActive`; auth → `cfg.Auth != nil`; idor → `cfg.Auth != nil && cfg.AuthUser2 != nil`; passive → `true`.

> **Tier enum note (risk):** `iota`-backed `int` means inserting a tier mid-list renumbers others. It is never persisted, so the risk is low, but keep additions **append-only** (or switch to string-backed) to be safe.

### 3.2 `CheckContext` — TWO shared guarded clients (the SSRF fix)

> **Correction surfaced by the design audit (important):** a *single* shared client cannot serve all checks. `auth.go` and `idor.go` deliberately use `CheckRedirect: http.ErrUseLastResponse` — **a 3xx IS the bypass/IDOR signal**, so they must NOT follow redirects. The follow-and-revalidate `guardedClient` would destroy that signal. Open-redirect (§5.2) needs the same no-follow behavior. Therefore `CheckContext` carries **two** clients built from **one** guarded `RoundTripper` (so SSRF egress + budget counting are identical on both):

```go
// go/internal/scanner/checkcontext.go (new)
type CheckContext struct {
	Cfg      *models.ScanConfig
	Client   *http.Client   // FOLLOWS redirects, re-validates IP each hop (default)
	NoFollow *http.Client   // CheckRedirect => ErrUseLastResponse; SAME guarded transport
	Audit    *ProbeAuditLog // scan-wide probe log (active tier)
}

// httpclient.go (extend)
func guardedClientNoFollow(cfg *models.ScanConfig) *http.Client {
	ap := allowPrivate(cfg)
	return &http.Client{
		Timeout:       0, // per-job ctx deadline instead (see §3.3)
		Transport:     budget.TransportGuarded(ap),           // budget OUTER, netguard INNER
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func NewCheckContext(cfg *models.ScanConfig) *CheckContext {
	c := guardedClient(cfg); c.Timeout = 0
	return &CheckContext{
		Cfg: cfg, Client: c, NoFollow: guardedClientNoFollow(cfg),
		Audit: currentAuditLog(), // aliases the global → GlobalAuditRecords()/--debug-bundle keep working
	}
}
```

**Client selection rule (enforced by review + a test):** `auth`, `idor`, and `openredirect` use `cc.NoFollow`; everything else uses `cc.Client`. A migrated auth/idor check that accidentally reads `cc.Client` would silently lose its 3xx signal — §3.4 adds a redirect-semantics test to catch exactly this.

This closes the **entire SSRF-bypass class (C2/C3 + the 5 high-severity instances)** structurally: no check ever constructs its own transport again.

### 3.3 Per-endpoint timeout

The shared clients set `Timeout: 0` (a single `client.Timeout` would otherwise cap the *whole scan* under connection reuse). Per-(endpoint, check) deadlines come from `ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)` **inside `runCheck`**, so each job gets its own deadline while sharing one connection pool.

> **Interaction risk (noted for the plan):** the per-job `WithTimeout` deadline must not be mistaken for the budget cancel-on-cap (`orchestrator.go` budget wiring). The plan must verify a per-job deadline firing is distinguishable from `--max-requests`/`--max-duration` soft-stop.

### 3.4 Worker-pool + orchestrator migration

**`workerpool.go`:** `WorkerPool.checks` becomes `[]scanner.Check`; the pool holds `*scanner.CheckContext`; `scanJob.check` becomes `scanner.Check`; `runCheck` signature drops `cfg` (now `cc.Cfg`), gains `cc`, and calls `job.check.Run(ctx, cc, job.endpoint)`. The panic-recovery synthetic finding (`workerpool.go:135-143`) now labels with `job.check.Category()`/`Name()`. Producer/channel logic is unchanged.

**`orchestrator.go`:** the hand-built slice + inline `PrintDisclaimer()` (lines 222-241) become:

```go
all := scanner.DefaultChecks()           // deterministic order, configleak first
var checks []scanner.Check
active := false
for _, c := range all {
	if !c.Enabled(o.cfg) { continue }
	checks = append(checks, c)
	if c.Tier() == scanner.TierActive { active = true }
}
if active { scanner.PrintDisclaimer() }  // fired once, before the pool runs
cc := scanner.NewCheckContext(o.cfg)
pool := NewWorkerPool(o.cfg.Workers, o.cfg.DelayMs, checks)
findings := pool.Run(ctx, cc, endpoints)
```

`ResetGlobalAuditLog()` still runs before `NewCheckContext`, so audit ordering is preserved.

> **`checksRun` metadata (risk → fix):** the hand-maintained `checksRun` literal (`orchestrator.go:577-589`, read by the report/frontend contract) **must be derived from the filtered `checks` slice** — otherwise it silently omits the 3 new proof checks. The plan derives it from `checks` (names), and the new categories (`cookie-flags`, `redirect`, `xss`) are added to the `checksRun` set.

### 3.5 Back-compat — keep all 12 test files green

There are **84 direct `Check*(ctx, cfg, ep)` call sites across 11 scanner test files**. Migration strategy (two layers, zero test edits):

1. Refactor each free function body into a struct method `Run(ctx, cc, ep)` (or an internal `…WithClient` form) that reads its client from `cc`.
2. **Keep the old `Check*(ctx, cfg, ep)` signature as a 3-line shim** that builds an ephemeral one-off context and delegates:
   ```go
   func CheckHeaders(ctx context.Context, cfg *models.ScanConfig, ep Endpoint) []models.Finding {
       return headersCheck{}.Run(ctx, NewCheckContext(cfg), ep)
   }
   ```
3. Keep `CheckFn`, `CheckInjectionWithAudit`, and `currentAuditLog()`/`GlobalAuditRecords()`/`ResetGlobalAuditLog()` exactly as-is.

**Engine tests are also kept unedited.** 6 engine test files (`workerpool_test.go`, `workerpool_cancel_test.go`, `scan_benchmark_test.go`, `workerpool_largescale_test.go`, `workerpool_fuzz_test.go`, plus `spawner_test.go`) build `[]scanner.CheckFn` and pass it to `NewWorkerPool`. **Decision:** `NewWorkerPool` keeps its existing `(workers, delayMs, []scanner.CheckFn)` signature and wraps each `CheckFn` internally via an `AsCheck(name string, fn CheckFn) Check` adapter; the production path uses a new `NewWorkerPoolChecks(workers, delayMs, []Check)` (or an overload) fed by `DefaultChecks()`. The legacy `Run` path lazily builds an ephemeral `CheckContext` when none is supplied. This keeps **all** engine + scanner test files unedited.

**Compile gate is the primary acceptance signal:** `cd go && go build ./... && go vet ./...` with **zero edits** to any `_test.go`, then `go test ./internal/scanner/... ./internal/engine/... -race` green.

**New SSRF regression test (the proof C2/C3 are fixed):** an `httptest` server that 302-redirects to `http://169.254.169.254/` (and `127.0.0.1`); assert every migrated check (esp. headers/exposure/configleak/ratelimit) **refuses** the redirect when `allowPrivate` is false. **Redirect-semantics test:** a 302 endpoint; assert `auth`/`idor`/`openredirect` observe the raw 302 (no-follow path) while passive checks follow.

---

## 4. Migration & free-rider fixes (in scope)

Bundled into the refactor because they are structurally inseparable or near-zero-cost:

- **C1** — delete `addAuth`, route injection auth through `AuthContext.ApplyToRequest`. (Must do, and trivially correct; also fixes the baseline-omits-auth medium when baseline requests get auth applied via the same path.)
- **C2 + C3** — SSRF guard on all checks (the whole point).
- **`guardedClient` option / no-follow variant** — required for auth/idor/openredirect (§3.2).
- **rate-limit category** — `Category: "headers"` → a dedicated category, fixed when its check is registered with a correct `Category()` (low risk, rides the registry change). *If* this requires an `ImpactBase` entry, that scoring change is called out in the plan.

Everything else stays behaviorally identical; the free-function shims guarantee it.

---

## 5. Proof Checks (all three — one per tier)

The user asked for all three, which validates the architecture across passive, active-lite, and full-active. Each is registered through `DefaultChecks()` and runs through `CheckContext`.

### 5.1 Cookie security flags — `cookie_flags.go` (TierPassive)

- **Zero extra requests** where possible: reads `Set-Cookie` off a response another check/the orchestrator already fetched (a body-light `PassiveResponse` snapshot of status+headers+final-URL shared via context); falls back to one cheap GET through `cc.Client` (guarded) otherwise.
- Parse with stdlib `(*http.Response).Cookies()` — never hand-roll.
- **Flag** session-shaped cookies (name allowlist: `session|sess|sid|auth|token|jwt|csrf|jsessionid|phpsessid|laravel_session|connect.sid|…`, or value ≥16 chars and not a small int). **Ignore-list wins** (analytics: `_ga|_gid|_fbp|mixpanel|amplitude|__utm|consent|locale|theme|…`). Never flag a **deletion** cookie (`Max-Age<0` / past `Expires` + empty value).
- **Severity:** missing `HttpOnly` → MEDIUM/CWE-1004 (Conf High); missing `Secure` → MEDIUM/CWE-614 (Conf High, **only on https://** — moot on plain http); `SameSite=None` or missing → LOW/CWE-1275 (Conf Medium; escalate `None`+missing-`Secure` to MEDIUM). `Strict`/`Lax` → no finding.
- **FP controls:** skip `>=400` responses; one finding per (cookie-name, flag); register **once against the discovery URL**, not per-endpoint (avoids N near-identical findings; the existing `Deduplicate` pass is the backstop).
- `Enabled()` → always true.

### 5.2 Open redirect — `openredirect.go` (TierActive, active-lite)

- Probes common redirect params (`next|url|return|returnTo|dest|redirect|redirect_uri|continue`) with a sentinel **RFC2606** host `fendix-redirect.example` (never resolvable, never third-party-owned). Uses **`cc.NoFollow`** so the 3xx `Location` is observable.
- **Detection key = host equality / host-prefix on the PARSED `Location` URL, never substring.** Payload shapes: `//host`, `/\host` (backslash bypass — normalize `\`→`/` before `url.Parse`, since browsers treat them alike but `url.Parse` doesn't), `https://host`, and whitelist-prefix bypass `https://trusted.com.<sentinel>`.
- **Severity:** MEDIUM/CWE-601; escalate to **HIGH** when `Location` crosses to a dangerous scheme (`javascript:`/`data:`/`vbscript:`) — and only when that scheme actually appears.
- **FP control (load-bearing):** a server redirecting to its **own** host with the sentinel only as a query *substring* (`Location: https://victim.test/login?next=//fendix-redirect.example`) → **no finding** (host ≠ sentinel). 200-with-payload-echoed-in-body → no finding (must be a 3xx with a `Location`).
- Adds `ProbeType "redirect"`; shares the per-endpoint cap (`effectiveMaxProbes`) + scan-wide `ProbeAuditLog`; `ctx.Done()` soft-stop check before **every** probe. Auth via `ApplyToRequest` (never `addAuth`).
- **Documented FN:** meta-refresh / JS-body redirects (Location-header only).

### 5.3 Reflected XSS — `xss.go` (TierActive, highest FP-risk; the FP controls are the point)

- Per `(param, location)` target via the existing `targetsForEndpoint`. Uses `cc.Client` (guarded) and the shared probe budget.
- **Content-Type gate FIRST (the single biggest FP control):** send the canary probe; if the response `Content-Type` is **not `text/html`** (json/xml/plain/missing) → emit nothing. Reflected input in a JSON API body is not XSS — the browser won't parse it as markup.
- **Canary distinguishes raw vs encoded reflection:** per-probe random marker `fendixXSS<8hex>` inside payload `"><svg/onload=fendixXSS<rand>>`. Detection **requires the HTML metacharacters to survive un-encoded** adjacent to the marker (literal `<svg/onload=fendixXSS<rand>`). If `<`/`>`/`"` come back as `&lt;`/`&gt;`/`&quot;`/`&#x3c;` → **encoded → safe → no finding**. Matching the bare marker alone is *not* a finding (that's the same FP class as the confirmed CMDi-reflection bug).
- **Context classification → confidence:** raw HTML / `<script>` context → **High**; angle-brackets survive but context unknown → **Medium**; attribute-only without breakout → **suppress** (documented FN, keeps FP low).
- **Severity** High, **Category** `injection`, CWE-79 + OWASP-A03, `Source: SourceBlackbox`. Auth via `ApplyToRequest`. Detection-only (the `<svg onload>` never executes server-side; we only inspect whether markup returns un-encoded), gated behind the active disclaimer.
- **Documented limits (explicit, not hidden):** DOM-based & stored XSS out of scope; Content-Type-sniffing clients (text/plain rendered as HTML) → FN; tag-specific WAF stripping `<svg` → FN (single canary); shared-budget starvation with injection on param-heavy endpoints (both draw the same 20-probe cap) → some XSS probes may be skipped; `>=400` HTML error pages echoing the query string are skipped to avoid self-reflection FP.

---

## 6. Test Strategy (whole refactor)

1. **Compile gate** — `go build ./... && go vet ./...`; **all 12 scanner `_test.go` compile with zero edits** (primary signal the shim layer works). Then `go test ./internal/scanner/... ./internal/engine/... -race` green (proves behavior-identical migration).
2. **Registry test** (`check_test.go`) — `DefaultChecks()` returns the expected ordered `Name()` slice with `configleak` at index 0; table-test `Enabled()` against {bare, EnableActive, Auth-only, Auth+AuthUser2} and assert the exact enabled subset + `Tier()` values.
3. **Disclaimer test** — `PrintDisclaimer` appears iff an active-tier check is enabled; absent for passive/auth/multiuser-only.
4. **SSRF regression test** — 302→`169.254.169.254`/`127.0.0.1`; every migrated check refuses when `allowPrivate=false`.
5. **Redirect-semantics test** — auth/idor/openredirect observe the raw 302; passive checks follow.
6. **Per proof check** — `cookie_flags_test.go` (https vs http, hardened cookie, analytics-ignored, deletion-cookie, dup-dedup), `openredirect_test.go` (reflecting 302, `//`/`/\`/scheme/prefix-bypass, javascript-scheme High, substring-host FP guard, 200-body no-finding), `xss_test.go` (raw-HTML High, script-context High, **JSON-CT suppressed**, **encoded-reflection suppressed**, marker-only no-finding).

---

## 7. Roadmap unlocked (follow-up plans, NOT this refactor)

Once checks are interface-registered with a shared guarded context, each of these is an **isolated new file + one `DefaultChecks()` line** (new types) or a **single-check internal change** (accuracy fixes):

- **Accuracy fast-follow** (the 18M/12L/4I findings): CORS depth (suffix-bypass, simple-request, null-origin, credentialed→CRITICAL, status-gate), IDOR id-mutation + structural fingerprint, JWT realism (`isJWTAuth` decode, scheme-aware tampering, real-token exp-flip), exposure patterns (JWT/AWS/PEM value-shapes, masked-value guard, stack-trace/internal-IP precision), CSP directive analysis + HSTS max-age + modern headers, boolean-SQLi control-probe, CMDi computed-canary, rate-limit escalating burst, soft-stop uniformity.
- **New scan types** (breadth): SSRF *detection*, host-header injection, GraphQL introspection, HTTP method tampering, SSTI, path traversal/LFI, stored-XSS (DAST-stateful), DOM-XSS (headless follow-up).

---

## 8. Risks & Mitigations (consolidated)

| Risk | Mitigation |
|---|---|
| Shared client is a **behavior change** (6 checks now guarded) | Intended posture; SSRF regression test asserts it; documented in spec. |
| auth/idor/openredirect read the wrong client and lose the 3xx signal | Two-client `CheckContext`; redirect-semantics test; review rule. |
| `checksRun` metadata drifts, omits proof checks | Derive `checksRun` from the filtered `checks` slice. |
| Connection-pool sharing perturbs **time-based SQLi** timing | Keep the `baseline + 4s` margin + confirmation re-probe; verify in injection tests post-migration. |
| Per-job `WithTimeout` vs budget cancel-on-cap confusion | Plan verifies the two are distinguishable; existing budget tests stay green. |
| `iota` Tier renumbering | Append-only additions (or string-backed). |
| Proof-check request amplification (cookie-flags per-endpoint) | Register cookie-flags once against discovery URL; dedup backstop. |

---

## 9. Acceptance Criteria

1. All 8 existing checks implement `Check` and run through `CheckContext`; **no check constructs its own `http.Client`.**
2. `addAuth` is deleted; injection auth uses `ApplyToRequest`.
3. SSRF regression test proves all checks refuse private/metadata redirects when `allowPrivate=false`.
4. All 12 scanner `_test.go` files compile and pass **unedited**; full suite green with `-race`.
5. `DefaultChecks()` is the single registry; orchestrator filters by `Enabled`; disclaimer fires iff an active check is enabled; `checksRun` reflects the filtered set.
6. cookie-flags, open-redirect, reflected-XSS are registered, tiered correctly, and pass their FP-control tests (esp. XSS JSON-CT + encoded-reflection suppression, open-redirect substring-host guard).
