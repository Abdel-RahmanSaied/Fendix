# DAST Module — The Powerful Upgrade (Design Spec)

> **Date:** 2026-06-18 · **Repo:** `fendix-engine` (`go/internal/scanner`) · **Status:** design, awaiting review
> **Scope:** Re-architect the black-box DAST module to an interface-based check registry with a single shared SSRF-guarded `CheckContext`; **fix all 45 verified findings**; ship **3 proof checks** (cookie-flags, open-redirect, reflected-XSS); add **4 flagship new scan types** (in-band SSRF, host-header injection, GraphQL introspection, HTTP method tampering). Delivered as **11 independently-shippable phases**.
> **Method:** Two multi-agent workflows (71 agents total): a 65-agent audit + adversarial-verification pass (52 findings audited → 45 confirmed/partial, 7 refuted) and a 6-agent design pass (4 new-type architects + sequencer + completeness critic). Every contract claim in §6 was then **ground-truthed against the live backend + engine source** — three premises from the draft were corrected (noted inline).

---

## 1. Why this, why now

The DAST module is the heart of fendix: 8 checks fanned across discovered endpoints. It is mature in spots (corpus-driven FP suppression, a strong injection module) but structurally limits growth and carries a **critical security defect of its own**:

- **The scanner can be turned into an SSRF weapon.** 6 of 8 checks build raw `&http.Client{Transport: budget.Transport()}` — bypassing the `netguard` egress guard `guardedClient` applies. Four of those follow redirects with **no `CheckRedirect`**, so an attacker-controlled 302 → `169.254.169.254` (cloud metadata) or RFC1918 is followed with zero re-validation. *(Verified critical.)*
- **Authenticated injection scans silently run unauthenticated.** `addAuth` double-prefixes bearer/basic creds (`Bearer Bearer xyz`); servers reject it, so every injection probe behind auth hits the 401 path instead of the vulnerable handler — a blanket false negative on the highest-value surface. *(Verified critical — caught by adversarial review, missed on first read.)*
- **Adding a scan type means editing the orchestrator.** The check list is a hand-built `[]scanner.CheckFn` slice with active/auth/multi-user gating inlined as `if` appends.

**The goal (chosen: the full powerful solution).** Make the SSRF posture structural, fix every verified accuracy defect, and grow coverage from 8 → 15 checks — so the module goes from "competent API scanner" to a DAST engine that detects SSRF, host-header poisoning, GraphQL exposure, verb-tampering, reflected-XSS, open-redirects, and insecure cookies, with materially lower false-positive noise. Each phase ships on its own.

---

## 2. Evaluation (verified, adversarially reviewed)

52 findings audited with the SAST/DAST-accuracy lens; an adversarial verifier tried to *refute* each (live `httptest`/Go repros where cheap). **45 survived** (3 critical, 8 high, 18 medium, 12 low, 4 info); **7 refuted**. Severity corrections were applied (e.g. the baseline-omits-auth bug was downgraded high→medium: a fast unauth baseline makes time-based detection *easier*, not harder).

### Critical (Phase 0)
| ID | Finding | File | Fix |
|----|---------|------|-----|
| C1 | `addAuth` double-prefixes bearer/basic → blanket FN on authed injection | `injection.go:846` | delete `addAuth`; use `cfg.Auth.ApplyToRequest` |
| C2 | 6/8 checks dial raw `budget.Transport()` — no netguard (SSRF bypass) | `configleak/auth/idor/exposure/ratelimit/headers.go` | one shared guarded client via `CheckContext` |
| C3 | 4 follow-redirect raw clients have no `CheckRedirect` — follow 302→metadata | `configleak/exposure/headers/ratelimit.go` | guarded follow-client re-validates IP each hop |

The remaining 42 (8 high + 18 medium + 12 low + 4 info) are grouped by check into Phases 2–5; the full list with corrected severities and fix sketches lives in the audit artifact and is reproduced per-phase below.

---

## 3. Architecture (Phase 0)

### 3.1 `Check` interface + `Tier`

New `go/internal/scanner/check.go`:

```go
type Tier int
const (
	TierPassive   Tier = iota // safe observation; always on
	TierActive                // sends payloads; gated by cfg.EnableActive
	TierAuth                  // needs cfg.Auth
	TierMultiuser             // needs cfg.Auth AND cfg.AuthUser2
)
func (t Tier) String() string { /* passive|active|auth|multiuser */ }

type Check interface {
	Name() string
	Category() string
	Tier() Tier
	Enabled(cfg *models.ScanConfig) bool
	Run(ctx context.Context, cc *CheckContext, ep Endpoint) []models.Finding
}

func DefaultChecks() []Check { /* 8 existing + 3 proof + 4 new, deterministic order, configleak first */ }
```

`Enabled(cfg)` replaces the orchestrator's inline gating. Tier additions are **append-only** (the `iota` int is never persisted, but renumbering is a needless footgun).

### 3.2 `CheckContext` — TWO guarded clients (the SSRF fix + a hard correction)

> **Correction the design audit forced:** a single shared client *cannot* serve all checks. `auth.go`/`idor.go` deliberately use `CheckRedirect: http.ErrUseLastResponse` — **a 3xx IS the signal** (auth-bypass / IDOR / open-redirect / host-header). The follow-and-revalidate `guardedClient` would destroy that signal. So `CheckContext` carries **two** clients built from **one** guarded `RoundTripper`, so SSRF egress + budget counting are identical on both:

```go
// go/internal/scanner/checkcontext.go (new)
type CheckContext struct {
	Cfg      *models.ScanConfig
	Client   *http.Client   // FOLLOWS redirects, re-validates IP each hop (default)
	NoFollow *http.Client   // CheckRedirect => ErrUseLastResponse; SAME guarded transport
	Audit    *ProbeAuditLog // scan-wide probe log (aliases the package global)
}

func guardedClientNoFollow(cfg *models.ScanConfig) *http.Client {
	ap := allowPrivate(cfg)
	return &http.Client{
		Timeout:       0, // per-job ctx deadline (see §3.3)
		Transport:     budget.TransportGuarded(ap),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func NewCheckContext(cfg *models.ScanConfig) *CheckContext {
	c := guardedClient(cfg); c.Timeout = 0
	return &CheckContext{Cfg: cfg, Client: c, NoFollow: guardedClientNoFollow(cfg), Audit: currentAuditLog()}
}
```

**Client-selection rule (enforced by review + a test):** `auth`, `idor`, `openredirect`, `hostheader` use `cc.NoFollow`; everything else uses `cc.Client`. This closes the **entire SSRF-bypass class (C2/C3 + 5 high instances)** structurally — no check ever constructs a transport again.

### 3.3 Per-endpoint timeout
Shared clients set `Timeout: 0` (a global `client.Timeout` would cap the whole scan under reuse). Per-`(endpoint, check)` deadlines come from `context.WithTimeout(ctx, cfg.Timeout)` inside `runCheck`. The plan must keep this distinguishable from the budget cancel-on-cap path.

### 3.4 Worker-pool + orchestrator migration
`WorkerPool.checks` → `[]scanner.Check`; pool holds `*CheckContext`; `runCheck` calls `job.check.Run(ctx, cc, ep)`; the panic-recovery synthetic finding labels with `Category()`/`Name()`. Orchestrator replaces the hand-built slice (`orchestrator.go:222-241`) with: filter `DefaultChecks()` by `Enabled`, fire `PrintDisclaimer()` once iff any enabled check is `TierActive`, build one `CheckContext`, run the pool. **`checksRun` metadata must be derived from the filtered slice** (else it omits the new checks).

### 3.5 Back-compat — every test file stays unedited
**86 direct `Check*(ctx,cfg,ep)` calls across 11 scanner test files; 6 engine test files pass `[]scanner.CheckFn`.** Strategy:
1. Each free function body becomes a struct `Run`; the old `Check*(ctx,cfg,ep)` signature is kept as a 3-line shim building an ephemeral `NewCheckContext(cfg)` and delegating.
2. `NewWorkerPool` keeps its `[]scanner.CheckFn` signature and wraps internally via `AsCheck(name, fn) Check`; a new `NewWorkerPoolChecks([]Check)` feeds production from `DefaultChecks()`.
3. `CheckFn`, `CheckInjectionWithAudit`, `currentAuditLog`/`GlobalAuditRecords`/`ResetGlobalAuditLog` unchanged.

**Primary acceptance signal:** `go build ./... && go vet ./...` with **zero `_test.go` edits**, then `go test ./internal/scanner/... ./internal/engine/... -race` green.

---

## 4. The phased plan (11 phases, each independently shippable)

Sequencing rationale: Phase 0 is mandatory-first and highest-risk (nothing lands safely until the interface + two-client context exist; the SSRF fix rides it). Proof checks (Phase 1) prove the interface immediately. Accuracy phases (2–5) each touch one check family and ship lower-noise reports. New types (6–9) come after the foundation is hardened. Phase 10 lands all cross-cutting contract sync once.

| # | Phase | Tier of work | Risk | Depends | Ships (what a user/CEO sees alone) |
|---|-------|--------------|------|---------|-----------------------------------|
| **0** | Foundation refactor + C1–C3 | arch + 3 criticals | **high** | — | Same output, but the scanner **can no longer be tricked into hitting internal/metadata endpoints** via redirect; authed injection actually authenticates. |
| **1** | Proof checks: cookie-flags · open-redirect · reflected-XSS | 3 new (passive/active) | med | 0 | Three new vuln classes in every scan; proves the interface across both clients + all tiers. |
| **2** | Injection accuracy (SQLi/CMDi/CRLF) | 6 fixes | med | 0 | Materially fewer false-positive SQLi findings — the #1 DAST trust-killer. |
| **3** | Auth realism | 6 fixes | med | 0 | Stops spamming CRITICAL "missing auth" on public health/metrics endpoints; correct JWT scheme handling. |
| **4** | CORS depth + headers/exposure precision | ~13 fixes | med | 0 | Catches real GET-reflection + credentialed-CORS bypasses; CSP/HSTS depth; lower exposure noise. |
| **5** | IDOR + rate-limit realism | 7 fixes | med | 0 | IDOR catches genuine cross-user-id access; rate-limit findings honestly scoped. |
| **6** | New: **in-band SSRF** (CWE-918) | 1 new | **high** | 0,1 | Marquee capability the engine completely lacked. |
| **7** | New: **host-header injection** (CWE-644/601) | 1 new | med | 0,1 | Password-reset-poisoning / Host-based open-redirect / cache-poisoning precursors. |
| **8** | New: **GraphQL introspection** (CWE-200) | 1 new | med | 0 | Exposed schema + GET-execution CSRF on modern APIs. |
| **9** | New: **HTTP method tampering** (CWE-650/693/285) | 1 new | med | 0,1 | Verb-based authz bypass + TRACE/XST + dangerous PUT/DELETE. |
| **10** | Contract sync + scoring calibration + ENGINE_VERSION ship | cross-cutting | med | 1–9 | Every new finding scores, maps to OWASP/ASVS/PCI, renders in HTML/SARIF + frontend; prod runs the new engine. |

> **Phase 0 split option (from the critic):** Phase 0 mixes a low-risk pure refactor (interface + shims) with three security-behavior changes. The implementation plan may split it into **0a (refactor, behavior-identical, tests green unedited)** and **0b (SSRF guard migration + addAuth, with the regression tests in §6)** so a bisect can isolate any behavior change. Recommended.

---

## 5. New scan types (designed, with honest limits)

All four are `TierActive`, share the per-endpoint probe cap (`effectiveMaxProbes` + `cc.Audit.Count`), `select` on `ctx.Done()` before every probe, record a `ProbeRecord`, and apply auth via `ApplyToRequest` (never `addAuth`).

### 5.1 In-band SSRF — `ssrf.go` (CWE-918) — Phase 6
Detects whether the **target** makes server-side requests to a client-controlled URL (distinct from `netguard`, which guards fendix's *own* egress). Probes URL-shaped params (`urlParamRe`; opt-in `ssrf-all` for every param). Three in-band signals, precedence (a)>(b)>(c), ≤1 finding per `(param,loc)`:
- **(a) Error-leak (HIGH):** inject an unroutable host (RFC5737 `192.0.2.1`, `.invalid` NXDOMAIN under a fendix sentinel); match a fetch-stack error-leak regex set **only when the body also contains our injected canary host** (proves the server fetched *our* URL, not a generic page error).
- **(b) Reflected-fetch / redirect-echo (HIGH/MED):** point the param at a URL carrying a unique marker; flag if the response now contains that marker (server inlined a fetch) and the baseline did not. Redirect-echo via `cc.NoFollow` when a 3xx `Location` carries the canary host → MEDIUM.
- **(c) Timing differential (MED, confirmation-only):** unroutable host that hangs to the connect timeout, medianed; never HIGH (shared-infra jitter).

**Honest limits (documented, not hidden):** no true OAST/blind detection (fendix has no callback collector — a `--oob-host` hook is designed in for the future); cloud-metadata IMDS confirmed only *indirectly* (we never fetch real `169.254.169.254` data); error-suppressing/identical-response servers evade; second-order SSRF out of scope.

### 5.2 Host-header injection — `hostheader.go` (CWE-644/601) — Phase 7
Per-endpoint (the surface is the request line + Host-family headers, not params). Sends a sentinel host via `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `Forwarded`; detects sentinel reflected into (a) an absolute redirect `Location` host (`cc.NoFollow`; **exact host-component compare via `url.Parse(...).Hostname()`, never substring**) → HIGH, or (b) an absolute link in the body anchored to a URL-host position → password-reset-context HIGH / generic MEDIUM. Baseline diff required; one finding per shape per endpoint.
**Limits:** no OOB; cache-poisoning *inferred* not proven (no second unkeyed request); stateful reset flows + non-GET triggers may FN; rare vhost-routing FP.

### 5.3 GraphQL introspection — `graphql.go` (CWE-200) — Phase 8
POSTs the standard introspection query to a **bounded 7-path origin-scoped sweep** (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, …; runs once per scan, sync-guarded) + any discovered endpoint whose path contains `graphql`. Positive **requires the full valid `data.__schema` JSON shape**, never a bare 200. Sub-findings: GET-execution CSRF (MED), batching enabled; HIGH escalation when `mutationType` is a non-null named type.
**Limits:** no blind detection; discovery gap (POST-only `/graphql` with no link relies on the path sweep); no real "production" signal (no `--env` flag); WAF/depth-limit evasion not attempted.

### 5.4 HTTP method tampering — `methodtamper.go` (CWE-650/693/285) — Phase 9
**Trigger gate first:** one canonical authed request; the check proceeds only for access-controlled/method-restricted endpoints. Probes: alternate verbs sent **without credentials** vs the gated canonical (a verb returning 2xx where canonical returned 401/403 = bypass, HIGH); `TRACE` (XST); `PUT`/`DELETE` acceptance.
**Load-bearing FP control:** a 2xx on `HEAD` with no data-bearing header is the *expected* HEAD contract → never flagged alone. Per-`(Title,Category)` dedup lists all bypassing verbs in one finding.
**Limits:** TRACE/XST confirmed as "method enabled" only (no browser-leak proof); PUT-write not confirmed by a follow-up GET (would write to the target); path-normalization bypasses out of scope; CSRF-403 may FN; budget exhaustion can leave late verbs untested.

---

## 6. Cross-cutting contract sync (Phase 10) — ground-truthed

Every claim here was verified against the live backend/engine, correcting three draft premises:

- **CORRECTED — `ImpactBase` is NOT a severity gate for DAST findings.** The draft (and the sequencer) claimed a missing `ImpactBase[category]` "silently downgrades new findings to Info." **Verified false:** the orchestrator and scanner **never call `CalculateSeverity`** (grep-confirmed empty); every DAST check **hardcodes `Severity:`**, and the only live gate is `EnforceSeverityConsistency`. `CalculateSeverity`/`ImpactBase` (`models/scoring.go:47,57`) *do* return `SeverityInfo` for an unknown category, but that path isn't on the DAST hot path. **Therefore:** adding `ImpactBase` entries (`rate_limiting`, `ssrf`, `host_header`, `graphql`, `method_tamper`, `cookie`, `redirect`, `xss`) is for **scoring/correlation parity**, *not* a correctness blocker — a new category does not become Info. (Still worth doing for the reachability-correlation path.)
- **Backend `_CATEGORY_MAP` sync (real).** `backend/scanning/compliance.py` `_CATEGORY_MAP` currently keys `headers, idor, cors, injection, auth_bypass` and an unmapped category returns `_EMPTY` (no compliance tags — not a crash). It must gain `cookie, redirect, xss, ssrf, host_header, graphql, method_tamper, rate_limiting`.
  - **Latent pre-existing bug to fix while here:** the engine already emits `Category: "data_exposure"` (`exposure.go`, `configleak.go`) which is **absent from `_CATEGORY_MAP`** → those findings get empty compliance mappings today. Add `data_exposure` too.
- **OpenAPI risk is LOW (corrected).** `backend/openapi.json` exposes `category` as a free-form `type: string`, **not an enum** — new categories do **not** break the schema or require a frontend `api.ts` regen for validation. Still run `make schema` for cleanliness, but it's not a blocker.
- **ENGINE_VERSION pin sites (verify count).** Live in the backend: `Makefile:117` (`?= v0.17.0`) + `docker-compose.prod.yml` (3 occurrences, `:-v0.17.0`). The repo memory says "4 sites"; the plan must `grep -rn ENGINE_VERSION` across **both** repos and bump every pin, plus tag the engine release so the GHCR image `ghcr.io/abdel-rahmansaied/fendix:<vNEXT>` **publishes before** the backend prod build (`FROM ghcr.io/...` fails otherwise).
- **Confidence calibration** tied to evidence strength is a sweep across Phases 2–5 (direct error signature / reflected canary / parsed introspection → High; shape-only → Medium; heuristic → Low). To avoid drift, Phases 2–5 do per-check calibration and Phase 10 does a final consistency audit — not a re-litigation.
- **SARIF/report path:** new CWEs (918, 644, 601, 79, 650, 693, 285, 200, 352) must serialize into `rules[].id` + CWE taxon — Phase 10 round-trips one finding of each new category through `fendix report --format sarif` and asserts a non-empty rule id.
- **Backend drift test:** extend `backend/scanning/tests/test_engine_drift.py` to assert the new categories ingest cleanly.

---

## 7. Test strategy (load-bearing negatives called out)

Per the critic, these are the regression tests that must exist (not just happy-path):

- **Phase 0:** SSRF-guard regression — `302 → 169.254.169.254` / direct private-IP hop is **blocked** through **both** `cc.Client` and `cc.NoFollow` for every migrated check, when `allowPrivate=false`. Redirect-semantics — `auth`/`idor`/`openredirect`/`hostheader` observe the raw 302; passive checks follow. **Auth-not-broken** — a protected endpoint `302→/login` is **not** reported as "Missing authentication." Compile gate: all `_test.go` unedited.
- **Phase 2:** boolean-SQLi noise-floor — a target with per-request CSRF token/timestamp (>5% length jitter between identical requests) yields **no** finding.
- **Phase 3:** real-token-also-fails — endpoint that 404/500s regardless of auth → alg-none/expired/malformed emit **nothing**.
- **Phase 1 XSS:** JSON-Content-Type reflection suppressed; HTML-entity-encoded reflection suppressed; marker-only (no surviving metachars) → no finding.
- **Phases 6/7/9:** each documents its blind/OOB limit with an explicit **false-negative acceptance test** (server is vulnerable only out-of-band → asserts no finding, encoding the known gap).
- **Shared-budget:** 2+ active checks on one endpoint at `effectiveMaxProbes=3` → total probes across **all** checks ≤ cap.
- **Phase 10:** round-trip one finding of each new category through `fendix report --format sarif`; assert non-empty `rules[].id` + CWE taxon. Backend drift test green.
- **SSRF test paradox (critic catch):** the SSRF in-band test sentinel is private/unroutable, which `guardedClient`'s `allowPrivate` policy *blocks*. The test harness must set `AllowPrivate=true` (or use a public-resolving sentinel) so the probe leaves the box — otherwise the test asserts the guard, not the detector.

---

## 8. Risks (consolidated)

| Risk | Mitigation |
|------|------------|
| Phase 0 mixes refactor + 3 behavior changes | Split into 0a (refactor, identical) / 0b (SSRF + addAuth, with regression tests). |
| auth/idor/openredirect/hostheader read wrong client → lose 3xx signal | Two-client `CheckContext`; redirect-semantics test; review rule. |
| New active checks share the per-endpoint budget → late checks starved | Shared-budget test at low cap; document ordering; consider per-check sub-budgets if starvation observed. |
| SSRF/host-header/method-tamper FNs read as "covered" | Each ships a documented FN acceptance test for its blind/OOB gap. |
| `checksRun` / category drift breaks backend ingest | Derive `checksRun` from filtered slice; Phase 10 syncs `_CATEGORY_MAP` (incl. the latent `data_exposure` gap) + drift test. |
| ENGINE_VERSION undercounted / GHCR ordering | grep both repos; engine tag+publish precedes backend prod build. |
| Connection-pool sharing perturbs time-based SQLi | Keep `baseline+4s` margin + confirmation re-probe; verify injection tests post-migration. |

---

## 9. Acceptance criteria (whole solution)

1. All checks implement `Check` and run through `CheckContext`; **no check constructs its own `http.Client`**; `addAuth` deleted.
2. SSRF-guard + auth-not-broken + redirect-semantics regression tests pass; all `_test.go` unedited; suite green with `-race`.
3. `DefaultChecks()` is the single registry; orchestrator filters by `Enabled`; disclaimer fires iff an active check is enabled; `checksRun` reflects the filtered set.
4. All 45 verified findings fixed (Phases 2–5), each with the load-bearing negative test from §7.
5. 7 new checks (3 proof + 4 types) registered, tiered, FP-controlled, each with documented-limit tests.
6. Phase 10: `_CATEGORY_MAP` (incl. `data_exposure`), `ImpactBase` entries, ENGINE_VERSION bumped across all verified pin sites, SARIF round-trip + backend drift test green, engine tagged/published before backend prod build.
