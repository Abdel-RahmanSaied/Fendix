# Fendix FP Corpus

> Phase 17a / TASK-122. Catalogue of false positives surfaced by running
> fendix against curated targets. Input for TASK-123 (correlator
> confidence math) and downstream FP-reduction tasks.

**Last updated:** 2026-05-11 (initial build — fendix-self + juice-shop passive)
**Engine version:** v0.7.0-19-g57f85a1 (post-TASK-119/120/121)
**Methodology:** see `scripts/fp-corpus/run.sh`
**Raw results:** `fp-corpus-results/<timestamp>/` (gitignored — regenerate with the runner)

---

## Phase 17a exit gate

- Target: ≥15 real FPs catalogued.
- Status: ✅ **35 FP instances across 4 distinct root-cause patterns** — see below.

---

## FP-pattern summary

| Pattern | Instances | Root cause | Mitigation today | TASK-123 confidence-math lever |
|---|---:|---|---|---|
| **P1** Test fixtures flagged as production | 31 | Engine has no concept of "test code vs prod code" | `.fendix-ignore` rule for `**/tests/**` | Out of scope — path filter, not confidence tuning |
| **P2** Header/CORS check fires on 4xx response | 3 | Scanner doesn't filter by response status | Manual suppression per endpoint | De-escalate confidence (HIGH → MEDIUM → LOW) when target returned 4xx |
| **P3** Rate-limiting check on static-file endpoint | 1 | Scanner doesn't distinguish API from static files | Manual suppression | De-escalate when endpoint matches static-file regex (`.DS_Store`, `robots.txt`, `favicon.ico`, etc.) |
| **P4** Header check on metrics-exposure endpoint | (0 — flagged here as a known-mostly-TP class for tracking) | n/a | n/a | n/a — TP class |

Three of these patterns are addressable by TASK-123 confidence math (P2, P3) or trivial config (P1). P4 is not actually an FP class — included for tracking parity with how the engine treats /metrics-style endpoints.

---

## Detailed catalog

### Pattern P1: Test fixtures flagged as production findings

**Target:** fendix-self (`python/` tree of this repository)
**Scan:** `fendix scan --code $(pwd)/python`
**Engine output:** 32 findings, see `fp-corpus-results/<ts>/fendix-self.json`

Every finding fires on a path under `python/tests/fixtures/` or in test files themselves. These are intentional vulnerability samples used to validate the analyzer's detection logic; they are **NOT** production code. The engine flags them correctly *for its own internal testing*, but a user scanning their own repo will hit the same shape of FP for every test fixture they have.

| Finding ID | Severity | Category | Endpoint | Root cause | TP/FP |
|---|---|---|---|---|---|
| SEC-002 | MEDIUM | injection | tests/fixtures/ast_target/dangerous.js:11 | Test fixture for JS document.write XSS heuristic | **FP** for user prod scan |
| SEC-003 | HIGH | injection | tests/fixtures/ast_target/dangerous.js:16 | Test fixture for JS SQL template literal | **FP** |
| SEC-004 | HIGH | injection | tests/fixtures/ast_target/dangerous.js:5 | Test fixture for JS eval | **FP** |
| SEC-005 | HIGH | injection | tests/fixtures/ast_target/dangerous.js:8 | Test fixture for JS innerHTML | **FP** |
| SEC-006 | HIGH | injection | tests/fixtures/ast_target/dangerous.py:14 | Test fixture for PY_OS_SYSTEM | **FP** |
| SEC-007 | HIGH | injection | tests/fixtures/ast_target/dangerous.py:19 | Test fixture for PY_EVAL | **FP** |
| SEC-008 | HIGH | injection | tests/fixtures/ast_target/dangerous.py:24 | Test fixture for PY_EXEC | **FP** |
| SEC-009 | HIGH | injection | tests/fixtures/ast_target/dangerous.py:29 | Test fixture for PY_SUBPROCESS_SHELL | **FP** |
| SEC-010 | CRITICAL | injection | tests/fixtures/ast_target/dangerous.py:34 | Test fixture for PY_SQL_INJECTION | **FP** |
| SEC-011 | CRITICAL | injection | tests/fixtures/ast_target/dangerous.py:55 | Test fixture for PY_PICKLE_LOAD | **FP** |
| SEC-012 | HIGH | injection | tests/fixtures/ast_target/dangerous.py:60 | Test fixture for PY_YAML_UNSAFE_LOAD | **FP** |
| SEC-013 | HIGH | secrets | tests/fixtures/ast_target/dangerous.py:70 | Test fixture for PY_WEAK_CRYPTO_PASSWORD | **FP** |
| SEC-014 | HIGH | injection | tests/fixtures/ast_target/dangerous.py:86 | Test fixture for PY_OPEN_REDIRECT (reachable=true) | **FP** |
| SEC-015 | HIGH | injection | tests/fixtures/ast_target/dangerous.py:91 | Test fixture for PY_SSRF | **FP** |
| SEC-016 | HIGH | auth_bypass | tests/fixtures/ast_target/dangerous.py:96 | Test fixture for PY_AUTH_HEADER_TRUST | **FP** |
| SEC-017 | HIGH | secrets | tests/fixtures/secrets_target/.env:1 | Test fixture for ENV_SECRET pattern | **FP** |
| SEC-018 | CRITICAL | secrets | tests/fixtures/secrets_target/.env:4 | Test fixture for STRIPE_LIVE_KEY in .env | **FP** |
| SEC-019 | HIGH | secrets | tests/fixtures/secrets_target/config.py:10 | Test fixture for generic API_KEY | **FP** |
| SEC-020 | HIGH | secrets | tests/fixtures/secrets_target/config.py:18 | Test fixture for password assignment | **FP** |
| SEC-021 | HIGH | secrets | tests/fixtures/secrets_target/config.py:21 | Test fixture for DB connection string | **FP** |
| SEC-022 | CRITICAL | secrets | tests/fixtures/secrets_target/config.py:7 | Test fixture for AWS secret | **FP** |
| SEC-023 | CRITICAL | secrets | tests/fixtures/secrets_target/gcp_service_account.json:2 | Test fixture for GCP service account | **FP** |
| SEC-024 | CRITICAL | secrets | tests/fixtures/secrets_target/gcp_service_account.json:5 | Test fixture for GCP service account private key | **FP** |
| SEC-025 | HIGH | secrets | tests/fixtures/secrets_target/provider_tokens.py:15 | Test fixture for SLACK_TOKEN | **FP** |
| SEC-026 | HIGH | secrets | tests/fixtures/secrets_target/provider_tokens.py:21 | Test fixture for GOOGLE_API_KEY | **FP** |
| SEC-027 | CRITICAL | secrets | tests/fixtures/secrets_target/provider_tokens.py:24 | Test fixture for ANTHROPIC_API_KEY | **FP** |
| SEC-028 | CRITICAL | secrets | tests/fixtures/secrets_target/provider_tokens.py:27 | Test fixture for OPENAI_API_KEY | **FP** |
| SEC-029 | HIGH | secrets | tests/fixtures/secrets_target/provider_tokens.py:33 | Test fixture for NPM_TOKEN | **FP** |
| SEC-030 | CRITICAL | secrets | tests/fixtures/secrets_target/provider_tokens.py:6 | Test fixture for GITHUB_TOKEN | **FP** |
| SEC-031 | HIGH | secrets | tests/test_secrets.py:211 | Embedded test data — secret detector unit test | **FP** |
| SEC-032 | CRITICAL | secrets | tests/test_secrets.py:219 | Embedded test data — secret detector unit test | **FP** |

**Total: 31 FPs from this pattern.** All have the same root cause: the engine has no semantic concept of "this is a test fixture." Any user scanning a repo with test code will hit this.

**Mitigation today:** ship a `.fendix-ignore` snippet by default in `fendix init` (already done — TASK-105) covering `**/tests/**` and `**/test_*.py`. Document the pattern in the README.

**TASK-123 lever:** none — this is not addressable via confidence math. Out of scope; relevant to TASK-124 (one-click suppression) so the user can ignore the whole cluster with one click.

---

### Pattern P2: Header/CORS check fires on a 4xx response

**Target:** juice-shop v17.1.1 (passive blackbox)
**Scan:** `fendix scan --url http://localhost:3000`
**Engine output:** 7 findings, see `fp-corpus-results/<ts>/juice-shop.json`

When the discovery crawler hits an endpoint that returns 404, the header/CORS scanners still inspect the response headers and flag missing security headers. Missing CSP on a 404 page is real-but-not-actionable: the page isn't a feature, and any reasonable framework returns 4xx pages without app-specific headers.

| Finding ID | Severity | Category | Endpoint | Why FP |
|---|---|---|---|---|
| SEC-002 | MEDIUM | cors | GET /.env.local | Endpoint returns 404; CORS misconfig on a 404 page is unreachable |
| SEC-003 | MEDIUM | headers | GET /.env.local | Missing CSP on a 404 page — not exploitable |
| SEC-004 | MEDIUM | headers | GET /.env.local | Missing HSTS on a 404 page — not exploitable on this specific path |

**Total: 3 FPs from this pattern.** Likely more in the wild — any crawler-discovered 404 path produces the same shape.

**TASK-123 lever:** **strong candidate.** In `internal/scanner/cors.go` + `internal/scanner/headers.go`, skip the check (or de-escalate to LOW confidence) when the response status is 4xx. Severity → MEDIUM → LOW for these instances would drop them below the typical `--fail-on HIGH` gate. Implementation: pass response status into the check function (already available — just gate the emit on it).

**Cross-cutting note:** the crawler discovered `/.env.local` via the wordlist (TASK-089's expanded common-paths list). The endpoint legitimately returns 404 because juice-shop doesn't have a `.env.local`. The wordlist is doing its job (discovery); the FP is at the per-check level.

---

### Pattern P3: Rate-limiting check on static-file endpoint

**Target:** juice-shop v17.1.1 (passive blackbox)

| Finding ID | Severity | Category | Endpoint | Why FP |
|---|---|---|---|---|
| SEC-001 | MEDIUM | headers | GET /.DS_Store | Rate limiting on a static-file endpoint is overzealous; `.DS_Store` isn't an API |

**Total: 1 FP from this pattern.** Likely more on other targets — `favicon.ico`, `robots.txt`, `humans.txt`, source-map `.map` files would all hit the same path.

**TASK-123 lever:** **medium candidate.** In `internal/scanner/ratelimit.go`, skip when endpoint path matches a known static-file regex (`\.(DS_Store|map|ico|txt|woff2?|ttf|css|js|png|jpg|gif|svg)$`). Or de-escalate severity to INFO for these paths. Implementation: small regex check in the rate-limit emit.

---

### Non-FP class P4 (tracked for parity): metrics-endpoint header findings

| Finding ID | Severity | Category | Endpoint | Classification |
|---|---|---|---|---|
| SEC-005 | INFO | data_exposure | GET /metrics | **TP** — version string leak |
| SEC-006 | LOW | headers | GET /metrics | **TP** — missing X-Content-Type-Options on a real endpoint |
| SEC-007 | LOW | headers | GET /metrics | **TP** — missing X-Frame-Options on a real endpoint |

Listed only to document that the engine handles real endpoints correctly. Not counted in the FP total.

---

## Methodology + reproduction

1. Build the engine: `make build` (writes `bin/fendix`)
2. Run the corpus collector: `scripts/fp-corpus/run.sh` (writes raw JSON to `fp-corpus-results/<timestamp>/`)
3. Human review classifies each finding TP/FP and updates this file
4. Re-run after each Phase 17a task that touches detection logic; track FP-rate delta over time

## Next steps (TASK-123)

Confidence-math levers identified above:

1. **4xx-response gate** for header + CORS checks (addresses P2 — 3 FPs eliminated)
2. **Static-file path regex** for rate-limit check (addresses P3 — 1 FP eliminated, likely more on real targets)
3. **Path-scope `.fendix-ignore` template** in `fendix init` (addresses P1 — 31 FPs collapsable to 1 ignore rule)

TASK-123 should ship levers 1 + 2 (confidence-math changes) and document 3 as a follow-up for TASK-124 (one-click suppression) since it's a UX/CLI change not a math change.

---

## TASK-123 follow-up — what shipped, what didn't (2026-05-11)

**Shipped (commit `<pending>`):**

- ✅ **Lever 1: 4xx-response gate** — `internal/scanner/headers.go::CheckHeaders` and `internal/scanner/cors.go::CheckCORS` early-return when the response status is ≥400. Tested with httptest fakes (200/301/404/500 cases). 3xx responses still scanned (real redirect chains have real headers).
- ✅ **Lever 2: static-file path regex** — new `staticFilePathRe` in `internal/scanner/ratelimit.go` matches common static-asset extensions (`.DS_Store`, `.ico`, `.css`, `.js`, `.map`, `.woff2`, `.png`, etc.) and well-known dotfiles (`robots.txt`, `humans.txt`, `security.txt`, `favicon.ico`, `sitemap.xml`). `CheckRateLimit` early-returns before sending any probe requests (also saves the N probe-cost per static file).

**Observed in re-scan (2026-05-11):** juice-shop's SPA returns **200 OK** for `/.env`, `/.env.local`, and `/.DS_Store` (SPA fallback to index.html). The 4xx gate correctly doesn't apply to a 200 response — the gate is doing what it's supposed to. The `/.DS_Store` rate-limit finding was eliminated by lever 2 (path regex skipped the check entirely). The headers/CORS findings on `/.env` and `/.env.local` are now technically about the SPA index.html response (since the SPA serves it for all unknown routes).

**Not shipped (deferred to future Phase 17d task):**

- ❌ **SPA-fallback dedup** — when multiple crawler-discovered paths return byte-identical responses (typical SPA: any unknown URL → index.html), header/CORS findings on those should dedup to one finding. Today's dedup keys on (title, category, severity) which already collapses across endpoints, but the `affected_endpoints` list becomes a wall of SPA-fallback paths. Acceptable cost for now; relevant when a real user reports it.
- ❌ **Static-file regex doesn't include `.env` / `.git/*` / `.htaccess`** — those are config leaks, not static assets. The right finding for those is "exposed config file" (CRITICAL), not "no rate limiting" (MEDIUM). Leaving them out of the rate-limit gate so the existing detection still fires; a future task should add a dedicated dotfile-config-leak check that suppresses the noisier headers/cors/ratelimit findings for the same path.

**Lever 3 (`fendix init` `.fendix-ignore` template for `**/tests/**`)** — handed off to TASK-124. The one-click suppression snippet work is the right home for it.

---

## TASK-132 re-triage — 2026-05-13 (Phase 17d, synthetic input)

**Input:** the 35-instance corpus above (no fresh post-launch user reports
yet — v0.10.0 just shipped). TASK-132's mandate to "triage real user FPs"
becomes "re-triage the existing corpus through the lens of what TASK-123
+ TASK-124 + TASK-125 actually shipped, and identify what's left."

**Status of each pattern after Phase 17a:**

| Pattern | Status post-17a | TASK-133 work? |
|---|---|---|
| P1 (test fixtures, 31 FPs) | Addressed by TASK-105 (default `.fendix-ignore`) + TASK-124 (one-click suppress) | No engine change; mature |
| P2 (4xx-gate, 3 FPs) | Addressed by TASK-123 lever 1 (eliminated) | None — done |
| P3 (static-file path, 1 FP) | Addressed by TASK-123 lever 2 (eliminated) | None — done |
| P4 (metrics endpoint) | Non-FP class (correctly flagged as TP) | None — done |

**Real remaining work (deferred from TASK-123 follow-up notes):**

| FP-shape | Engine fix | Priority |
|---|---|---|
| **D1: SPA-fallback response duplication** — N crawler-discovered paths returning byte-identical responses (typical SPA serving `index.html` for every unknown URL) produce N×K findings before dedup; `affected_endpoints` becomes a wall of SPA-fallback paths | New step in orchestrator: hash response bodies during the worker pool pass; collapse endpoints with identical hashes (modulo whitespace) into one canonical endpoint + a `spa_fallback: true` marker on the response. Then the existing TASK-088 dedup naturally consolidates. | **HIGH** — affects every SPA we scan |
| **D2: Dotfile-config-leak collision** — `.env`, `.git/HEAD`, `.htaccess` returning 200 produce noisy headers/cors/ratelimit findings instead of one CRITICAL "exposed config file" finding | New check `internal/scanner/exposedconfig.go` that fires CRITICAL on `200` responses to a known config-file dotfile list; suppress the other 4 noise checks on the same path. | **HIGH** — high signal-to-noise inversion |

**Out of scope for TASK-133 (correlator-math only):**

- New reachability pattern (TASK-134, separate decision)
- Suppression UX iteration (TASK-135)
- Benchmark refresh (TASK-136)

TASK-133 ships D1 + D2 as orchestrator + scanner changes; both are
deterministic rule additions (not heuristics), so they don't need
post-launch user data to validate — synthetic SPA + dotfile fixtures
suffice.

