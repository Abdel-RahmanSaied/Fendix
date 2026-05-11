# Fendix — Next Execution Phase (12–18 Months)
## Solo-Builder Path: v0.7.0 Hybrid Scanner → AI-Native Developer Security Intelligence Platform

---

## Context

Fendix today (v0.7.0, May 2026) is a **single-binary hybrid DAST+SAST scanner**, MIT-licensed, with a GitHub App, plugin system, and reachability-aware correlation. Operating posture: **solo Principal Engineer + Engineering Manager** ([tasks/AGENT_IDENTITY.md](tasks/AGENT_IDENTITY.md)). No team, no funding round committed.

The prompt asks for an "AI-native Developer Security Intelligence Platform" plan. This directly contradicts the durable non-goals decision **BACKLOG-017**, ratified in the 2026-04-30 strategic-advisor session ([tasks/MEMORY.md:1167–1190](tasks/MEMORY.md)):

> "No AI-driven anything. AI triage / LLM fix suggestions / AI FP reducer each burn 2 sprints, ship slop UX, weaken the trust story. Fendix's moat is *signal*, not *magic*."
>
> "No SaaS / multi-tenant / enterprise pivot before 1000+ GH stars."
>
> "Explicit non-goals: AI-driven triage / LLM fix suggestions, compliance dashboards, container/infra/CSPM/mobile scanning, Burp-style proxy, multi-tenant SaaS with SSO/RBAC."

**You confirmed in this session that BACKLOG-017 should be superseded.** This plan therefore:

1. Opens with **ADR-008**, the explicit supersession of BACKLOG-017, with documented trigger and new non-goals.
2. Plans the AI-native pivot **for one engineer's bandwidth** — not a 13-person team.
3. Keeps the v0.7.0 wedge ("DAST + SAST as one PR check") unchanged: still the funnel.
4. Sequences the pivot so it is **default-alive at every stage** — no quarter requires a funding event to complete.

Three hard constraints shape every section:
- **One engineer.** Every milestone fits one person + part-time contractor help; if it doesn't, defer it.
- **MIT engine stays MIT, no telemetry.** New commercial features live in `fendix-backend` (proprietary, already exists). The engine's trust capital is non-negotiable.
- **Cash discipline.** Cloud + LLM bills cannot exceed ~$500/month until paid revenue covers them. Rent everything; self-host nothing.

**Critical correction vs. original plan:** `fendix-backend` already exists and is production-ready. It is a Django 5.2 + DRF + Postgres 16 + Redis + Celery backend with auth (simplejwt RS256 + API keys), subscriptions (Free/Pro/Team/Enterprise plans, quota enforcement), scan lifecycle (Scan → Celery → ScanFinding), scheduled scans, email notifications, and a Stripe scaffold. The plan does **not** need to build a new cloud backend from scratch. Q1 foundations are ~80% done. The real Q1 work is wiring Stripe and adding the AI explanation endpoint.

Reference files I'll cite repeatedly:
- [go/internal/models/finding.go](go/internal/models/finding.go) — Finding struct, seed of the graph schema
- [go/internal/engine/correlator.go](go/internal/engine/correlator.go) — hybrid correlator + reachability (TASK-114)
- [go/internal/ghapp/handler.go](go/internal/ghapp/handler.go) — webhook → scan → comment + SARIF
- [go/internal/plugin/plugin.go](go/internal/plugin/plugin.go) — NDJSON wire contract (the seam for ingesting other scanners)
- [docs/adr/](docs/adr/) — ratified ADRs; ADR-008 is added by this plan
- [tasks/MEMORY.md](tasks/MEMORY.md), [tasks/PHASES.md](tasks/PHASES.md), [tasks/CURRENT_SPRINT.md](tasks/CURRENT_SPRINT.md) — strategic + operational state
- `../fendix-backend/backend/scanning/` — Scan, ScanFinding, ScheduledScan models + Celery tasks (already shipped)
- `../fendix-backend/backend/subscriptions/` — Plan, Subscription, UsageRecord, quota enforcement (already shipped)
- `../fendix-backend/backend/billing/` — Stripe scaffold (exists, not yet wired — Q1 priority)

---

## ADR-008 (proposed) — Supersede BACKLOG-017: Pivot to AI-Native Intelligence Plane

### Status
Proposed (2026-05-11). Supersedes BACKLOG-017 (2026-04-30) in part.

### Context
BACKLOG-017 was ratified six weeks ago, before v0.7.0 shipped. Since then:
- v0.7.0 landed with reachability + plugin system + GitHub App; the wedge is now defensible.
- The OSS distribution channel is established (MIT, signed releases, GitHub Marketplace listing pending).
- Competitive landscape has hardened around an "AI-native AppSec" framing (Aikido, Endor, Snyk's AutoFix). Staying signal-only while every adjacent tool ships AI risks ceding the category.
- The operator has decided that "AI-native intelligence plane" is the right long-term positioning.

### Decision
Supersede BACKLOG-017 with the following revised non-goals:

**Now permitted (was forbidden):**
- AI-assisted finding **explanation** (read-only, deterministic prompts, cacheable).
- AI-assisted **fix suggestion as text in PR comment** (no auto-PR, no auto-merge).
- A persistent backend (`fendix-backend`, already exists, proprietary license) that aggregates findings across a user's repos for **one tenant per install** — not multi-tenant SaaS.
- Lightweight runtime signal ingestion **opt-in only**, behind an explicit flag, off by default.

**Still forbidden (durable):**
- LLM-generated auto-PRs that merge without human review.
- Multi-tenant SaaS with SSO/RBAC/audit-log/SOC2.
- Compliance dashboards (SOC2/ISO/FedRAMP product features).
- Container scanning, CSPM, mobile scanning, Burp-style proxy.
- Any feature that requires the OSS engine to phone home.
- LLM calls from the OSS engine itself; only the cloud product calls LLMs.

### Consequences
- The OSS engine continues unchanged. It is the sensor, MIT, offline-capable.
- The existing `fendix-backend` (proprietary, already deployed) is the commercial layer. It adds: persistence, AI explanation (Q1), AI fix-suggestion-as-text (Q2), cross-scanner ingestion (Q2). Solo-operable.
- "AI-native" marketing claim is justified by **explanation + suggestion + cross-scanner correlation**, not by autonomous remediation.
- Multi-tenant SaaS is **still off-limits** until 1000+ GH stars (durable threshold from BACKLOG-017, retained). `fendix-backend` serves as **single-tenant Pro** (user-level isolation via FK, strict per-row ownership; no SSO/SAML/enterprise gates).

### Why this is the right supersession, not a full reversal
BACKLOG-017's core thesis was correct: full-autonomy AI agents burn sprints for slop UX. The supersession draws a tighter line: **read-only AI** (explain, suggest) is permitted because it cannot break a customer's code; **write AI** (auto-PR, auto-merge) remains forbidden. This keeps the trust posture while letting Fendix compete for the AI-native category.

---

## SECTION 1 — PLATFORM STRATEGY

### 1.1 Strategic Direction (one paragraph)

Fendix stops being only an OSS scanner and becomes a **two-layer product**: the MIT scanner (the sensor, trust capital, OSS funnel) and the existing closed-source `fendix-backend` (Django + Postgres, already deployed) that adds AI explanation, AI fix-suggestion-as-text, cross-scanner ingestion, and persistent dashboards. The wedge ("DAST + SAST as one PR check") stays unchanged and funnels free signups. AI is **read-only** (explain + suggest); autonomous remediation is off the table per the ADR-008 supersession.

### 1.2 Category To Own

**"Developer Security Intelligence — without the magic."** The differentiator against Aikido, Snyk AutoFix, Endor: Fendix's AI explains and suggests but never writes to your code. Trust is the wedge. The pitch:

> *"Every other AppSec tool wants to merge to your main branch. Fendix shows you what's wrong, explains why, and suggests how to fix it. You stay in control. Your engine source is on GitHub under MIT."*

### 1.3 Ideal Customer Profile (ICP)

| Dimension | ICP-Primary |
|---|---|
| Company size | 10–200 engineers |
| Stack | Polyglot (Python/Go/TS/Java), GitHub-hosted, K8s a plus but not required |
| Pain | "We installed Snyk and the dev team disabled the PR bot in 2 weeks. Too noisy. Don't trust the auto-fix." |
| Buyer | Senior dev / tech lead / VP Eng (no CISO line item in year 1) |
| Champion | The engineer who installed the OSS engine |
| Anti-ICP | Enterprises requiring SSO/SOC2 (Aikido + Snyk own); compliance-only buyers (Vanta); >500-eng orgs (insufficient solo capacity to support) |
| Annual contract size | $10–40/dev/month, self-serve, no sales call |

### 1.4 Land-and-Expand Motion

```
LAND     OSS engine + GitHub App + Marketplace listing (free, v0.7.0)
            └─► single PR check, single-binary install
                   ↓
SIGNAL   GitHub App install rate, OSS GitHub stars, plugin authorship
                   ↓
EXPAND-1 Free fendix-backend account (1 user, 3 repos cap)
            └─► dashboard + AI explanation per finding (10/mo cap)
                   ↓
EXPAND-2 Pro ($15-30/dev/month), 50 explanations/dev/month, AI fix-as-text
            └─► cross-scanner ingestion (Trivy/Grype/Semgrep imports)
                   ↓
EXPAND-3 Studio ($X/team/month), 200+ devs, plugin marketplace revenue share
            └─► reserved for after 1000 GH stars; SSO/audit are NOT included
                  (durable non-goal from BACKLOG-017, retained in ADR-008)
```

### 1.5 PLG vs Enterprise

**PLG only. No enterprise tier in 18 months.** Reason: solo founder cannot support an enterprise sale cycle (security questionnaires, BAAs, custom MSAs, procurement). Saying yes to one $100K deal absorbs 6 months of bandwidth and produces 1× revenue with no compounding. Compounding comes from PLG (the OSS engine plus self-serve cloud).

### 1.6 What NOT to Build (durable nos for 18 months)

1. **LLM auto-PR / auto-merge.** AI writes nothing to customer code. Suggestions are text in PR comments only.
2. **Multi-tenant enterprise SaaS** with SSO/SAML/SCIM/audit-export. Aikido + Snyk own this.
3. **Compliance product features** (SOC2/ISO/FedRAMP evidence engines). The opportunity cost is too high.
4. **K8s eBPF runtime agent.** Forbidden by BACKLOG-017's "no container scanning." Defer to year 2 minimum.
5. **A new graph database.** Postgres adjacency is enough.
6. **A custom query DSL.** Use SQL + natural-language → SQL via LLM.
7. **Self-hosted enterprise install.** Drains 30% of bandwidth for 5% of revenue.
8. **Mobile, Burp proxy, CSPM, IaC-first** — durable BACKLOG-017 nos, retained.
9. **An IDE extension in year 1.** Cursor/Copilot own the IDE surface; PR is the wedge.
10. **Anything that requires the OSS engine to phone home.** Telemetry stays opt-in, separate-process, transparent.

### 1.7 The Moat

The moat is **three layers**, sequenced by year:

| Moat layer | Year | Why hard to copy |
|---|---|---|
| **Trust capital** (MIT + signed + no telemetry + transparent AI) | 1 | Competitors closed-source; cannot retrofit |
| **OSS engine quality** (correlator + reachability + plugin ecosystem) | 1 | TASK-114's reachability is already 6–12 months for competitors |
| **Cross-scanner intelligence** (one inbox across Snyk/Trivy/Semgrep/Gitleaks results) | 2 | Schema + dedup quality compounds over time |

**No "outcome dataset" moat in this plan.** That requires AI auto-PRs (ADR-008 forbids) plus enterprise-scale customer data (PLG-only constraint prevents). It is a real moat for Snyk/Cursor; it is not available to a solo MIT-engine-first product.

### 1.8 Sequencing logic

1. **Operator-rollout completion first.** Five steps from [CURRENT_SPRINT.md](tasks/CURRENT_SPRINT.md) (GitHub App registration → Fly.io deploy → Marketplace submit → seed-issues → launch post). Without these, no funnel.
2. **Cloud backend before AI.** Need persistence before storing AI explanations.
3. **AI explanation before AI suggestion.** Explanation is risk-free (no code-rewrite). Suggestion-as-text is medium-risk (still no merge).
4. **Cross-scanner ingestion before more native checks.** Customers already pay Snyk/Trivy; meet them there.
5. **Plugin ecosystem grows the OSS engine** in parallel — but as community contribution, not core engineering.

---

## SECTION 11 — ROADMAP & EXECUTION PLAN

Placed early because every other section depends on the quarter it lands in.

### 11.1 Quarterly Roadmap (months 0–18)

#### Q0 — "Land the v0.7.0 Launch" (next 2–4 weeks, this sprint)

This is the **current** [tasks/CURRENT_SPRINT.md](tasks/CURRENT_SPRINT.md) sprint, not new work. Do not pivot until this lands.

| Step | Source |
|---|---|
| Register GitHub App on github.com | CURRENT_SPRINT step 6 |
| Deploy fendix-app via Fly.io | `./scripts/deploy-app.sh` |
| Submit Marketplace listing | CURRENT_SPRINT step 8 |
| Run seed-issues.sh on public repo | CURRENT_SPRINT step 9 |
| Publish launch post to HN/r/devops/r/golang | `docs/launch-post.md` |

**Exit criteria Q0:** Public Marketplace listing live, launch post published, ≥250 GH stars within 2 weeks, ≥20 GitHub App installs. **If Q0 underperforms** (e.g., <100 stars, <10 installs), the AI-native pivot in Q1 should be reconsidered — solo bandwidth cannot save an unsuccessful launch with new features.

#### Q1 (months 0–3) — "Wire Stripe + Ship AI Explanation"

Theme: `fendix-backend` is already running — auth, scans, subscriptions, quota enforcement are done. Q1 closes the two remaining gaps: revenue collection (Stripe) and the first AI feature (explanation).

**What already exists in `fendix-backend` and does NOT need to be built:**

- Postgres 16 + Django ORM — `Scan`, `ScanFinding`, `ScheduledScan`, `ReportArtifact` models ✓
- Auth — simplejwt RS256 + `fx_`-prefixed API keys (SHA-256 hashed at rest) ✓
- Plan tiers — Free / Pro / Team / Enterprise with `PlanFeature` + `UsageRecord` quota ✓
- Async job queue — Celery 5.4 + Redis (no new queue infrastructure needed) ✓
- Scan lifecycle — `POST /api/scans` → Celery → engine subprocess → `ScanFinding` bulk-create ✓
- Scheduled scans — `ScheduledScan` + `django_celery_beat` ✓
- Email notifications — completion + critical-finding alert ✓
- Frontend dashboard — Next.js 16 consuming the DRF OpenAPI contract ✓

| Workstream | Deliverable | Estimate (solo days) |
|---|---|---|
| Wire Stripe Checkout | `billing/` scaffold already exists with `stripe_subscription_id` + `stripe_customer_id` on `Subscription`. Add webhook handler for `checkout.session.completed` + `customer.subscription.updated/deleted`. Handle dunning (failed payments, grace period). Replace `UpgradeRequest` manual-approve flow with self-serve checkout. | 9 |
| AI explanation endpoint | New `POST /api/findings/:id/explain` view in `scanning/`. Calls Claude Haiku 4.5 with prompt caching. Response cached by `(finding_hash, model_version)` in a new `FindingExplanation` model (`UniqueConstraint` guards idempotency). Add `"ai_explanation"` `PlanFeature` key to seed plans: Free tier value = `"10"`, Pro = `"50"`. Quota enforced via `ai_explanations_used` on `UsageRecord` — same `F()+1` atomic pattern as `scans_used`. **No separate feature gate** — both Free and Pro can explain; only the monthly cap differs. | 5 |
| `ai_explanations_used` quota meter | Add field to `UsageRecord`. Add `check_explanation_quota()` helper mirroring `check_scan_quota()`. Wire into the explain view before calling Anthropic. | 2 |
| `taint_chain` + `reachable` on `ScanFinding` | Engine emits these fields since TASK-114 but backend model doesn't store them. One migration: add `reachable BooleanField(default=False)` + `taint_chain JSONField(default=list)`. Update `services.FendixEngine` to parse and persist. Old findings show `reachable=False` — correct, not misleading. | 2 |
| ADR-008 written into [docs/adr/](docs/adr/) | This plan's ADR section, formalized | 1 |
| OSS engine v0.8 maintenance | P0 bug fixes only | 4 |

**Note on OpenAPI sync overhead:** Every backend serializer/view change requires `make schema` → commit `openapi.json` → `cd ../fendix_frontend && npm run codegen` → commit `api.ts`. Budget ~30 min per Q1 feature for this loop. It is mandatory per the backend `CLAUDE.md` contract — do not skip it.

**Note on Q0/Q1 parallelism:** Marketplace review takes 1–2 weeks after submission. Stripe wiring and the `taint_chain` migration have zero dependency on Marketplace approval — start those in parallel during the review window. Do not start AI explanation work until Q0's launch post is published (the funnel must be open before adding paid features).

**Total Q1: ~23 solo days ≈ 5–6 weeks at 70% capacity** (leaving 30% for community, marketplace ops, support).

**Exit criteria Q1:**

- A free user signs up, runs a scan, sees findings in the dashboard, clicks any finding, reads an AI explanation.
- Self-serve Stripe Checkout works end-to-end for Pro upgrade.
- First 5 paid Pro signups.
- ≥500 GH stars on OSS engine.
- Total LLM bill < $50/month.
- `taint_chain` and `reachable` visible in the dashboard for correlated findings.

**What is intentionally NOT in Q1:**

- No new backend framework, no new repo, no new language. Django is the backend.
- No SARIF imports from other scanners (Q2).
- No AI fix suggestions (Q2).
- No runtime, no compliance, no enterprise.

#### Q2 (months 3–6) — "AI Fix-as-Text + Cross-Scanner Ingestion"

Theme: monetize by being where competing tools' results converge.

| Workstream | Deliverable | Solo days |
|---|---|---|
| AI fix-as-text | Per-finding "AI Suggest" button → Claude Sonnet 4.6 + prompt cache → suggested code block in PR comment, never auto-merged. Includes "Mark helpful / not helpful" feedback button. | 6 |
| Multi-scanner ingestion: Trivy | First-class importer. Trivy SARIF or JSON → Fendix finding model. Dedup by CVE+package+version. | 4 |
| Multi-scanner ingestion: Gitleaks, Semgrep | Same pattern. | 4 |
| Multi-scanner ingestion: Snyk SARIF | The Trojan-horse import. "Keep Snyk; we just make it useful." | 3 |
| EPSS + KEV enrichment | Daily cron pulls FIRST.org EPSS + CISA KEV; lookup at finding-store time. | 3 |
| Priority Inbox | Replace "list of findings" with "what to fix today, ranked by severity × EPSS × KEV × reachability." This is the non-commodity UX moment. | 5 |
| Stripe Pro tier expansion | Add seat-based metering. | 2 |
| OSS engine v0.9 | Native govulncheck/pip-audit/npm-audit (already in plan.md P1.6) | 6 |

**Total Q2: ~33 solo days.** Easier quarter; Q1 is the heaviest.

**Exit criteria Q2:**
- A user imports their Snyk SARIF, sees 50K findings reduced to a ranked Priority Inbox of ~200 actionable items.
- Pro tier monthly recurring revenue (MRR) ≥ $1K.
- ≥1000 GH stars (BACKLOG-017's threshold for considering Studio tier, retained).
- LLM bill < $200/month.

#### Q3 (months 6–9) — "Studio Tier + Plugin Marketplace"

Theme: monetize the plugin ecosystem; broaden the funnel.

| Workstream | Deliverable | Solo days |
|---|---|---|
| Plugin marketplace v1 | The `fendix-backend` dashboard lists community plugins with author, downloads, ratings. Plugins remain user-installable (no cloud-side execution — still local subprocess, ADR-002 contract). | 8 |
| Paid plugin revenue share | Stripe Connect. Plugin authors set price; Fendix takes 20%. | 6 |
| Studio tier ($X/team/month) | Multi-user same-org account (still single tenant per company; not multi-tenant SaaS — distinction preserved). Shared inbox, shared policies. | 6 |
| Saved query / triage workflows | "Find me all findings on services tagged 'production' from Snyk import where EPSS > 0.5." | 4 |
| Community Semgrep rule pack | Curated, dual-licensed via the plugin system. | 5 |
| OSS engine v1.0 | Tag the 1.0 — only after 6+ months of stable v0.7-v0.9 in the field. | 2 |

**Total Q3: ~31 solo days.**

**Exit criteria Q3:**
- Plugin marketplace live with ≥15 community plugins.
- Studio tier MRR ≥ $5K.
- Total MRR ≥ $10K (default-alive for one founder).
- OSS engine v1.0 tagged.

#### Q4 (months 9–12) — "Quality + One Optional Big Bet"

Theme: catch breath, prioritize what's working, pick **one** bet.

By Q4 you'll have ~9 months of usage data. **Pick exactly one** of the following as a Q4 bet — not all:

1. **Lightweight runtime opt-in:** a `fendix-agent` Docker sidecar (NOT a K8s eBPF DaemonSet — that's BACKLOG-017-forbidden) that watches your own CI/CD logs for which packages were imported, sends back "loaded vs not" signal. Local-first, opt-in, single-tenant. ~25 solo days.
2. **AI-assisted custom rule writing:** "Write me a Fendix plugin that detects X." Generates plugin scaffold. Drives plugin marketplace adoption. ~15 solo days.
3. **GitLab + Bitbucket parity:** unlock segments locked out of GitHub-first. ~20 solo days.
4. **First contractor hire** with the MRR cushion: a part-time DevRel / content / community person to grow the funnel while you stay in the code. ~$3-5K/month for 10 hrs/week.

**Default recommendation: option 2** (AI-assisted custom rules) — it compounds with the marketplace, fits "AI-native intelligence" framing, and is the smallest scope. Option 4 (contractor hire) should happen *regardless* of which bet you pick, as soon as MRR clears $8K.

**Exit criteria Q4:**
- One Q4 bet shipped.
- MRR ≥ $15K.
- ≥2000 GH stars.
- 6-month customer churn measured; <10% target.

#### Q5–Q6 (months 12–18) — "Sustain or Pivot"

By month 12 you have data to make the real decision:

| If by month 12... | Then Q5–Q6 path |
|---|---|
| MRR $15-30K, churn <10%, OSS stars >2000, no enterprise inbound | **Sustain.** Polish, plugin ecosystem, sustain growth. Bring on one contractor. Year 2 plan from a position of strength. |
| MRR $30K+, enterprise inbound, founder bandwidth tapped | **Raise + hire.** Pre-seed/seed round, 2-3 hires. Re-evaluate BACKLOG-017 enterprise nos. Plan Year 2 from funded position. |
| MRR <$10K, slow growth | **Pivot or fold.** This plan failed; either re-focus on OSS-only and consult on the side, or shut down cleanly. Be honest with yourself by month 14, not month 24. |

### 11.2 Dependency Graph

```
[Q0: Marketplace launch]
        ↓
[Q1: fendix-backend Stripe + AI explanation] ── relies on ──► OSS engine v0.7+ (already shipped)
        ↓
[Q2: AI suggest + multi-scanner ingest + priority inbox]
        ↓
[Q3: plugin marketplace + Studio tier]
        ↓
[Q4: one big bet] ─── optionally ──► [first contractor]
        ↓
[Q5–Q6: sustain or raise+hire]
```

### 11.3 Staffing — the honest version

**Months 0–9: solo.** No hires. No co-founder unless one materializes organically.
**Month 9–12 (if MRR clears $8K): one part-time contractor.** DevRel/content first; not engineering.
**Month 12+ (if MRR clears $30K and enterprise inbound exists): consider raising + hiring.**

There is **no** "Founding AI Engineer / Founding Backend / Founding Frontend" hire in this plan. That was the original draft's biggest disconnect from reality.

### 11.4 Budget (real numbers, solo)

| Category | Year 1 | Year 2 (if sustaining) |
|---|---|---|
| Cloud hosting (Fly.io, Supabase, Cloudflare) | $50-200/month | $200-500/month |
| LLM API (Claude Haiku + occasional Sonnet) | $50-300/month | $300-1000/month |
| Stripe fees | 2.9% + 30¢ × MRR | ~same |
| Domain + email + tools | $50/month | $100/month |
| Compliance/SOC2 | **$0** (we're not pursuing this) | $0 |
| Contractor (Q4 onward) | $0-5K/month | $5-10K/month |
| Founder salary | $0 (you fund yourself) | from MRR if it's there |
| **Monthly burn floor** | **$200-500** | **$1-2K + contractor** |

This is the **default-alive** posture: $500/month burn = $6K/year survives on freelance income. Compare with the original draft's $1.8M Year-1 budget — that draft assumed funding that doesn't exist.

### 11.5 Highest-Leverage Bets vs. Postpone

| **Do first** | **Postpone or skip** |
|---|---|
| Q0 launch operations (this sprint) | Multi-tenant enterprise SaaS |
| Cloud backend foundations (Q1) | K8s eBPF runtime agent |
| AI explanation (Q1) — read-only, low-risk | Compliance evidence engine |
| Cross-scanner ingestion (Q2) | Custom query DSL |
| Priority Inbox UX (Q2) | A graph database |
| Plugin marketplace (Q3) | Custom RBAC system |
| OSS engine v1.0 tag (Q3) | Multi-region SaaS |

### 11.6 Technical Debt Traps (specific to solo)

1. **Don't rewrite the backend.** Auth (simplejwt RS256 + API keys), subscriptions, quota, scan lifecycle, Celery queue — all exist and are tested. Django is not glamorous; it is done. Rewriting in Go to match a plan that was written before you checked what existed would be a quarter of wasted work.
2. **Don't put LLM calls in the request path.** Always async via Celery. User gets a `202 Accepted` with `explanation_id`; frontend polls `GET /api/findings/:id/explain`. One synchronous 30-second Claude call in a DRF view is a P0 incident waiting to happen.
3. **Don't pick Neo4j or any graph DB.** Postgres adjacency is fine for 18 months.
4. **Don't skip the OpenAPI sync loop.** Every backend change requires `make schema` → `npm run codegen` → commit both. Skipping it breaks the frontend's `api.ts` types silently — you won't notice until a runtime error in prod.
5. **Don't create a `--cloud-token` CLI upload path.** The backend runs the engine via Celery (`POST /api/scans` → `FendixEngine().run()`). A second upload path (user runs locally, posts JSON) creates two code paths that diverge over time. If users want cloud persistence, they use the GitHub App or the dashboard — not a secret upload token.
6. **Don't conflate the OSS engine and the backend.** Two repos, two licenses, versioned JSON report contract between them. Engine speaks no cloud dialect; backend drives the engine as a subprocess.
7. **Resist the urge to add a new feature whenever a community user requests it.** OSS engine: bug fixes + one new feature per quarter. Backend: roadmap only. Everything else goes to BACKLOG.

---

## SECTION 2 — CORE PLATFORM ARCHITECTURE

### 2.1 Topology (solo-operable)

```
                    ┌──────────────────────────────────────────────────┐
                    │              fendix-backend (already deployed)    │
                    │                                                  │
                    │  ┌──────────────────────────────────────────┐    │
                    │  │   Django 5.2 + DRF  (django + celery +   │    │
                    │  │                      celery-beat)         │    │
                    │  │   - simplejwt RS256 + API key auth        │    │
                    │  │   - /api/scans, /api/findings, ...        │    │
                    │  │   - Stripe webhooks (Q1 — wire now)       │    │
                    │  │   - /api/findings/:id/explain (Q1 — new)  │    │
                    │  └──────────────────────────────────────────┘    │
                    │                    │                              │
                    │       ┌────────────┼────────────┐                 │
                    │       ▼            ▼            ▼                 │
                    │  Postgres 16    Redis        Anthropic API        │
                    │  (models:       (Celery      (Claude — Q1)        │
                    │  Scan,          broker)                           │
                    │  ScanFinding,                                     │
                    │  Subscription)                                    │
                    └──────────────────────────────────────────────────┘
                                        ▲
                                        │ HTTPS + JSON
                    ┌───────────────────┴──────────────────────────┐
                    │           fendix_frontend (Next.js 16)        │
                    │  Consumes DRF OpenAPI contract (api.ts)       │
                    └──────────────────────────────────────────────┘

   ─── Customer side (unchanged from today) ───
        ┌──────────────────────────┐    ┌─────────────────────────────┐
        │ fendix CLI (OSS, MIT)    │    │ fendix-app (OSS, GitHub App)│
        │ + plugin sandbox         │    │ webhook → scan → comment    │
        └────────────┬─────────────┘    └────────────┬────────────────┘
                     │ offline only (no upload)       │ POST /api/scans (GitHub webhook)
                     │                                │
                     └──────────────┬─────────────────┘
                                    ▼
                       POST /api/scans  (JSON report)
```

### 2.2 Service Inventory — What Already Exists

**There is one cloud service.** `fendix-backend`. Django monorepo. Three processes (django + celery + celery-beat), all sharing one Postgres 16 and one Redis. Already running.

Django apps within `fendix-backend/backend/`:

- `scanning/` — `Scan`, `ScanFinding`, `ScheduledScan`, `ReportArtifact`; `FendixEngine` subprocess wrapper; Celery tasks
- `subscriptions/` — `Plan`, `PlanFeature`, `Subscription`, `UsageRecord`; quota enforcement (`check_scan_quota`, `require_feature`)
- `billing/` — Stripe scaffold; `stripe_subscription_id` + `stripe_customer_id` on `Subscription` (wire in Q1)
- `accounts/` — `CustomUser` (UUID pk, email auth), simplejwt RS256, API keys
- `common/` — pagination, middleware (request-ID, CSP), shared base models
- `config/` — settings (base/development/production), URLs, Celery, ASGI/WSGI

**New Django apps to add (Q1–Q2):**

- `explain/` — `FindingExplanation` model; Claude Haiku calls with prompt caching; quota enforcement (Q1)
- `ingest/` — SARIF import adapters for Trivy, Gitleaks, Semgrep, Snyk (Q2)
- `enrich/` — EPSS/KEV daily Celery Beat task (Q2)

### 2.3 Communication Protocols

| Boundary | Protocol | Why |
| --- | --- | --- |
| Browser → backend | HTTPS + JSON (DRF) | Frontend is Next.js — already consumes the OpenAPI contract |
| CLI / GitHub App → backend | HTTPS + JSON (`POST /api/scans`) | Existing contract; no new format needed |
| LLM | Anthropic Python SDK | Prompt caching is decisive for cost |
| Stripe | webhook (HMAC verified via `stripe-signature`) | Standard; scaffold in `billing/signing.py` already exists |
| Celery | Redis broker + result backend | Already wired; no new infra |
| No gRPC, no NATS, no Kafka, no Temporal | — | Not needed; Celery + Redis is the queue |

### 2.4 Sync vs Async

| Sync (user waits) | Async (Celery task) |
| --- | --- |
| Dashboard reads (`GET /api/scans`) | AI explanation generation (`explain.tasks.generate_explanation`) |
| Auth flows | Cross-scanner SARIF ingest of large files (Q2) |
| Scan creation ack — returns `scan.id`, status=QUEUED | EPSS/KEV nightly enrichment (Q2, Celery Beat) |
| Stripe webhook ack | Scan execution (`scanning.tasks.execute_scan`) |

All async work uses Celery 5.4 + Redis. No new queue infrastructure. Idempotent tasks only — explanation task checks `FindingExplanation.objects.filter(finding_hash=..., model_version=...)` before calling Anthropic.

### 2.5 Tenancy Model

**User-level isolation.** Every model row is owned by `user` (UUID FK). `IsAuthenticated` + `require_feature()` is the auth/permission stack — already enforced on every view. This is not multi-tenant SaaS in the BACKLOG-017 sense — no SSO, no SAML, no audit-log export. The Studio tier (Q3) extends this with shared org accounts but still no SSO/SAML.

### 2.6 Caching

| Cache | TTL | Notes |
|---|---|---|
| AI explanations by `(finding_hash, model_version)` | forever (DB row) | Same finding gets same explanation; cost win |
| Anthropic prompt cache (provider-native) | 5 min default | Critical for cost — Section 4 |
| EPSS/KEV | 24h | Daily Celery Beat refresh (Q2) |
| DRF list responses | 30s via Cloudflare (in front of nginx) | Reduces DB load |

### 2.7 Failure Handling (solo-grade, not enterprise-grade)

- **Idempotency:** `FindingExplanation` has a `UniqueConstraint(fields=["finding_hash", "model_version"])`. Celery task checks existence before calling Anthropic — safe to retry.
- **Retries:** All LLM Celery tasks use `autoretry_for=(Exception,)` with exponential backoff, max 3 retries.
- **Degraded mode:** Anthropic down → explanation task stays in Celery retry queue; user sees "generating…" in dashboard. No scan blocking.
- **No multi-AZ, no DR.** Single region (existing deployment). Daily Postgres backup. RTO 4 hours, RPO 24 hours — acceptable for a $20/dev/month product.

### 2.8 Observability (solo-grade)

- Logs: existing `logs/` Django app + structured logging already in place.
- Errors: Sentry (already configured in `config/settings/_helpers/sentry_config.py`).
- Metrics: existing `monitoring/` app + health-check views.
- Traces: skip until 5+ engineers.
- Uptime: Better Stack free tier or UptimeRobot.

### 2.9 What's Explicitly Cut (vs. original draft's proposed fendix-cloud)

- New Go monorepo → Django already exists; don't rewrite what works
- Clerk for auth → simplejwt RS256 + API keys already exist in `accounts/`
- htmx dashboard → Next.js 16 frontend already consumes the DRF OpenAPI contract
- Postgres SKIP LOCKED job queue → Celery + Redis already wired
- Supabase / Fly.io managed Postgres → existing Postgres deployment already runs
- Cloudflare R2 for artifacts → `ReportArtifact` stores bytes in Postgres `bytea` (fine at solo scale; migrate to S3 if >10 MB average)
- Firecracker microVMs → no sandbox, because no auto-PR (ADR-008 forbids)
- Multi-region → single region in year 1
- BYOK → not until enterprise (not in plan)
- Multi-agent orchestration → no agents (ADR-008 forbids auto-PR)

This list is **the value of the correction**: you are not starting over, you are extending what already works.

---

## SECTION 3 — SECURITY GRAPH DESIGN (deferred, mostly)

### 3.1 The Honest Take

A real security graph is correct architecture for an AI-native intelligence platform. It is also 6+ engineer-months. **For a solo founder, year 1 does not have a graph.** It has Postgres with adjacency tables and a clear plan to grow into one.

This is in tension with the prompt's "Design the next-generation Fendix Security Graph in extreme detail." I'm choosing **realistic over impressive** because the original-draft graph design fits a team of 4, not a team of 1.

### 3.2 Year-1 Schema (Postgres only)

```sql
-- entities + edges, RLS-isolated by org_id
CREATE TABLE entities (
  id           UUID PRIMARY KEY,
  org_id       UUID NOT NULL,
  type         TEXT NOT NULL,        -- 'repo','service','endpoint','package','vuln','finding','secret'
  external_key TEXT NOT NULL,        -- e.g. 'CVE-2024-1234'
  props        JSONB NOT NULL,
  created_at   TIMESTAMPTZ DEFAULT now(),
  updated_at   TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX ON entities (org_id, type, external_key);
CREATE INDEX ON entities USING GIN (props);

CREATE TABLE edges (
  id          UUID PRIMARY KEY,
  org_id      UUID NOT NULL,
  src_id      UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  dst_id      UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  rel         TEXT NOT NULL,         -- 'contains','exposes','affected_by','reaches'
  props       JSONB NOT NULL,
  observed_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX ON edges (org_id, src_id, rel);
CREATE INDEX ON edges (org_id, dst_id, rel);

ALTER TABLE entities ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_iso ON entities USING (org_id = current_setting('app.org_id')::uuid);
ALTER TABLE edges ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_iso_e ON edges USING (org_id = current_setting('app.org_id')::uuid);
```

### 3.3 Relationships Populated in Year 1

- `Repo ─contains─► Finding` (always)
- `Repo ─declares─► Package ─affected_by─► Vulnerability` (when SBOM available)
- `Finding ─evidenced_by─► TaintChain` (already in Finding struct today)

Skip: `Service`, `Endpoint─reaches─►Endpoint`, `Identity`, `RuntimePod`. These are year-2+ when there's bandwidth.

### 3.4 Reachability (already shipped)

[engine/correlator.go](go/internal/engine/correlator.go) already proves intra-function taint chains for SQLi, SSRF, open-redirect via TASK-114. **This is the year-1 reachability story.** Network reachability (which endpoints are exposed) and runtime reachability (which packages are loaded) are explicitly deferred to year 2+.

### 3.5 Scoring (extended from today's [models/scoring.go](go/internal/models/scoring.go))

```
fendix_score = severity_base
             * confidence_multiplier
             * source_multiplier
             * (1 + epss_score)            # NEW Q2: EPSS scaled 0–1
             * (1.5 if kev_listed else 1)  # NEW Q2: CISA KEV bonus
             * (1.5 if reachable_code      # already exists today (TASK-114)
                else 1.0)
```

Network/runtime multipliers are NOT in year 1.

### 3.6 Graph DB Migration Plan: There Isn't One Yet

Postgres adjacency holds through Q6 at solo scale. If MRR clears $30K and a team forms, evaluate Memgraph or AGE-on-Postgres at that point — explicitly out of scope for this 18-month plan.

### 3.7 Why a Graph Is Still the Moat Direction (just not yet)

The two-table schema above is forward-compatible: a graph DB migration in year 2 is `SELECT * FROM entities/edges → INSERT INTO graph_db`. Schema choice today doesn't block that future.

---

## SECTION 4 — AI EXPLANATION & FIX-SUGGESTION SYSTEM

### 4.1 What This System Is (and Is NOT)

**Is:** Generate natural-language explanation of a finding (Q1). Generate a suggested code fix *as text in a PR comment* (Q2). Both opt-in, both gated by Pro tier or quota.

**Is NOT:** AI agents that open PRs. AI auto-merge. Multi-agent orchestration. Sandbox validation. Outcome-feedback ML loop. All forbidden by ADR-008.

This section is deliberately scoped down from the original draft — that one designed an AI remediation pipeline that requires Firecracker sandboxes, Temporal workflows, regression-risk judges, and confidence weighting. **A solo founder cannot operate that, and ADR-008 forbids the auto-PR endpoint it serves.**

### 4.2 Design Principles

1. **Read-only AI.** AI never writes to your code. The user copies the suggestion if they want it.
2. **Deterministic prompts.** Same input → same prompt → cacheable output. No agent loops, no tool use, no multi-turn.
3. **Cost discipline.** Aggressive prompt caching, response caching, model routing. LLM bill < $300/month through Q2.
4. **Transparency.** Every AI output shows: model, prompt version, token cost, "Was this helpful?" button.

### 4.3 Model Routing

| Task | Model | Why |
|---|---|---|
| Finding explanation | Claude Haiku 4.5 | Cheap, fast, sufficient |
| Fix suggestion (Q2) | Claude Sonnet 4.6 | Code reasoning needs more capability |
| Embeddings | Not used in year 1 | RAG postponed; finding context is small |

No fallback provider in year 1 — single vendor (Anthropic) is fine at solo scale. Add fallback only when first 4-hour Anthropic outage actually causes user pain.

### 4.4 Prompt Design (the actual work)

**Static system prompt** (cached, ~2K tokens):
```
You are a senior application security engineer explaining a vulnerability to
a developer on their pull request. You will be given a Fendix finding in
JSON form. Output: 1) a 100-word explanation of the issue and why it
matters, 2) one specific, minimal code change that addresses it. The
suggestion must be a code block in the user's language. Do not invent
APIs, function names, or imports. If the finding's evidence is too sparse
to suggest a safe fix, say so explicitly.
```

**Per-finding user turn** (NOT cached, ~500-2K tokens):
```
Finding: {finding_json}
Code context: {function_body_from_taint_chain}
Language: {primary_lang}
```

**Cache breakpoints:** static system prompt at 1; user turn at 2. 5-min TTL, automatic.

### 4.5 Cost Math (real numbers)

Per Pro tenant assumption: 50 devs × 4 explanations/dev/month = 200 explanations.
- Haiku 4.5: $0.80/M input + $4/M output (estimate).
- Per explanation: ~3K cached input + ~1K fresh input + ~500 output.
- Cost per explanation: ~$0.005.
- Cost per Pro tenant per month: ~$1.

Suggestion (Q2) costs more (Sonnet, larger context): ~$0.15 per suggestion. 50 suggestions/tenant/month = $7.50/tenant/month.

Hard caps: per-tenant monthly token budget. Per-explanation rate limit. Auto-throttle on cost spike.

### 4.6 No Sandbox, No Outcome Dataset

The original draft's Plan → Patch → Validate → PR pipeline + outcome capture + learning loop is **all cut** by ADR-008. The user reads the suggestion, copies it (or not), and that's the entire flow.

**This is a deliberate strategic concession.** It means Fendix cannot build the "outcome dataset moat" that Cursor or Snyk AutoFix build. The compensating moat (per Section 1.7) is trust, OSS quality, and cross-scanner intelligence.

### 4.7 Preventing Hallucinations (within the read-only constraint)

- **Constrained output:** JSON-schema for response (explanation + suggested_code + language + caveats).
- **No new APIs:** prompt biases hard toward using only what's in the provided code context.
- **Caveats surfaced:** every suggestion shows "AI-generated. Review before applying."
- **"Not helpful" feedback button:** stored per (finding_hash, prompt_version). Used manually by you to identify bad prompts. Not auto-fed to a model — that's the outcome loop ADR-008 cut.

### 4.8 What Comes Back Year 2+

When and if BACKLOG-017 is further superseded (or revenue/funding justifies team expansion), the elements deferred here are:

- Sandbox validation of AI suggestions
- Auto-PR generation
- Outcome dataset + learning loop
- Multi-agent orchestration

These are documented as **future ADR triggers**, not as Year 1 commitments.

---

## SECTION 5 — RUNTIME SECURITY & CORRELATION (mostly deferred)

### 5.1 Honest Reality

BACKLOG-017 forbids container/CSPM/mobile scanning. ADR-008 supersedes the AI bits but **keeps the runtime-scanning prohibition** intact. K8s eBPF agents are not in this plan.

What can happen in year 1: **local-side runtime hints**, not cloud-side telemetry.

### 5.2 The Single Year-1 Runtime Feature: `fendix scan --import-loaded`

A CLI flag that reads `runtime.json` (a user-generated file from `pip list --json` or `npm list --json` or `go version -m`) and marks packages as "loaded" so the scanner can downgrade findings on unloaded packages.

```bash
# User generates the loaded-package manifest, however they want
$ pip list --json > runtime.json    # or any equivalent
$ fendix scan --code . --import-loaded runtime.json
```

This is:
- Engine-side, not cloud-side.
- User-generated input, not telemetry.
- Honors no-telemetry promise.
- Provides ~80% of the value of a real runtime agent at 1% of the engineering cost.
- Solo-shippable in 2-3 days.

### 5.3 Q4 Optional Bet: Sidecar Container

If Q4's chosen bet is "lightweight runtime opt-in" (Section 11.1's option 1), implement as a Docker sidecar that reads `/proc/.../maps` in customer CI (not in customer prod K8s). Local-only, opt-in, signed binary, no phone-home. Still not a K8s DaemonSet.

### 5.4 Falco, eBPF, Tetragon, IAM correlation

**Not in this plan.** All multi-engineer-quarter items. Revisit in year 2 if MRR + funding support team expansion. Document this clearly in the README so customers don't expect runtime correlation as a year-1 feature.

### 5.5 Attack-Chain Modeling

Skip. Reachability today (TASK-114's taint chain) is enough story for year 1. The graph traversal narrative ("if this gets popped, billing service is reachable") requires the `Service ─calls─► Service` and `Identity ─grants─► Resource` edges that are not populated until year 2+.

---

## SECTION 6 — MULTI-AGENT SECURITY SYSTEM (entire section deferred)

ADR-008 forbids the autonomous-PR endpoint that justifies a multi-agent system. Without auto-remediation, agents become over-engineering — every interaction is a one-shot LLM call with deterministic output.

**Year 1 has no agents.** It has:
- One function: `Explain(finding) → Explanation`
- One function (Q2): `Suggest(finding) → SuggestedFixText`

Both are stateless DRF views in `fendix-backend`. Neither is "an agent" in the multi-agent-system sense.

The multi-agent architecture in my prior draft (Detection / Correlation / Remediation / Runtime / Compliance / Governance / Learning / Exploit Simulation / Security Copilot) is **all cut**. It belongs in a year-2-team-of-5 plan, not a year-1-solo plan.

The only thing approaching "agent" worth shipping in year 1 is **a chat interface** ("Fendix Copilot Lite"): natural-language queries over the user's findings. ~5 solo days in Q3 if there's bandwidth. Pattern: NL question → LLM translates to parameterized SQL → execute → format → render. No tool use, no multi-turn agent loop.

---

## SECTION 7 — AUTONOMOUS SECURITY OPERATIONS (deferred)

ADR-008 caps autonomy at **Level 1 (Suggest)** on the autonomy ladder:

| Level | Behavior | Year 1? |
|---|---|---|
| L0 — Detect | Find findings | ✓ today |
| L1 — Suggest | Suggest fixes in PR comment (text only) | ✓ Q2 |
| L2 — Draft | Open draft PRs | **forbidden by ADR-008** |
| L3 — Propose | Open ready PRs | forbidden |
| L4 — Auto-merge | Merge with confidence > X | forbidden |
| L5 — Auto-rollback | Detect post-merge failures, revert | forbidden |

**The autonomous-operations product line is cut.** This is the single largest strategic concession in this rewrite. Competitors (Snyk AutoFix, Aikido) will ship L2-L4; Fendix's positioning becomes "the trustworthy alternative" — read-only, MIT-engine, no auto-write.

If this concession proves wrong (customers demand L2+, revenue depends on it), supersede ADR-008 in year 2 with a follow-up ADR. Do not silently drift.

---

## SECTION 8 — DEVELOPER EXPERIENCE

### 8.1 Core Principles (unchanged from prior draft — they survive solo scale)

1. **PR is the primary surface.** Most users never log in.
2. **No finding without context.** If we can't explain, say why.
3. **Latency is a feature.** PR comment < 2 minutes from push.
4. **Trust is the wedge.** No auto-write. No telemetry. Signed binaries. MIT engine.
5. **Noise is bankruptcy.** Bias under-alerting.

### 8.2 Surfaces (sized for solo)

| Surface | Priority | Status |
|---|---|---|
| GitHub PR check + comment | P0, exists | v0.7.0 |
| Web dashboard (htmx) | P0, Q1 | new |
| CLI | P0, exists | v0.7.0 |
| Slack notifications | P1, Q2 | basic webhook |
| GitLab support | **defer** | Q4 bet only |
| IDE extension | **defer** | year 2+ |
| Mobile, Teams, Linear | **defer** | year 2+ |

### 8.3 PR Comment UX (extended from v0.7.0)

Today's PR comment renders findings table. Q1 adds an "AI Explanation" link per finding pointing into cloud dashboard (requires logged-in cloud account):

```markdown
### Fendix — 3 new findings on this PR

| Severity | Title | File |
|---|---|---|
| CRITICAL | SQL injection via /api/import | routes/import.py:42 |
| HIGH | Hardcoded AWS key | infra/deploy.sh:7 |
| MEDIUM | Missing CSP header | (3 endpoints) |

[View AI explanations and suggestions →](https://fendix.cloud/o/123/findings)

<sub>fendix v0.9 · `fendix snooze CRITICAL-7b3e` to hide · 0 telemetry</sub>
```

In Q2, suggestions render inline once the user is logged in and on Pro:

```markdown
| CRITICAL | SQL injection via /api/import | routes/import.py:42 | [Suggested fix](link) |
```

Click → cloud dashboard shows the LLM-generated code block, "Copy" button, "Was this helpful?" feedback.

### 8.4 Diff-Aware Scans (Q2)

Today: full scan on every PR. Add `--changed-files-only` to scan touched files + transitive callers. Solo-shippable. Big perceived-latency win.

### 8.5 Trust-Building Sequence (the 30-day window)

1. **First scan** produces ≥1 obviously real finding.
2. **First AI explanation** is accurate, useful, copy-paste-quality.
3. **First false positive** has a one-click suppression snippet in the comment.

This is the entire onboarding moat. If you nail these three moments, the user converts to Pro. If you miss any, they uninstall.

### 8.6 Local Scans (preserved verbatim from today)

Engine runs offline. `fendix scan --offline` continues to work. Engine does not talk to the backend — ever. Scans reach the cloud only when the user configures the GitHub App or triggers a scan from the dashboard. No-telemetry promise unchanged. There is no `--cloud-token` upload path (see Technical Debt Trap #5).

### 8.7 Policy-as-Code (already exists)

[`.fendix.yaml`](go/internal/policy/) shipped in TASK-109. Year 1 extends with:
- Per-branch severity gates (already in place)
- AI explanation budget (new in Q1): `ai.monthly_explanation_budget: 100`
- Suppression rules (already in place)

Out of scope: auto-remediation policy (no auto-remediation per ADR-008).

### 8.8 Adoption Funnel (solo)

```
GitHub Marketplace → install → first PR comment within 24h → click "see AI explanation" link
  → cloud signup (free tier, 10 explanations/mo) → invite teammates → hit limit → upgrade to Pro
```

Goal funnel rates (year-1 targets):
- Marketplace install → first PR comment: 60%+
- First PR comment → cloud signup: 15-25%
- Cloud signup → Pro upgrade: 5-10%

If cloud-signup rate is below 10% by month 6, the AI explanation feature isn't pulling its weight — revisit prompt quality or surface (maybe the link in the PR comment isn't clicky enough).

---

## SECTION 9 — ENTERPRISE PLATFORM REQUIREMENTS (deferred)

### 9.1 Honest Take

**Enterprise is not in this plan.** ADR-008 retains BACKLOG-017's "no SSO/SAML/audit/SOC2" non-goal. Solo founder has no bandwidth for enterprise sales cycles.

This section is therefore a list of **what to consciously NOT build** in year 1, and the trigger conditions that would justify revisiting:

| Capability | Year 1? | Revisit when |
|---|---|---|
| SAML / SSO | No | MRR $50K + first 3 enterprise inbounds requesting it |
| SCIM | No | After SSO |
| Custom RBAC | No | Studio tier proves out (Q3+) |
| Audit log export | No | First compliance-driven request |
| BYOK encryption | No | First $100K+ enterprise deal in pipeline |
| Data residency (EU) | No | First EU customer churns over residency |
| Multi-region | No | $100K MRR or specific customer demand |
| SOC2 Type I | No | $200K ARR and enterprise-sales-led growth |
| SOC2 Type II | No | After Type I |
| ISO 27001 | No | EU enterprise expansion |
| FedRAMP | No | Federal customer signal (unlikely year 1-2) |
| Status page | **Yes** (Q1) | Free Better Stack or self-hosted Cachet |
| Privacy policy + ToS | **Yes** (Q1) | Required for paid tier — use Termly or similar template |
| Basic DPA template | **Yes** (Q3 if first EU paid customer) | Use a DocuSign template |

### 9.2 What Free + Pro tiers DO include for trust signals

Even without SOC2, you can build trust capital:

- **MIT-licensed source** of the engine (already exists).
- **Signed releases** (cosign keyless, already exists).
- **Public security.txt + responsible disclosure** (Q1, 1 day).
- **Public threat model** (`docs/threat-model.md` — already exists for the engine; extend for `fendix-backend` in Q1).
- **Quarterly transparency report**: "we received N security questionnaires, we don't have SOC2, here's why and our roadmap" — owns the conversation rather than ducking it.

### 9.3 The "Trust Without Compliance" Positioning

Document this explicitly on the public site:

> *Fendix Cloud doesn't have SOC2 yet. We're a small team focused on signal quality. The engine source is MIT on GitHub — read it, fork it, run it on your own infrastructure. The cloud service is what you'd build yourself with a small Postgres + Anthropic API key, and you can replace it with self-hosting at any time. If SOC2 is required for your purchasing process, Fendix Cloud is not the right fit yet.*

This is **the right answer** for solo-scale and is more defensible than a half-built SOC2 story.

---

## SECTION 10 — SCALABILITY & DISTRIBUTED SYSTEMS

### 10.1 Solo-Scale Targets (month 18)

| Dimension | Realistic month-18 target |
|---|---|
| Paying Pro orgs | 100-300 |
| Free orgs | 1,000-3,000 |
| Total findings stored | 5–20M |
| Daily scans uploaded | 500-2,000 |
| Concurrent scans (peak) | 50-200 |
| Graph nodes (entity rows) | 5–20M |
| LLM calls / day | 1,000-5,000 |
| LLM cost / month | $300-1,000 |

These are 100× smaller than the prior draft's targets. That's correct. The prior draft sized for a team of 13 and a $25M Series A.

### 10.2 Storage Architecture (single-database era)

| Store | Use | Sizing year 1 |
|---|---|---|
| Postgres (Fly.io or Supabase managed) | findings, entities, edges, users, orgs, billing | 50-200 GB |
| Cloudflare R2 | SARIF archives, raw scanner uploads | 100-500 GB; cheap |
| Anthropic API | LLM calls | not storage; metered |
| No Redis | — | use Postgres for cache + lock |
| No ClickHouse | — | flat files in R2 for analytics |
| No Qdrant | — | no RAG in year 1 |

### 10.3 Scaling Bottleneck Forecast (and Solo-Friendly Mitigation)

| Bottleneck | Threshold | Solo mitigation |
|---|---|---|
| Postgres CPU | ~80% sustained | Vertical scale on Fly.io (one click); add read replica only at $20K MRR |
| LLM rate limit | Anthropic provider cap | Per-org daily budget; auto-throttle |
| R2 egress | Cloudflare's free tier exceeded | Move to R2 paid (~$15/TB) |
| Cloud-api request volume | ~1M req/day | Vertical scale; horizontal would require sessions in Redis — defer |
| Webhook flood from large repos | bursty | Postgres job queue absorbs; rate limit per org |

### 10.4 Backups

Daily Postgres logical dump → R2 with 30-day retention. RPO 24h, RTO 4h. **Acceptable** for $20/dev/month tier. Documented in the privacy/security page; not enterprise-grade.

### 10.5 What I'm Explicitly Not Doing

- No multi-region (single Fly.io region in year 1).
- No K8s self-managed (Fly.io abstracts this).
- No Kubernetes operator for customers (BACKLOG-017 / ADR-008 forbids).
- No streaming ingest (NATS/Kafka).
- No autoscaling group orchestration (Fly.io handles).
- No SRE rotation (one-person on-call until $10K MRR).
- No load test at 1B edges. The prior draft suggested running this in Q3 "before you have the data." That's a 2-week engineering project that solo bandwidth cannot afford until it actually matters. Defer until Postgres p99 query latency starts climbing.

---

## SECTION 12 — COMPETITIVE STRATEGY

### 12.1 Beating Snyk

Snyk's exposure is noise + price. Snyk AutoFix's exposure is auto-write trust.

**Fendix wedge against Snyk** (revised under ADR-008):
- "Ingest your Snyk results into Fendix; we deduplicate, score by EPSS+KEV+reachability, and surface ~200 actionable items from your 50K-finding sea."
- "Snyk wants to merge to your main branch. Fendix shows you the fix and lets you decide."
- "Snyk is closed-source. Fendix's engine is MIT — audit it, fork it, run it air-gapped."

12-18 months later: customer keeps paying Snyk for the scanners, pays Fendix Pro for the intelligence layer. Eventually realizes Trivy + Semgrep + Gitleaks + Fendix is cheaper than Snyk + Fendix and migrates off Snyk. Slow drift, not direct displacement.

### 12.2 Avoiding Wiz Head-On

Unchanged from prior draft. Wiz owns CSPM. Fendix stays developer-side and complements. **No new energy spent on cloud posture.**

### 12.3 Complementing GitHub Advanced Security

Unchanged. Ingest CodeQL SARIF, ingest Dependabot. Position as "the intelligence layer that unifies GHAS with everything else."

### 12.4 Differentiating from Aikido

Aikido is the closest competitor and **the most credible threat**. They are well-funded, dev-first, scanner-bundling. They will ship AI auto-fix.

Fendix's hard differentiators (and only differentiators):

1. **MIT-licensed engine, signed releases, no telemetry.** Aikido cannot retrofit this.
2. **AI is read-only.** Aikido will go to L2-L4 autonomy; Fendix stays L1. This is a **strategic concession marketed as a virtue**.
3. **Plugin ecosystem.** Open contract; Aikido has none.
4. **Cross-scanner ingest.** Aikido pitches their own scanners. Fendix ingests yours.

If Aikido out-executes on L2+ AI and customers turn out to want it, **Fendix will look slow and conservative for 12+ months**. This is a real risk I am explicitly accepting in the plan. ADR-008's read-only constraint is the price of the trust positioning.

### 12.5 The Moat (restated, post-ADR-008)

1. **Trust capital.** MIT + signed + no-telemetry + read-only AI. Compounding, hard to retrofit.
2. **OSS engine quality.** Reachability + plugin system already exist and lead category.
3. **Cross-scanner intelligence.** Becomes the "single inbox" over time.

**Not the moat (was in prior draft, cut):**
- Outcome dataset (requires auto-PR → cut)
- Runtime + IAM + attack-path (BACKLOG-017 / ADR-008 retained nos)
- Enterprise lock-in (PLG-only)

### 12.6 The Wedge — preserved

"DAST + SAST as one PR check" remains the wedge. v0.7.0 ships it. Q0 marketing launches it.

### 12.7 Expansion Strategy (single founder version)

1. Land: OSS engine + GitHub App (free).
2. Identify: cloud signup via PR-comment "see AI explanation" link.
3. Convert: 10 free explanations/month → hit cap → upgrade to Pro ($20/dev/mo).
4. Expand: invite teammates (Studio tier in Q3).
5. **Stop.** No enterprise. No outbound sales.

### 12.8 Long-Term Category Vision

**"Developer Security Intelligence — without the magic."**

Position Fendix as the trustworthy, read-only alternative to autonomous-AI security platforms. This is a smaller TAM than the autonomous-AI category leader's TAM. **That's the tradeoff for being solo + MIT + read-only.** It's a defensible, profitable, niche position — not a $1B category-defining position. Be honest with yourself about which game you're playing.

---

## SECTION 13 — BRUTALLY HONEST REVIEW (solo-founder edition)

### 13.1 Biggest Architectural Risks

1. **One Postgres is a single point of failure.** Year 1 = single region, single primary. One Fly.io regional outage = product down. Acceptable at $20K MRR; document the limitation; revisit when one customer outage costs more than read-replica setup.
2. **Anthropic-only LLM.** No fallback provider. A 24-hour Anthropic outage takes "AI Explanation" feature down. Mitigate by caching aggressively and degrading gracefully — never let it block finding ingestion.
3. **Postgres adjacency will run out of legs** somewhere around 50M+ edges. Year 1 target is 5-20M — plenty of headroom. But if you onboard a single 5000-repo customer in Q3, you skip the headroom in a week.
4. **Next.js frontend is an OpenAPI contract consumer.** Every backend schema change must be propagated via `make schema` → `npm run codegen`. Schema drift causes silent type errors in the frontend — the CI `schema-check` target guards this but only if CI is green before deploy.
5. **No Celery task isolation per tenant.** A stuck LLM explanation task for one user can exhaust the Celery worker pool if concurrency is uncapped. Set `CELERYD_CONCURRENCY` and use `task_time_limit` + `task_soft_time_limit` on explanation tasks from day one.

### 13.2 Biggest Execution Risks

1. **Founder burnout.** One person, 18 months. Q1 is ~23 days — manageable. But Q2 adds cross-scanner ingest + AI fix-as-text on top of community management, customer support, and Marketplace operations. Build in vacation. Build in non-product Saturdays. If you can't sustain 35 hrs/week of Fendix work without resentment, the plan is too aggressive.
2. **Scope creep is the killer.** Every community user, every paying customer, every Twitter reply asks for one more thing. Discipline: OSS gets bug fixes + one new feature per quarter. Cloud gets the roadmap. Everything else goes to BACKLOG.
3. **Skipping the Q0 launch.** The temptation will be to start the Q1 cloud work before the marketplace listing is live. Don't. Q0 is the funnel; no funnel = no users for Q1's features.
4. **Q1 cloud backend being too ambitious.** If you find yourself slipping past 50% of Q1 day budget by week 6, cut scope: drop Stripe integration to Q2; ship dashboard with hardcoded "free for everyone" entitlement first.
5. **Marketing yourself as "AI-native" while building read-only AI.** Customers may arrive expecting Snyk AutoFix-style features and bounce. Be precise in marketing copy: "AI explanations and suggestions, no auto-write." Set expectations honestly.

### 13.3 Biggest Product Mistakes Likely To Happen

1. **Shipping AI suggestion before AI explanation has 80%+ helpful rating.** Suggestion is harder; if explanation isn't good, suggestion will be bad.
2. **Building Studio (multi-user) too early.** Premature org features tax solo bandwidth. Single-user Pro should prove out first.
3. **Adding a feature because Aikido shipped it.** Fendix differentiation is "trustworthy alternative," not "feature parity." Resist.
4. **Trying to support GitLab + Bitbucket in year 1.** Three SCM providers = 3× webhook bugs.
5. **Letting OSS engine and backend versions drift.** The backend's `FendixEngine` subprocess wrapper pins which engine fields it reads. When the engine adds a new field (e.g., `taint_chain`), the backend migration + parser update must ship in the same release window. Track this in `CURRENT_SPRINT.md`.

### 13.4 Biggest Scaling Risks (solo-grade)

1. **One customer with a 10K-repo monorepo overwhelms shared Postgres.** Per-org rate limit on uploads from day 1.
2. **Runaway LLM bill from one user repeatedly clicking "explain" on the same finding.** Cache by `(finding_hash, model_version)` forever; per-org daily token cap.
3. **One viral HN/Twitter moment overwhelms the backend.** Cloudflare in front of nginx; existing rate limiting (anon 20/min, user 100/min, scan_create 10/hr) already in place. Vertical-scale the Fly.io machine manually if needed — this is a one-click operation.

### 13.5 Biggest AI Risks

1. **Hallucinated explanation that misleads a developer into thinking a real bug isn't real.** Mitigate: "Was this helpful?" feedback; manually review low-rated outputs weekly; iterate prompts.
2. **Prompt injection via finding content** (untrusted user code in the prompt). Mitigate: clear delimiters in prompt; outputs go through markdown sanitization before render; never let LLM tool-call.
3. **Anthropic prompt-cache key cross-tenant leakage.** Verify Anthropic's cache is account-scoped; include `org_id` as a cache-buster if any doubt.
4. **Prompt regression on Anthropic model version updates.** Pin model version (`claude-haiku-4-5-20251001`); test new versions on holdout set before flipping default.
5. **Cost surprise.** Daily LLM-cost dashboard. Alert if daily spend > $20 (Pro tier doesn't cover that).

### 13.6 Biggest GTM Risks

1. **Free-to-paid conversion is too low to be default-alive.** If <5% of free signups upgrade by month 9, either the value gap isn't compelling or pricing is wrong. Iterate on free limits (3 repos? 10 explanations?) before iterating on price.
2. **OSS engine adoption stalls.** Q0 launch doesn't hit 250 stars in 2 weeks. Then no Q1 funnel. The plan assumes the launch lands; have a "what if Q0 underperforms" branch (mini-pivot to consultancy income while iterating positioning).
3. **Customers love the OSS engine, hate paying for cloud.** Real risk; mitigate by making cloud "obviously more valuable than running it yourself" (UI quality, AI quality, multi-scanner ingest).
4. **Aikido or Snyk launches a "Fendix-like" free tier.** They could squeeze the wedge. Mitigate: ship faster; lean harder on MIT engine differentiation; cross-scanner-ingestion as the moat they cannot match without making their own scanner free.

### 13.7 Biggest Hiring Mistakes (preempted)

Most don't apply yet (solo). The one that *can* apply:

1. **Hiring a contractor too late.** Once MRR clears $8K, finding 10 hrs/week of DevRel/content/community help is *high-leverage*. Founders often resist this. Don't.
2. **Hiring an engineer first when DevRel is the bottleneck.** Solo founders default to "hire someone who can do what I do." Hire someone who does what you can't do.

### 13.8 Biggest Roadmap Traps

1. **"AI features for the sake of AI features."** Every feature must pull its weight in the conversion funnel; "We have AI" is not a positioning. We have **explanation**, **suggestion**, **cross-scanner intelligence**. Specific verbs.
2. **The compliance hole.** Customers will ask for SOC2 in year 1. Saying "we don't have it, here's why" is a feature in this plan. Saying "we're working on it" is the trap. Don't half-start it.
3. **The "open core" trap.** Some MIT engine feature gets requested as "cloud-only paid feature" by a sales conversation. Resist. Open-core splits are nightmares for solo founders. Keep the line: engine = MIT, cloud = different repo.
4. **Customer-driven roadmap dilution.** One enterprise prospect asks for SSO; one open-source contributor asks for GitLab; one Pro user asks for IDE extension. All reasonable; all sized for a team you don't have. Default to no.

### 13.9 What Must Happen for Fendix to Survive 18 Months

1. **Q0 launch produces ≥250 stars and ≥20 GitHub App installs within 2 weeks.**
2. **Q1 ships Stripe self-serve + AI explanation by month 3** with ≥5 paying users.
3. **Q2 priority inbox + cross-scanner ingest converts at ≥10% free→paid** by month 6.
4. **Month 12 MRR ≥ $10K** (default-alive runway for solo founder).
5. **Founder doesn't quit by month 9 from burnout.** This is the single biggest risk and it doesn't show up in product metrics.

### 13.10 What Would Likely Kill Fendix

1. **Founder burnout.**
2. **AI explanation quality is bad** (hallucinates, confuses) and undermines the trust positioning. The entire pitch depends on AI being *good*, just not *autonomous*.
3. **Marketplace launch flops.** Q0 underperforms → no funnel → no Q1 conversion.
4. **A well-funded competitor launches free Fendix-clone**. Most likely Aikido shipping a free OSS scanner with AI-explanation feature parity. Mitigate by being first; ship Q1 by month 3.
5. **Cash runs out before paid revenue covers $500/month burn.** Mitigate: keep burn under $200/month until Pro tier ships in Q1; have 6 months of personal runway before starting Q1.

### 13.11 What the Founder Should Obsess Over Daily

In priority order:

1. **OSS engine GitHub stars and GitHub App installs.** Funnel health.
2. **Free → Pro conversion rate.** Revenue health.
3. **AI explanation "helpful" rating.** Product quality health.
4. **Daily LLM cost.** Burn discipline.
5. **Your own energy.** If you're dreading Fendix work, that's signal, not noise. Investigate.

Things **not** to obsess over yet:
- ARR (not enough customers; vanity)
- Headcount (you're solo)
- Conference talks, podcasts, Twitter follower count
- "Thought leadership" content
- Competitor product launches (refresh news once a week, not hourly)

---

## VERIFICATION

By quarter, the plan is verified if these hold:

**Q0 (this sprint):**
- GitHub Marketplace listing live.
- `./scripts/deploy-app.sh` ran successfully; `fendix-app` is reachable.
- Launch post published.
- ≥250 GH stars, ≥20 installs within 2 weeks.

**Q1 (months 0–3):**
- `curl -X POST https://api.fendix.cloud/v1/findings` with engine NDJSON returns 200.
- Cloud dashboard at `https://app.fendix.cloud` shows the finding with AI explanation.
- ≥5 paid Pro signups via Stripe.
- LLM bill < $50/month.
- OSS engine v0.7 still runs offline (`fendix scan --offline` works).
- ADR-008 committed to `docs/adr/`.

**Q2 (months 3–6):**
- Import a Snyk SARIF → see deduplicated findings + EPSS/KEV scores.
- Priority Inbox UI shows ranked findings.
- AI suggestion-as-text working on at least 3 languages (Python, Go, JS).
- MRR ≥ $1K.

**Q3 (months 6–9):**
- Plugin marketplace live with ≥15 plugins.
- Studio tier purchasable.
- OSS engine v1.0 tagged.
- Total MRR ≥ $10K (default-alive).

**Q4 (months 9–12):**
- One Q4 bet shipped.
- MRR ≥ $15K.
- First contractor onboarded (if MRR justifies).

**Q5–Q6 (months 12–18):**
- One of: (a) sustain at $30K+ MRR + bring on 1-2 more contractors / hires, or (b) raise + scale, or (c) honest pivot/fold decision.

---

## Critical Files — Modification Index

### fendix-engine (OSS, MIT)

| Concern | Files | Notes |
|---|---|---|
| Finding schema evolution | [go/internal/models/finding.go](go/internal/models/finding.go) | Extend with `epss`, `kev`, `cloud_uploaded_at`. Keep wire-compatible. |
| Correlator + reachability | [go/internal/engine/correlator.go](go/internal/engine/correlator.go) | Reference implementation; do not break existing tests. |
| Plugin / NDJSON contract | [go/internal/plugin/plugin.go](go/internal/plugin/plugin.go), [python/engine.py](python/engine.py) | Versioned contract; backend `FendixEngine` subprocess wrapper parses the JSON report output. |
| GitHub App | [go/internal/ghapp/handler.go](go/internal/ghapp/handler.go) | No change needed — GitHub App already posts scan results via `POST /api/scans` to the backend. The engine runs inside the backend's Celery task, not locally. |
| Reporters | [go/internal/reporters/](go/internal/reporters/) | No new format needed — backend already reads the existing JSON report. |
| ADRs | [docs/adr/](docs/adr/) | New: ADR-008 (BACKLOG-017 supersession); ADR-009 (backend-vs-OSS split); ADR-010 (no-runtime-agent policy retained). |
| Strategic plan | [tasks/PHASES.md](tasks/PHASES.md) | Add Phase 17 (Q0 closeout), Phase 18-21 (Q1-Q4 from this plan). Phase 16 (Architecture v2) stays as year-2+ horizon. |
| Sprint state | [tasks/CURRENT_SPRINT.md](tasks/CURRENT_SPRINT.md) | After Q0 completes, replace active phase with "Phase 17 — Stripe + AI Explanation". |
| Session memory | [tasks/MEMORY.md](tasks/MEMORY.md) | Add an entry for this strategic session: ADR-008 trigger, plan reference, key decisions. |

### fendix-backend (proprietary, cloud)

| Concern | Files | Notes |
| --- | --- | --- |
| AI explanation | `backend/explain/` (new Django app) | `FindingExplanation` model + Celery task + DRF view. `UniqueConstraint(finding_hash, model_version)` for cache. |
| AI explanation quota | `backend/subscriptions/models.py` | Add `ai_explanations_used` to `UsageRecord`. Mirror `scans_used` pattern. |
| Reachability storage | `backend/scanning/models.py` | Add `reachable BooleanField` + `taint_chain JSONField` to `ScanFinding`. One migration. |
| Engine parser | `backend/scanning/services.py` | Update `FendixEngine` to parse and persist `reachable` + `taint_chain` from engine JSON report. |
| Stripe wiring | `backend/billing/` | Add webhook handler for `checkout.session.completed`, `customer.subscription.updated/deleted`. Wire `UpgradeRequest` → Stripe Checkout self-serve flow. |
| Feature gate for AI | `backend/subscriptions/permissions.py` | Add `"ai_explanation"` feature key to Pro+ plan seed (`seed_plans.py`). |
| Cross-scanner ingest | `backend/ingest/` (new Django app, Q2) | SARIF import adapters for Trivy, Gitleaks, Semgrep, Snyk. Maps to `ScanFinding` model. |
| EPSS/KEV enrichment | `backend/enrich/` (new Django app, Q2) | Daily Celery Beat task. Adds `epss_score` + `kev_listed` fields to `ScanFinding`. |

---

## Final Word

Fendix v0.7.0 is a solo-built, MIT-licensed, high-trust hybrid scanner with a defensible wedge. The 18-month plan **extends** that — it does not replace it.

What changes (per ADR-008 supersession): AI explanation + suggestion-as-text + a small cloud product for persistence and cross-scanner intelligence.

What stays unchanged: solo bandwidth, MIT engine, no telemetry, no auto-PR, no enterprise, no compliance product, no runtime agent, no multi-tenant SaaS.

**One sentence to internalize:**
> The OSS engine is the funnel. The cloud product is the revenue. AI is read-only. Trust is the moat. Solo is the constraint.
