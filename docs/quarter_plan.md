# Fendix — Engine-First Roadmap (Sequential, Time-Honest)

**Decision date:** 2026-05-11
**Supersedes for this period:** Q1 of [docs/example_plan.md](example_plan.md) (cloud / Stripe / AI explanation work). Cloud work resumes after these workstreams ship.
**Does not supersede:** ADR-008 (still written), Q0 launch ops (still happen in parallel with workstream 1), the rest of the 18-month plan.

---

## What changed and why

The original Q1 in [example_plan.md](example_plan.md) was "wire Stripe + ship AI explanation" — ~23 solo days on top of the already-built `fendix-backend`. The operator has decided to defer all cloud / monetization work and put that window into the OSS engine instead.

The first attempt at this plan crammed all four engine directions into one quarter (~49 days inside ~50 days of capacity — zero slack, four workstreams stepping on each other). **This revision drops the artificial 3-month deadline.** Each workstream gets the time it actually needs and ships as its own release. The operator decides week-to-week which workstream is active.

**Trade-off being accepted:** No paid revenue until all four workstreams ship (~7–9 months at honest pace). The plan's $10K-MRR-by-month-9 target is gone. Replace it with: "v0.8 → v0.9 → v0.10 → v0.11 ship cleanly with published numbers and no regressions; founder is not burned out at the end of any of them." Cloud work resumes from a position of engine strength after.

---

## The four workstreams (in execution order)

Listed in the order they should run. Order matters — each one's design assumptions depend on the previous one shipping.

### Workstream 1 — Detection quality + FP reduction (ships as v0.8)

**Why first:** Lowest invasiveness. No wire-contract changes. Improvements stack with whatever comes next. Real-world false positives from Q0 launch will flow into this workstream's tuning corpus.

**Why paired:** Detection and FP-reduction must ship together. Adding new checks without FP discipline rebuilds the noise problem from scratch. Section 8.1.5 of [example_plan.md](example_plan.md): *"noise is bankruptcy."*

| # | Task | Estimate |
|---|---|---:|
| 1.1 | Native `govulncheck` / `pip-audit` / `npm-audit` — engine reads `go.mod` / `requirements.txt` / `package-lock.json` directly, resolves CVEs without OSV/Trivy delegation | 6 days |
| 1.2 | Reachability patterns beyond v0.7's three (SQLi, SSRF, open-redirect): add XSS-sink and command-injection-sink taint chains; same correlator pattern as TASK-114 | 4 days |
| 1.3 | FP corpus build — run engine against 3–5 OWASP-juice-shop-style targets, catalog every FP into tickets; necessary input for 2.1 | 2 days |
| 2.1 | Correlator confidence math pass — tighten thresholds; "DAST + SAST agreed + reachable" escalates, "one engine only, no taint chain" de-escalates; tune against the 1.3 corpus | 3 days |
| 2.2 | One-click suppression snippets in PR comment — extend [go/internal/ghapp/handler.go](../go/internal/ghapp/handler.go) so every finding ships with a copy-paste `.fendix-ignore` keyed on stable hash | 3 days |
| 2.3 | Severity scoring refresh per Section 3.5 of [example_plan.md](example_plan.md) — rebalance the underused `reachable_code` multiplier; leave EPSS/KEV for the cloud Q2 work | 2 days |

**Workstream 1 total: ~20 days. Plus a 25% integration buffer = ~25 days. Calendar: ~5–6 weeks at 70% capacity.**

**Ships as v0.8.0.** Release notes lead on: "FP reduction first, two new check families second."

---

### Workstream 2 — Performance / Phase 16 (ships as v0.9)

**Why second:** Invasive. Touches every code path. Doing this before workstream 1 means the new checks would be written twice (once against embedded Python, again after the port). Doing it after workstream 1 means everything written in v0.8 just gets faster.

**Why TASK-117 is deliberately skipped:** TASK-117 is the AST analyzer migration (tree-sitter or Python plugin). It's the hardest of the four Phase 16 tasks, the AST analyzer is doing real work that doesn't degrade gracefully when removed, and shipping <500ms p50 without it still wins the cold-start story. Tree-sitter port is a quarter's work on its own.

| # | Task | Estimate |
|---|---|---:|
| 3.1 | TASK-115: port secrets analyzer to Go — ~1000 LOC translation from `python/analyzers/secrets.py` to `go/internal/scanner/secrets/`; detect-secrets patterns + 7 custom regex types become Go equivalents; NDJSON plugin contract intact (in-process plugin from orchestrator's view) | 6 days |
| 3.2 | TASK-116: Semgrep shelled-out, not embedded — remove embedded Python; detect Semgrep in `$PATH`; if absent, scan continues without Semgrep + emits "install semgrep for X% more checks" notice | 5 days |
| 3.3 | TASK-118: drop embedded Python entirely + cold-start benchmark — target <500ms p50; publish numbers in [docs/benchmarks.md](benchmarks.md) using existing `make benchmark` infra | 4 days |
| 3.4 | Plugin wire-contract compatibility audit — verify v0.7-era plugins still work against v0.9, document any breaking changes in release notes | 2 days |

**Workstream 2 total: ~17 days. Plus 25% buffer = ~21 days. Calendar: ~5 weeks at 70% capacity.**

**Ships as v0.9.0.** Release notes lead on: "cold start dropped 4×; embedded Python is gone; plugin contract unchanged."

**Risk callout:** This is the workstream most likely to slip. Test extensively before tagging. A bad v0.9 release that breaks plugins or misses cold-start targets is worse than a v0.9 that ships 2 weeks late.

---

### Workstream 3 — Plugin ecosystem (ships as v0.10)

**Why third:** Phase 16 (workstream 2) may subtly shift the plugin NDJSON contract; doing plugin docs/examples before v0.9 ships means rewriting them. After v0.9 the contract is stable and the documentation work is wasted-effort-free.

| # | Task | Estimate |
|---|---|---:|
| 4.1 | Plugin authoring docs — rewrite [docs/plugins.md](plugins.md) for external authors: NDJSON wire contract with worked examples, lifecycle, error handling, packaging, installation; today's docs target Fendix-internal use | 3 days |
| 4.2 | Reference plugins — 2 new ones in non-Go languages (Python + Ruby or Node) to prove the wire contract is language-agnostic; pick from Grype importer, Trivy importer, `.env`-file secrets scanner | 3 days |
| 4.3 | `fendix plugins list` / `fendix plugins install <git-url>` CLI subcommands — local install only (no marketplace yet; that's Q3 of [example_plan.md](example_plan.md)) | 3 days |
| 4.4 | Plugin smoke test in CI — extend `make test` to run each reference plugin against a fixture and assert findings shape; protects the wire contract against silent regressions | 2 days |

**Workstream 3 total: ~11 days. Plus 25% buffer = ~14 days. Calendar: ~3–4 weeks at 70% capacity.**

**Ships as v0.10.0.** Release notes lead on: "the plugin contract is now external-author-ready."

---

### Workstream 4 — Detection round 2, post-launch data (ships as v0.11)

**Why fourth:** This workstream depends on real-world FP reports from launch traffic. Q0 launches in parallel with workstream 1; by the time workstreams 1–3 ship, you have ~4–6 months of real user feedback. The second pass of FP tuning is informed by *actual* user pain, not synthetic juice-shop fixtures.

| # | Task | Estimate |
|---|---|---:|
| 5.1 | Real-world FP triage — catalog every FP filed against v0.8–v0.10 since launch; cluster by pattern; pick the top 5–10 categories to fix | 3 days |
| 5.2 | Targeted correlator fixes per category | 5 days |
| 5.3 | One more reachability pattern based on what users actually hit (likely: XXE, deserialization, or path-traversal) — pick from real ticket data, not from this doc | 4 days |
| 5.4 | Suppression UX iteration — based on how users actually use the one-click suppression from workstream 2.2 | 2 days |
| 5.5 | Benchmark refresh — re-run the published cold-start + check-coverage numbers on the latest release; refresh [docs/benchmarks.md](benchmarks.md) | 1 day |

**Workstream 4 total: ~15 days. Plus 25% buffer = ~19 days. Calendar: ~5 weeks at 70% capacity.**

**Ships as v0.11.0.** Release notes lead on: "fixes for the 5–10 false-positive patterns users actually hit."

---

## Total time + sequencing

| Workstream | Release | Days (with buffer) | Calendar (70% capacity) |
|---|---|---:|---:|
| 1 — Detection + FP | v0.8 | 25 | ~6 weeks |
| 2 — Phase 16 perf | v0.9 | 21 | ~5 weeks |
| 3 — Plugin ecosystem | v0.10 | 14 | ~4 weeks |
| 4 — Detection round 2 | v0.11 | 19 | ~5 weeks |
| **Total** | — | **~79 days** | **~5 months end-to-end** |

Plus:
- Q0 launch ops — parallel to workstream 1, ~5 operator days
- ADR-008 — 1 day, anywhere in the timeline (recommend during workstream 1)
- Community support, GitHub issues, customer DMs — folded into the 30% capacity buffer

**End-to-end honest expectation: ~5 months from start to v0.11 shipping.** That's "engine-first detour" time. Cloud work (Stripe + AI explanation, the original Q1 of [example_plan.md](example_plan.md)) resumes after.

---

## What stays unchanged from [example_plan.md](example_plan.md)

- **ADR-008 is still written**, even though no AI ships during these workstreams. The strategic decision (read-only AI permitted, auto-PR forbidden) is independent of feature timing. Do it during workstream 1.
- **Q0 launch ops still happen.** Marketplace registration, deploy via `./scripts/deploy-app.sh`, Marketplace submit, seed-issues, launch post. In parallel with workstream 1. Q0 exit criteria (≥250 stars, ≥20 installs in 2 weeks) is unchanged and is a real decision gate — see below.
- **All durable non-goals from Section 1.6 of [example_plan.md](example_plan.md).** No auto-PR. No multi-tenant SaaS. No compliance product. No eBPF runtime agent. No IDE extension this year. No `--cloud-token` upload path.
- **The 18-month plan resumes** after workstream 4. Stripe + AI explanation become the next-up work (the original Q1 of [example_plan.md](example_plan.md), ~23 solo days). Q2-Q6 follow as written, just shifted right by ~5 months.

---

## Decision gates (when to re-plan)

1. **End of week 2: Q0 launch result.** If Marketplace listing failed to ship, or stars + installs are <40% of target (<100 stars, <8 installs), pause workstream 1 and re-evaluate. Widening the engine moat on a product nobody is using is sunk cost.
2. **End of workstream 1 (v0.8 ships): FP corpus quality.** If the juice-shop FP corpus produced fewer than ~15 real FPs, the corpus is too small to tune against — either expand it (add vAPI, crapi targets per the [docs/benchmarks.md](benchmarks.md) plan) or accept that workstream 4's real-world-data FP pass is doing the heavy lifting.
3. **Before starting workstream 2: should it run at all?** If workstream 1 took >7 weeks instead of 6, the operator's capacity assumption (70%) is wrong, and workstream 2's invasive Phase 16 work will hurt. Consider skipping straight to workstream 3 (lower invasiveness) and deferring Phase 16 to next year.
4. **End of workstream 2 (v0.9 ships): plugin breakage rate.** If v0.9 broke more than 1–2 reference plugins, the wire-contract migration was botched. Add a hotfix sprint before workstream 3, or v0.10's plugin docs will be teaching against a broken contract.
5. **Before starting workstream 4: is launch data sufficient?** Workstream 4 needs real user FPs. If by the time workstreams 1–3 ship there are fewer than ~20 user-reported FPs, defer workstream 4 to next year — there's no signal to act on. Resume the cloud work from [example_plan.md](example_plan.md) §Q1 instead.

---

## Success criteria

In priority order — the operator should be able to honestly say all five at the end of this roadmap:

1. **v0.8 → v0.9 → v0.10 → v0.11 shipped** with published numbers and no major regressions.
2. **Q0 launch landed** — Marketplace listing live, ≥250 stars + ≥20 installs (or a documented "what we learned" post-mortem if missed).
3. **ADR-008 committed** to [docs/adr/](adr/).
4. **OSS engine v1.0 candidate.** After v0.11, the engine has detection breadth, FP discipline, performance, plugin ecosystem, and post-launch tuning. v1.0 tag becomes meaningful at this point — earlier than the Q3 timing in [example_plan.md](example_plan.md).
5. **Founder is not burned out.** Soft criterion, hard reality. The whole point of dropping the artificial 3-month deadline is to make this criterion achievable.

---

## What does NOT get measured during these workstreams

- MRR. There is none by design.
- Paid signups. There are none.
- Free-to-paid conversion rate. Cloud isn't shipping.
- AI explanation quality. No AI ships here.
- LLM bill. Should be $0.

These resume measurement after workstream 4 when the cloud work returns.

---

## Cut order if something has to give

The whole point of this revision is that *time is not the constraint that forces cuts* — each workstream takes the time it needs. But if external pressure (cash, personal, market) forces a stop before v0.11, the cut order is:

1. **Workstream 4 entire** — defer round-2 FP tuning to "do during cloud quarter as a side track."
2. **Workstream 3.4** (plugin CI smoke test) — keep the docs + reference plugins, drop the automated regression guard for one more release.
3. **Workstream 3.3** (`fendix plugins` CLI) — docs + reference plugins are the deliverable; the CLI commands are nice-to-have.
4. **Workstream 2.3** (TASK-118 cold-start benchmark publish) — ship Phase 16 without the published numbers; add them in v0.9.1.
5. **Workstream 1.2** (XSS + cmd-injection reachability) — keep v0.7's three reachability patterns; v0.8 ships with just the new dep scanners + FP work.

Never cut: workstream 1's FP reduction (2.1–2.3), ADR-008, or Q0 launch ops.
