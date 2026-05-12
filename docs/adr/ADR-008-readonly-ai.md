# ADR-008: Read-Only AI Permitted — Auto-Remediation Forbidden

## Status

Accepted (2026-05-11, formalised during Phase 17a kickoff)

Supersedes: BACKLOG-017 entry "AI-driven triage / LLM fix suggestions" (2026-04-30).
All other BACKLOG-017 entries are unchanged.

## Context

### The prior decision (BACKLOG-017, 2026-04-30)

The 2026-04-30 strategic session produced BACKLOG-017 — a durable list of
explicit non-goals. Its "no AI" entry read:

> "No AI-driven anything. AI triage / LLM fix suggestions / AI FP reducer each
> burn 2 sprints, ship slop UX, weaken the trust story. Fendix's moat is
> *signal*, not *magic*."

This was the correct call in April 2026. At that point:

1. The engine was v0.5–v0.6, with rough FP rates and no taint-chain reachability.
   Layering an LLM on noisy findings would amplify the noise, not reduce it.
2. `fendix-backend` existed but lacked the persistence needed to cache LLM
   responses per finding — every explanation call would be a fresh, unbilled API hit.
3. The competitive landscape was: Snyk had launched AutoFix in closed beta;
   Aikido's AI remediation was not yet GA. The category wasn't clearly won.

### Forces that changed by 2026-05-11

**Engine quality.** Phases 11–17a shipped taint-chain reachability (TASK-114),
six reachable sink categories (TASK-120, TASK-121), FP-reduction gates (TASK-123),
and a real FP corpus (TASK-122). The signal quality is now high enough that an
LLM explanation of a finding will be grounded in a real, reproducible issue
rather than scanner noise.

**Backend readiness.** `fendix-backend` is production-ready: auth (simplejwt
RS256 + API keys), subscriptions (Free/Pro/Team/Enterprise plans, quota
enforcement), scan lifecycle (Scan → Celery → ScanFinding), and the Stripe
scaffold are all deployed. The missing pieces for an AI explanation endpoint are
small: a `FindingExplanation` model, a quota meter, and a call to the Anthropic
API with prompt caching. The infrastructure cost is one sprint, not a quarter.

**Competitive hardening.** By mid-2026, "AI-native AppSec" is the default
marketing framing for Aikido, Endor, and Snyk AutoFix. A scanner that ships
zero AI features cannot claim category leadership. The risk is no longer "we
burn a sprint on AI slop" — it is "we cede the category to tools with weaker
signal but stronger AI framing."

**The tighter distinction.** The blanket "no AI" rule in BACKLOG-017 conflated
two qualitatively different things:

1. **Read-only AI** — the LLM reads a finding and produces text (explanation,
   suggested fix). Nothing is written to the user's repository. The user remains
   the decision-maker at every step. A bad suggestion is annoying, not harmful.

2. **Write AI** — the LLM generates a code change and opens (or merges) a PR
   without a human in the loop. A bad suggestion becomes a commit. Trust is
   spent in a way that cannot be recovered if the commit introduces a regression
   or a new vulnerability.

These are not the same risk class. BACKLOG-017 banned both under a single rule;
this ADR draws the line between them.

### Options considered

#### A. Keep BACKLOG-017 unchanged — no AI, ever

The simplest path. No LLM API calls, no rate-limit risk, no trust surface to
defend.

**Why rejected:** Permanently cedes the "AI-native AppSec" category. By the
time v0.11 ships and the cloud quarter opens, every major competitor will have
shipped AI explanation + fix suggestion. Onboarding a new user who has already
used Snyk AutoFix and Aikido and sees no AI in Fendix's dashboard creates an
immediate credibility gap — even if our signal quality is higher. The blanket
prohibition made sense in April 2026; it does not make sense in October 2026+.

#### B. Full AI-native — autonomous fix PRs on confirmed findings

Ship what Snyk AutoFix ships: the LLM detects a finding and opens a PR with
a suggested fix, optionally auto-merging if the CI passes.

**Why rejected:** Permanent prohibition. Three reasons:

1. **Trust is the wedge.** Fendix's differentiator is that human engineers
   verify every finding before action. A tool that writes to your main branch
   without explicit approval is in a different trust category. One bad
   auto-merged fix that introduces a regression or breaks production ends the
   product. The risk is asymmetric — the upside (slightly faster fix cycle) does
   not justify the downside (a single incident that destroys the trust story).

2. **No "outcome dataset" moat available.** Autonomous fix PRs accumulate a
   dataset of accepted/rejected/reverted changes that lets a product improve its
   suggestions over time. Building this moat requires millions of PRs — at
   Snyk/Cursor scale. A solo-operated PLG product cannot build it. Without the
   moat, the autonomous-fix feature is permanently playing catch-up to tools
   that have the data.

3. **Regulatory trajectory.** EU AI Act and emerging AppSec regulations are
   likely to require explicit human approval for AI changes to production systems.
   Shipping autonomous remediation now and having to retrofit a human-in-the-loop
   requirement later is a worse path than starting with read-only and adding
   write capability only if/when the regulatory picture clarifies.

#### C. Read-only AI only (this decision)

Explanation and fix suggestions are text, never commits. The LLM reads; the
human writes.

**Why accepted:** Captures the "AI-native" label without the liability of
autonomous remediation. Explanation is genuinely useful — a developer who
understands *why* a finding is a vulnerability fixes it faster and is less
likely to recur. Fix suggestion as text (in a PR comment, never auto-merged) is
a productivity boost that respects the human in the loop. Both features are
cacheable by `(finding_hash, model_version)`, keeping LLM cost proportional to
unique findings, not scan frequency.

## Decision

**Read-only AI is permitted in the `fendix-backend` cloud product. Write AI
(auto-PR, auto-remediation, auto-merge) is permanently forbidden.**

The boundary is drawn as follows:

### Permitted

- **AI explanation** (`POST /api/findings/:id/explain`): the LLM receives the
  finding's title, category, evidence (redacted), taint chain (if present), and
  CWE reference, and returns a 2–4 paragraph explanation of why this is a
  vulnerability and what its impact is. Response cached by
  `(finding_hash, model_version)` in `FindingExplanation`. Quota-metered by
  plan (Free: 10/month, Pro: 50/month per developer seat).

- **AI fix suggestion as text** (`POST /api/findings/:id/suggest`): the LLM
  receives the above context plus the affected code snippet (if the whitebox
  engine provided a file:line reference) and returns a suggested fix as a
  Markdown code block, displayed in the dashboard and optionally inserted as a
  PR comment by the GitHub App. The suggestion is text only — the App writes a
  comment, not a commit.

- **AI-assisted explanation in PR comments**: the GitHub App may include a
  brief AI-generated "why this matters" paragraph alongside the finding summary
  in PR comment output, if the user has opted in (plan feature flag
  `ai_pr_context`).

### Forbidden — permanently

- **LLM calls from the OSS engine binary** (`fendix` CLI). The CLI must work
  offline, without an Anthropic API key, without any cloud dependency. Users
  have an explicit expectation that the CLI sends traffic only to the scan
  target (see the "What Fendix sends to the network" table in README). Any LLM
  integration that violates this is a trust-story breach.

- **Auto-PR generation**: the GitHub App or any other component writes commits
  or opens PRs on behalf of the user. Suggestions are always text-only.

- **Auto-merge**: no Fendix component merges or approves a PR, regardless of
  CI status.

- **LLM-as-scanner**: using an LLM to detect vulnerabilities (as opposed to
  explaining them). All detection stays in the deterministic rule-based engine
  (Go scanner + Semgrep + Python AST). LLM false-positive rates are
  unacceptable for a security scanner.

- **LLM FP reducer**: using an LLM to decide whether a finding is a false
  positive. The FP reduction work in Phase 17a (TASK-122–125) uses deterministic
  heuristics (4xx gate, static-file regex, scoring formula). LLM-based filtering
  is out of scope permanently — it changes finding counts in ways users cannot
  audit or reproduce.

### Cloud-only constraint

AI features live exclusively in `fendix-backend` (Django, proprietary,
already deployed). The OSS engine emits findings; the cloud product stores and
enriches them. This boundary is deliberate:

- The Anthropic API key lives in the backend's secrets manager, not on the
  user's machine.
- LLM billing is per-account, not per-scan, keeping cost proportional to
  unique findings surfaced through the dashboard.
- OSS users who self-host get the full scanner with no AI. This is the correct
  trade-off — the scanner itself is the MIT-licensed trust anchor; AI enrichment
  is the cloud-product monetisation layer.

### Implementation timing

ADR-008 is written now (Phase 17a) because the strategic decision happened on
2026-05-11. **No AI features ship until after v0.11** — Cloud Q1 of
[docs/example_plan.md](../docs/example_plan.md) (Stripe + AI explanation,
~23 days) is deferred until Phase 17d ships. Writing the decision now prevents
scope creep into Phase 17b/17c/17d and ensures any PR that touches `fendix-backend`
during the engine quarter is correctly scoped.

## Consequences

### Positive

- **"AI-native" positioning is credible.** We can state: "Fendix explains what
  is wrong, explains why it matters, and suggests how to fix it — without
  touching your code." That claim is coherent and defensible.

- **Trust story is preserved.** The OSS engine binary ships no LLM calls. The
  README's "What Fendix sends to the network" table remains accurate. The cosign
  audit story is unchanged.

- **Implementation is scoped.** The first AI feature (explanation) is 5 days of
  backend work (TASK per example_plan.md Q1). It does not touch the scanner,
  the CLI, or the data contract.

- **Cost is proportional.** Caching by `(finding_hash, model_version)` means
  the Anthropic bill scales with unique findings shown to users, not with scan
  frequency. A user who runs 10 scans per day against the same codebase pays
  for one explanation call per finding, not ten.

- **Regulatory safe harbour.** Read-only suggestions require no AI-Act
  compliance work (no autonomous decision-making about user code). If
  regulations tighten further, we are already inside the safe zone.

### Negative

- **Loses users who want full auto-remediation.** Developers who prefer Cursor-
  or GitHub Copilot Autofix-style workflows will see Fendix's
  "suggestion-as-text" as a half-measure. These users choose product convenience
  over control. We explicitly serve trust-first users.

- **No "outcome dataset" moat.** As noted above: without auto-PR acceptance
  data at scale, Fendix's suggestion quality cannot self-improve through RLHF.
  We rely on the quality of the underlying model (Claude) rather than
  fine-tuning. Acceptable for a solo-operated product; acknowledged as a long-
  term disadvantage versus Snyk/Cursor at scale.

- **Revenue delayed.** AI explanation is the first paid feature gate (10
  explanation calls/month on Free, 50 on Pro). The delay of ~5 months (Phase
  17a → 17d before cloud work resumes) pushes the first monetisation moment to
  ~month 6 from the Q0 launch. Explicit trade-off: engine moat first, revenue
  second.

### Constraints enforced on future work

1. Any PR that adds an `import anthropic` or equivalent to the `go/` or
   `python/` directories must fail review — LLM calls belong in `fendix-backend`
   only.
2. The `--debug-bundle` flag (TASK-102) must never include LLM API keys or
   explanation cache entries — the bundle is shareable for support tickets.
3. The SARIF output, HTML report, and JSON output emitted by the CLI contain
   findings only — no AI-generated content. If the dashboard injects an
   explanation into a re-rendered report, that must be clearly labelled
   `"ai_explanation": "..."` as a separate field, not mixed into `"evidence"`.
4. `ReachableMult` escalations (TASK-125) are based on static dataflow, not LLM
   inference. Any future severity-scoring change must follow the same rule.

## Alternatives Considered

See "Options considered" section above. The three explicit options were:

- **A. Keep BACKLOG-017 blanket ban** — rejected: cedes AI-native category permanently.
- **B. Full autonomous remediation (auto-PR + auto-merge)** — rejected:
  permanently forbidden for trust, moat, and regulatory reasons.
- **C. Read-only AI (this decision)** — accepted.

One additional option explored but not developed as a full alternative:

- **D. OSS engine with optional local LLM (Ollama, LM Studio)** — running
  explanation via a local model so the CLI doesn't require a cloud account.
  Deferred indefinitely. Local model quality for code security is not yet
  competitive with Claude, maintenance burden is high, and the user experience
  (install Ollama, pull a 7B model, wait for it to load) is incompatible with
  the "curl | sh install" user journey.

## Implementation Checklist

- [ ] `docs/adr/ADR-008-readonly-ai.md` (this document).
- [ ] BACKLOG-017 in `tasks/PHASES.md` updated to reference ADR-008 as
      partial supersession (AI entry only; all other BACKLOG-017 entries
      remain).
- [ ] `docs/example_plan.md` Q1 AI explanation task references this ADR
      for the boundary on what the AI endpoint may and may not do.
- [ ] When the backend AI endpoint ships (Cloud Q1): system prompt for the
      explanation endpoint reviewed against the "permitted" list in this ADR
      before merge; no auto-PR generation code is ever introduced.

## References

- [BACKLOG-017](../tasks/PHASES.md#backlog) — Strategic non-goals (original
  blanket prohibition, 2026-04-30; superseded for the AI entry by this ADR).
- [docs/example_plan.md](../docs/example_plan.md) — 18-month product roadmap
  including Cloud Q1 (AI explanation + Stripe) and Q2 (AI fix-as-text).
- [docs/quarter_plan.md](../docs/quarter_plan.md) — v0.8 → v0.11 engine-first
  roadmap; cloud work resumes after v0.11.
- ADR-004 — Active probe safety (parallel decision structure: probe consent
  required before any active test; AI suggestion consent required before any
  auto-PR, both forbidden without explicit opt-in).
- ADR-007 — Open-source posture (MIT engine is the trust anchor; cloud backend
  is the monetisation layer; this ADR extends that two-layer model to AI).
- TASK-125 — Severity scoring refresh (deterministic `ReachableMult`; not
  LLM-driven; established the precedent for scoring changes staying in the
  rule-based system).
- TASK-126 — This ADR (Phase 17a closeout task).
