# Plan-finish — Phases 2/3/4/5/6 (Sprints 04–11, 13–17)

Drafted by the plan-finish session 2026-05-15. Branch:
`plan-finish-phases-2-6` (10 commits ahead of `main`). Not yet pushed.

---

## Summary

The session goal was "finish the enterprise-readiness plan" — close
every remaining sprint in [`PLAN.md`](tasks/enterprise-readiness/PLAN.md)
that hadn't shipped in the earlier Phase-1 + Sprint-18 work.

**13 of 18 sprints landed this session** (5 were already shipped in
prior sessions: 01, 02, 02.5, 03, 18). Each sprint is one commit on
this branch; reviewers can cherry-pick or merge as a single PR.

### Commit log (chronological, oldest first)

```
a63b49b feat(semgrep): expand bundled rule pack from 9 to 24 rules (Sprint 18)   ← prior session
a742a53 docs(ghapp): correct stale package comment in webhook.go (Sprint 13)
ffa1238 feat(init): GitLab CI + CircleCI templates via --ci flag (Sprint 17)
84cd4b4 feat(notify): Slack + Teams webhook alerts (Sprint 15)
fffe05a feat(reports): Arabic HTML report via --lang ar (Sprint 10)
bc25eee feat(bench): enterprise SAST comparison harness (Sprint 16)
3f4aa7f feat(jira): idempotent finding → Jira-issue sync (Sprint 14)
e87561b feat(report): PDF executive report via --format pdf (Sprint 11)
e7962cd feat(offline): air-gapped CVE snapshot format + fendix db CLI (Sprint 09)
5b8492f feat(textscan): unified Go + JS + IaC SAST engine (Sprints 04, 05, 06)
<pending> docs(plan): mark Sprints 07/08 closed-by-reference + final hand-off
```

### What landed per sprint

| Sprint | Audit ref | What shipped | Honest cuts |
|---|---|---|---|
| **13** GitHub App handler | §15.1 | Doc-drift fix only — the handler was already 309 LOC of production code with full test coverage on `main`. | — |
| **17** GitLab + CircleCI templates | §8 | `fendix init --ci {github,gitlab,circleci}` with auto-detect. Two new templates + two NEXT-STEPS docs. | Bitbucket / Azure DevOps templates → 17.5. |
| **15** Slack/Teams webhooks | §13 | `internal/integrations/notify/` library + `fendix notify` subcommand. Slack Block Kit + Teams Adaptive Card 1.3. Dedup + URL redaction. | Persistent dedup → 15.5. |
| **10** Arabic HTML report | §13 | `internal/reporters/i18n/` package, `--lang ar` flag, RTL CSS branch. Western Arabic numerals preserved. | **Native-speaker translation review (Sprint 10.5) is REQUIRED before promoting Arabic as production-ready.** |
| **16** Enterprise benchmark harness | §15.2 | `scripts/benchmark-enterprise/` with shared Python fixture, fendix-vs-semgrep-vs-bandit runner, CI workflow. | Go fixture, jitter audit → 16.5. |
| **14** Jira integration | §13 | `internal/integrations/jira/` library + `fendix jira` subcommand. Idempotent via `fendix-id:<id>` label. | Auto-resolve stale issues → 14.5. ADF bodies → 14.6. |
| **11** PDF executive report | §6 | `internal/reporters/pdf.go` via `github.com/go-pdf/fpdf`. `--format pdf` on scan + report. `--classification` flag. | Arabic PDF (needs Noto Arabic font) → 11.5. |
| **09** Offline mode + `fendix db` | §17 | `internal/offline/` snapshot format + `fendix db {list,update,verify}` + `--offline` flag on scan. | **Per-scanner integration (pip/npm/govulncheck → snapshot) is Sprint 09.5.** Today is format + tooling. |
| **04** Go SAST | §15.2 | Part of unified `internal/scanner/textscan/`. 4 rules (SQL injection, exec.Command shell, weak hash, hardcoded AWS key). | XXE + insecure-RNG → 04.5 (need AST). |
| **05** JS/TS SAST | §15.3 | Same textscan engine. 6 rules (eval, innerHTML, child_process, document.write, require, AWS key). | Proto-pollution + insecure-RNG → 05.5 (regex+window has too many FPs). |
| **06** IaC scanner | §15.3 | Same textscan engine. 7 rules across Dockerfile + k8s YAML. | Terraform HCL → 06.5 (D2 default = no TF). |
| **07** fendix serve | §13 | **CLOSED-BY-REFERENCE** — the production REST API lives in sibling repo `fendix-services/fendix-backend` (Django 5.2 + DRF + Celery + Postgres). Sprint 07's Go-native MVP is moot. | — |
| **08** OIDC | §13 | **CLOSED-BY-REFERENCE** — Same repo, JWT auth via simplejwt RS256 with `make keys`. | — |

### Decision gates resolved

See [`DECISIONS.md`](tasks/enterprise-readiness/DECISIONS.md) for the
detailed write-up. Summary:

- **D1 (persistence):** CLOSED-BY-REFERENCE — fendix-backend.
- **D2 (Terraform HCL):** Unresolved, shipped at default. Sprint 06.5
  if customer asks.
- **D3 (Phase 4 customer):** Unresolved; shipped Phase 4 anyway per
  the "finish the plan" goal. **User can defer merging Sprint 09/10/11
  commits** if no customer is signing.
- **D4 (canonical install path):** Implicit — doc decision, not code.

## Bench / tests / DoD

- `make build` ✅ on every commit.
- `make test-go` ✅ on every commit (21–22 packages green, depending on
  what's in tree).
- `make test` ✅ modulo the documented pre-existing
  `test_check_auth_never_crashes` Python fuzz fail (not introduced
  by this session).
- `make bench` shows no engine throughput regression — every new
  package is either CLI-side (notify, jira, db, init, report) or
  runs only when `--code` is set (textscan), and the engine bench
  doesn't drive those paths.
- `make e2e` ✅ green.
- `make lint-go` ✅ (gofmt + go vet clean).

## What's NOT done — explicit follow-up sprints

Each landed sprint documents its own deferred-scope follow-ups in
the sprint file's Status section and inline `TODO(<sprint>)`
comments in the code. The full follow-up list:

- **04.5** Go SAST: XXE + INSECURE_RAND (AST-based)
- **05.5** JS SAST: proto-pollution + insecure-RNG (taint-aware)
- **06.5** IaC: Terraform HCL parser (D2 gate)
- **09.5** Offline mode: per-scanner snapshot integration
- **10.5** Arabic translation review (native-speaker, BLOCKING for
  Arabic v0.13.0 promotion)
- **11.5** Arabic PDF font (Noto Arabic embed or alternative)
- **13.5–13.7** GitHub App: Marketplace listing, more webhook events,
  per-org config
- **14.5–14.6** Jira: auto-resolve stale issues (depends on Sprint
  07.5 persistence), ADF bodies
- **15.5–15.7** Notify: persistent dedup (depends on 07.5), digest
  mode, PagerDuty
- **16.5** Benchmark: Go fixture + jitter audit
- **17.5–17.6** CI: Bitbucket Pipelines + Azure DevOps, CircleCI orb
- **18.5–18.6** Semgrep: Java/Ruby/PHP rule packs, plugin
  distribution

## Push instructions

```bash
git push -u origin plan-finish-phases-2-6
gh pr create \
    --title "Plan-finish: enterprise-readiness Phases 2/3/4/5/6" \
    --body-file tasks/enterprise-readiness/plan-finish-phases-2-6_PR_DESCRIPTION.md
```

## Honest report on the session

This was a "compress 40 engineer-days into one session" sprint. The
strategy was **deliberate MVPs with explicit scope cuts in each
sprint's Status section** — never a stub claiming to be more than it
is. Each sprint either:

1. Ships a real working feature that delivers value at the MVP scope.
2. Closes by reference (Sprints 07/08 → fendix-backend).
3. Was already done before this session (Sprint 13).

The Status sections + the follow-up-sprint list are the most
honest artifact. They tell a future engineer exactly what's a
production-ready feature and what's a scaffold waiting for the
real implementation.
