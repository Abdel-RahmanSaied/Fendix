# Fendix — Enterprise Readiness Plan

This directory holds the sprint-by-sprint plan for taking Fendix from
v0.11 to enterprise-ready (target: v0.14).

## Files

| File | What it's for |
|---|---|
| [`PLAN.md`](PLAN.md) | Master plan — sprint roster, decision gates, recommended ordering, cuts vs. source brief. **Start here.** |
| [`DECISIONS.md`](DECISIONS.md) | Decision log — records which gates have been resolved, when, and why. |
| [`RISKS.md`](RISKS.md) | Cross-sprint risk register — risks that span multiple sprints or grow over time. |
| `sprint-NN-<name>.md` | One file per sprint. Self-contained: read-first list, deliverables, tests, DoD, follow-ups. |

## How to use this directory

### If you're starting a sprint
1. Open the sprint file you've been assigned.
2. Follow the "Read first" list. Don't skip — these are the files that prevent the trap of "this is more complicated than the brief implies."
3. Confirm any decision gates listed at the top of the sprint are resolved (see [`DECISIONS.md`](DECISIONS.md)).
4. Implement, test, ship.
5. Update the sprint file's "Status" section with actual-vs-estimate and any surprises.

### If you're reviewing the plan
- Read [`PLAN.md`](PLAN.md) top to bottom. The sprint files are reference.
- Focus on the "Cuts vs. source brief" table and the decision gates — those are where the plan disagrees with the source brief.

### If you're estimating budget
- Sum the `Days` column from PLAN.md's roster for the sprints you want to fund.
- Add 20% buffer for unplanned work surfaced during review.
- Calendar time at 70% capacity: roughly 2× the engineer-day total for a solo engineer.

### If you're auditing what's been deferred
- [`sprint-12-nca-ecc-deferred.md`](sprint-12-nca-ecc-deferred.md) — the one fully-deferred sprint
- "Cuts vs. source brief" table in [`PLAN.md`](PLAN.md) — features cut from sprints that DID ship
- Each sprint file has a "Follow-ups" section listing what we deliberately didn't ship in that sprint

## How to maintain this directory

When a sprint completes:
1. Mark ✅ in PLAN.md's roster table
2. Fill in the sprint file's "Status" section
3. If new follow-up sprints are needed, add them to the roster with a new number (e.g. Sprint 4.5)
4. If risk turned out higher than estimated, add an entry to RISKS.md

When a decision gate is resolved:
1. Strike through the gate in PLAN.md
2. Add the resolution to DECISIONS.md with date + rationale
3. Update affected sprint files

## Quick navigation

- **Trust fixes (small, high-leverage):** Sprints [01](sprint-01-pip-audit-naming.md), [02](sprint-02-osv-batch.md), [03](sprint-03-verify-scope.md)
- **New SAST engines:** Sprints [04](sprint-04-go-sast.md), [05](sprint-05-js-sast.md), [06](sprint-06-iac-sast.md)
- **Server mode:** Sprints [07](sprint-07-fendix-serve.md), [08](sprint-08-oidc.md)
- **Government / compliance:** Sprints [09](sprint-09-offline-mode.md), [10](sprint-10-arabic-html.md), [11](sprint-11-pdf-report.md), [12 DEFERRED](sprint-12-nca-ecc-deferred.md)
- **Integrations:** Sprints [13](sprint-13-github-app-handler.md), [14](sprint-14-jira.md), [15](sprint-15-slack-teams.md)
- **Polish:** Sprints [16](sprint-16-benchmarks.md), [17](sprint-17-ci-templates.md), [18](sprint-18-semgrep-rules.md)

---

Generated 2026-05-14 from the audit + source brief. See PLAN.md for the
full backstory.
