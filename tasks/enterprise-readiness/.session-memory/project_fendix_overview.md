---
name: project-fendix-overview
description: "What Fendix is, where the enterprise-readiness plan lives, and the working conventions a new session needs to know before reading the plan."
metadata: 
  node_type: memory
  type: project
  originSessionId: 911255e3-c2a2-41c3-978e-966f3a6969e0
---

Fendix is a hybrid API + code security scanner. The user works on this
project from more than one machine, so the repo path differs by device
— always derive it via `git rev-parse --show-toplevel`, never hardcode
it. The Go module is in `go/` (not the repo root); the Python engine is
in `python/`. CLI binary lands at `bin/fendix` after `make build`.

The enterprise-readiness plan is the active work track. Master plan:
`tasks/enterprise-readiness/PLAN.md`. Sprint files alongside it
(`sprint-NN-*.md`) are self-contained briefs with Read-first lists,
deliverables, DoD, and a Status section to fill in.

**Why:** The user is shipping Fendix from v0.11 toward v0.14
"enterprise-ready." The plan's value comes from honesty: deferred
sprints are documented (`sprint-12-nca-ecc-deferred.md`), cuts vs. the
source brief are listed in PLAN.md, and each sprint's Status section
captures actual-vs-estimate so future sessions can plan against
calibrated numbers.

**How to apply:** Any session picking this work up should
(1) read PLAN.md + DECISIONS.md + RISKS.md, (2) check which sprints have
✅ in PLAN.md's roster, (3) check Status sections of recently-shipped
sprints for follow-ups, (4) propose a candidate sprint to the user
before writing code. See [[feedback-fendix-sprint-shipping-pattern]] for
how to actually execute one.

Conventions confirmed effective:
- Branch per session: `<phase>-<topic>` (e.g. `phase1-trust-fixes`,
  `sprint-02p5-npm-batch`).
- One commit per sprint; each commit independently builds + tests +
  benches.
- Co-author trailer: `Co-Authored-By: Claude Opus 4.7 (1M context)
  <noreply@anthropic.com>`.
- Never push to origin or open PRs without explicit user confirmation.
- Draft PR descriptions as working files under
  `tasks/enterprise-readiness/<branch>_PR_DESCRIPTION.md` (the user
  copy-pastes them when they actually push).
- Session memory lives **in the repo** at
  `tasks/enterprise-readiness/.session-memory/` (not under
  `~/.claude/...`) so it syncs across devices via git. Update it there
  during hand-off; commit the updates with the rest of the session's
  work. The user's `~/.claude/projects/.../memory/` for this project
  holds only a POINTER.md confirming the canonical store is in-repo.
