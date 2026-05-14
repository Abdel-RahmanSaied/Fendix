# Next-session bootstrap prompt

This file holds the prompt to start a fresh Claude Code session that
picks up the enterprise-readiness plan **wherever it currently is** and
ships the next sprint(s) in order. It is intentionally generic — the
prompt makes the session read the plan, recall what the prior session
left behind via the on-disk memory, and pick the next work item itself
rather than hardcoding a sprint.

Copy everything in the fenced block below and paste it as the first
message of a new session. The new session reads this without prior
chat context, so the prompt is self-contained — it points at files
on disk, not memory.

---

```
You are picking up the Fendix enterprise-readiness plan. The plan,
audit, per-sprint tasks, and prior-session status notes are all on
disk. You have not seen them before; read them before writing any
code.

# Where you are

Working directory: the Fendix repo. Find it via `git rev-parse --show-toplevel`
or assume `/Users/saied/WorkDir/Fendix/fendix-services/Fendix` if you're
on the primary dev machine. The path differs across the user's machines
— never hardcode it; always derive from git.

This project's session memory lives **in the repo** at
`tasks/enterprise-readiness/.session-memory/` so it syncs across
devices via git. Your auto-memory directory under `~/.claude/projects/...`
holds only a pointer (POINTER.md) confirming this — it is NOT the
canonical store. Do not write memory updates to `~/.claude/...` for
this project; write them to the repo location and commit them as part
of the session's hand-off.

Do not push to origin and do not open PRs without explicit user
confirmation.

# Step 0 — Recall and ground (mandatory, ~10 minutes)

## 0a. Memory recall

Read `tasks/enterprise-readiness/.session-memory/MEMORY.md` (the
in-repo index). Read each file the index points to, in full. These are
the only record of what prior sessions learned about this codebase
that isn't already in git history or the plan documents — read them
before anything else and treat them exactly the way you would treat
auto-loaded memory.

If your auto-memory MEMORY.md (under `~/.claude/projects/...`) contains
entries beyond a single POINTER pointing at the repo, those are stale
mirrors from before this project moved its memory in-repo. Read the
in-repo location and ignore the auto-loaded ones for project-specific
context.

## 0b. Disk reading — read these files in this order, in full

1. tasks/enterprise-readiness/README.md
2. tasks/enterprise-readiness/PLAN.md  ← the master plan
3. tasks/enterprise-readiness/DECISIONS.md
4. tasks/enterprise-readiness/RISKS.md
5. CHANGELOG.md (top section — `[Unreleased]`)
6. The most recent ~10 commits: `git log --oneline -15`
7. Every sprint file under tasks/enterprise-readiness/ that has a
   filled-in Status section showing "Status: done" or "in-progress".
   These are the prior session's actual-vs-estimate notes and the
   surprises they flagged. Pay attention to "Follow-ups created"
   sub-sections — those become candidate sprint files for *this*
   session.

The README explains the directory layout. PLAN.md has the sprint
roster (with ✅ marks for shipped sprints) and the recommended
ordering at the bottom.

# Step 1 — Decide what to ship this session

## 1a. Build the candidate list

Make a candidate list of "next sprint to ship." Sources, in priority
order:

  1. **Any sprint file with Status: in-progress.** These are the
     prior session's interrupted work. Finish them before starting
     anything new.
  2. **Any "Follow-ups created" entry from a recently-shipped sprint
     that has its own sprint file.** These are the small honest
     deferrals (e.g. `sprint-02p5-*.md`) the prior session wrote up.
     They're usually 0.5-1 day and unblock nothing important being
     missing.
  3. **The next sprint in PLAN.md's recommended-ordering table** that
     is not yet ✅. Skip sprints whose Decision Gate (D1–D4 in PLAN.md)
     is unresolved unless you have explicit user direction otherwise —
     resolving a gate without the user is a way to waste a sprint.

Stop and surface to the user if:
  - A required Decision Gate is unresolved AND blocks every otherwise-
    ready sprint.
  - The natural next sprint is large (>2 days) — confirm scope before
    starting.

## 1b. Confirm with the user before writing code

State your candidate (one sentence: "I propose Sprint XX (`title`),
estimated N days, because <reason>") and ask for go-ahead. Do not
self-authorise large work.

# Step 2 — Confirm prerequisites

For the chosen sprint, confirm:

  - `make build` succeeds on main as-is
  - `make test` passes on main as-is (Go: 21 packages green; Python:
    179 passed + 1 known pre-existing fuzz failure
    `test_check_auth_never_crashes` that is NOT yours to fix)
  - `make e2e` — note which tests fail on main as-is. Two known
    pre-existing fails as of 2026-05-14:
    `TestCorrelator_HybridScanProducesCorrelatedFinding` and
    `TestReachable_HybridScanProducesReachableCorrelated`. Do not fix
    these as part of any sprint.
  - The sprint file's "Read first" section enumerates other
    prerequisites (binaries, env, deps). Honour them.

If a prerequisite fails AND it isn't pre-existing, surface it to the
user before working around it. The hard rule is: do not silently work
around prerequisite gaps; either the user fixes them, you fix them
deliberately as their own commit, or you stop and report.

# Step 3 — Branch strategy

Default: one branch per session, multiple sprint commits if more than
one fits in the session.

  git checkout -b <topic-branch> main

Topic-branch naming: `<phase>-<short-description>` (e.g.
`phase1-trust-fixes`, `sprint-02p5-npm-batch`,
`phase2-go-sast`). Look at the prior session's branch names via
`git branch -a` and follow the existing convention.

Each commit must independently:
  - Build (`make build`)
  - Pass `make test` (the same Python fuzz fail is acceptable)
  - Pass `make bench` with no regression vs. main on the engine
    throughput numbers
  - Update CHANGELOG.md under `[Unreleased]` → the appropriate version
    heading (the prior session conventionally used `### v0.X.Y —
    Phase N <topic>` then `#### Fixed / Added / Changed / Performance`
    sub-headings)

# Step 4 — Implement the sprint

Read the sprint file's "Concrete deliverables" section. Stay strictly
inside the file paths it lists. The prior session repeatedly
discovered that:

  - Sprint files sometimes reference paths that have moved or
    function names that have been renamed. Verify on disk before
    editing; adjust the path/name silently when correct, but flag in
    the commit body or sprint Status if the divergence was material.
  - Sprint files' "Read first" section is load-bearing. The trap of
    "this is simpler than the brief implies" only opens when you skip
    it.
  - The sprint file's risk section lists likely surprises and their
    mitigations. Read it before improvising.

# Step 5 — Definition of done (per sprint)

Cross-check against the sprint file's DoD section AND PLAN.md's
"Definition of done (per sprint)" section. Don't ship until every
checkbox is true.

For the manual checks (`bin/fendix <subcmd> --help`, live invocations
against fixtures), capture the actual output in the commit body or
Status section. The prior session conventionally:

  - put bench numbers (before/after) in a small table in the commit
    body
  - put manual-DoD evidence (actual --help output, actual scan
    output) in the sprint file's Status section, not the commit body
  - listed surprises explicitly in the Status section, with one
    bullet per surprise — the prior session found this was the most
    valuable information for future sessions

# Step 6 — Hand-off

When the session ends:

  - Update the sprint file's Status section with actual-vs-estimate,
    surprises, follow-ups (with sprint-file paths if you created
    new ones).
  - Mark the sprint ✅ in PLAN.md's roster table.
  - Save anything novel to memory **in the repo location**
    (`tasks/enterprise-readiness/.session-memory/`): a NEW kind of trap
    the prior session didn't already document, a non-obvious project
    fact, a user-preference correction. Don't save things derivable
    from git/code (those rot fast). Don't duplicate prior memory
    entries. Don't write to `~/.claude/projects/...` — that location
    holds only a POINTER for this project. Commit the memory update as
    part of the session's hand-off so the next device sees it.
  - Draft a PR description as a working file at
    tasks/enterprise-readiness/<branch>_PR_DESCRIPTION.md (the
    prior session put PHASE1_PR_DESCRIPTION.md there as a template
    to copy from).
  - Do NOT push to origin. Do NOT open the PR. Report back to the
    user with:
      * The N-commit log
      * Bench numbers (where the sprint's gate required them)
      * Surprises, with a one-line take on each
      * Anything outside the sprint scope that needed touching
        (and why)
      * What's left undone — explicitly, including which sprint file
        to point the NEXT session at if relevant

# Hard rules (lifted from the prior session and confirmed effective)

- Do not modify code outside the sprint's listed file paths.
- Do not change CLI flag names, .fendix.yaml keys, or the Finding
  struct JSON shape. Additive only.
- No new CGo. Only the deps PLAN.md's "Dependency posture" section
  permits.
- If a sprint's "Read first" list mentions a file you can't find,
  stop and surface that — don't guess.
- If a test is failing in main (not introduced by your work), do not
  fix it as part of these sprints. Note it and continue. Confirmed
  pre-existing failures: `test_check_auth_never_crashes`,
  `TestCorrelator_HybridScanProducesCorrelatedFinding`,
  `TestReachable_HybridScanProducesReachableCorrelated`.
- If you find yourself wanting to defer a sprint feature to make
  ship-date, say so before doing it. The plan has explicit cuts;
  silent cuts erode the plan's value.
- The build artifact `go/internal/embedded/engine/.gitkeep` is
  re-modified by every `make build`. Do not stage it; do not commit
  it. The prior session learned to add only specific paths in `git
  add` (never `git add -A`) for this reason.
- `git stash pop` after a `git checkout main` round trip can silently
  drop tracked-file edits when the .gitkeep build artifact is in the
  way. If you need to baseline against main, prefer `git worktree
  add` over stash, OR commit your in-progress work first to a WIP
  commit and reset it later.

# Reference: how to read what's already on disk

Use `git log --all --oneline | head -20` to see what's already on
disk. Look for branches whose names match a sprint or phase
(`phase1-trust-fixes`, `sprint-02p5-npm-batch`, etc.). Cross-check
against PLAN.md's roster: a sprint is shipped if it has ✅ in the
roster, even if its branch has been merged + deleted.

If a topic branch exists locally and is NOT yet on origin, ask the
user before doing anything to it; merging or pushing is a human
decision.

# When in doubt

Re-read the relevant sprint file's Risks section. Each sprint surfaced
the likely surprises during planning; if you hit one, the mitigation
is already documented.

Begin with Step 0. Do not skip it.
```

---

## How to use this prompt

1. Open a new Claude Code session in this repo (or any Claude session
   that can read this filesystem).
2. Paste the fenced block above as the first message.
3. The session will:
   - Recall its on-disk memory entries
   - Read the plan + audit + sprint files (~10 minutes)
   - Identify the next sprint(s) to ship and confirm with you
   - Ship them as commits on a topic branch
   - Hand back with bench numbers, surprises, and explicit
     unfinished-work notes

## What this prompt does NOT do

- Hardcode which sprint is next. The session figures that out from
  PLAN.md's roster + the recommended ordering + the prior session's
  Status sections + any in-progress / follow-up sprint files.
- Authorise large work. The session must confirm scope with you
  before starting any sprint estimated >2 days.
- Push or open PRs. Always handed back to a human.

## What to expect back

- A topic branch with N commits (one per sprint)
- An honest report (not just "done") covering:
  - Actual vs. estimated time per sprint
  - Surprises encountered (and which sprint file they should be
    added to as risks)
  - Any code outside the sprint scope that needed touching
  - What's left undone, with pointers to the next session
- Tests + bench results in the report
- A PR description drafted under
  `tasks/enterprise-readiness/<branch>_PR_DESCRIPTION.md` but NOT
  pushed

## When to regenerate this prompt

This prompt is intentionally generic — it should keep working as the
plan evolves. Regenerate only if:

- The directory layout under `tasks/enterprise-readiness/` changes
  fundamentally
- The repo structure (Go module path, Makefile target names) changes
- A new hard rule emerges that future sessions need to know about

If a hard rule changes, update the "Hard rules" section in the fenced
block. If new pre-existing test failures emerge, update the list under
the same section.
