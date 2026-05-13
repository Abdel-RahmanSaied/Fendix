# Next-session bootstrap prompt

This file holds the prompt to start a fresh Claude Code session that
picks up the enterprise-readiness plan and ships **Sprints 01–03 (Phase 1
trust fixes)** as a single v0.11.1 release.

Copy everything in the fenced block below and paste it as the first
message of a new session. The new session reads this without prior
chat context, so the prompt is self-contained — it points at files
on disk, not memory.

---

```
You are picking up the Fendix enterprise-readiness plan to ship Phase 1
(Sprints 01–03) as v0.11.1. The plan, audit, and per-sprint tasks are
all committed at HEAD on main. You have not seen them before; read them
on disk before writing any code.

# Where you are

Working directory: /Users/saied/WorkDir/Fendix/fendix-services/Fendix
Branch state at session start: main is at the tip of a recently-merged
work cycle (5 commits landed: Track 4 engine fixes + the
enterprise-readiness plan + the audit report). Do not push to origin.

# What to do (in order)

## Step 0 — Ground yourself (mandatory, ~10 minutes)

Read these files in this order, in full. Do not skim:

1. tasks/enterprise-readiness/README.md
2. tasks/enterprise-readiness/PLAN.md
3. tasks/enterprise-readiness/DECISIONS.md
4. tasks/enterprise-readiness/RISKS.md
5. FENDIX_AUDIT_REPORT.md (specifically §3, §7, §15.4, §15.5 — the
   sections each Phase 1 sprint addresses)

Then read each sprint file you'll implement:

6. tasks/enterprise-readiness/sprint-01-pip-audit-naming.md
7. tasks/enterprise-readiness/sprint-02-osv-batch.md
8. tasks/enterprise-readiness/sprint-03-verify-scope.md

The sprint files contain "Read first" sections at the top. Honor them.
The trap of "this is simpler than the brief implies" only opens when
you skip the read-first list.

## Step 1 — Confirm prerequisites

Before implementing, confirm:

- `make build` succeeds on main as-is
- `make test` passes (Python: 174 + 6 pre-existing fuzz flake; Go: all
  21 packages green)
- `bin/fendix --version` reports a v0.11.x build
- pip-audit is available (or installable): `pip install pip-audit && pip-audit --version`
  — needed for Sprint 01's subprocess test path
- `golang.org/x/sync` is an indirect dep in go.mod (Sprint 02 promotes
  it to direct; confirm it's not already direct)

If any prerequisite fails, surface it before writing code — do not
work around it.

## Step 2 — Branch strategy

Create branch `phase1-trust-fixes` off main. All three sprints land
as commits on this branch:

  git checkout -b phase1-trust-fixes main

Three commits, one per sprint, in this order:
  - Commit 1: Sprint 01 (pip-audit naming + fallback flag)
  - Commit 2: Sprint 02 (OSV batch queries + concurrency cap)
  - Commit 3: Sprint 03 (verify scope + exit codes)

Each commit must independently:
  - Build (`make build`)
  - Pass tests (`make test`, including the new tests for that sprint)
  - Pass `make bench` with no regression vs. main
  - Update CHANGELOG.md under [Unreleased] → v0.11.1

After all three commits land, you'll have v0.11.1 ready to tag.

## Step 3 — Implement Sprint 01

Follow tasks/enterprise-readiness/sprint-01-pip-audit-naming.md exactly.
The sprint file specifies file paths, function signatures, test names,
and CHANGELOG wording. Stay inside that scope; do not refactor
adjacent code.

Specific things to watch for:

- The package doc comment update in pip/scanner.go must read literally
  what the sprint file says (it's the line an external evaluator
  inspects to verify the trust fix). Do not editorialize.
- The new `--use-pip-audit` flag MUST be Hidden:false (visible in
  --help). It's a real feature, not a stub.
- The pip-audit JSON schema tests need a fake binary shell script.
  See the writeFakePipAudit helper in the sprint file.
- pip-audit exits 1 when findings exist — that's normal, not an error.
  The sprint's TestScanViaSubprocess_ExitCode1WithFindingsIsNormal
  test locks this in.

Definition of done for Sprint 01 is at the bottom of its sprint file.
Verify every checkbox before committing. Update the sprint file's
Status section with actual-vs-estimate and any surprises.

## Step 4 — Implement Sprint 02

After Sprint 01 is committed and tests pass, move to Sprint 02.

Honest expectation up front: OSV.dev's /v1/querybatch response shape
omits aliases. Sprint 02's plan explicitly accepts this — batch
findings ship with only the OSV-id in references; aliases (CVE-*)
are deferred to Sprint 02.5. Do NOT try to hydrate aliases inside
this sprint. The sprint file says so; honor it.

Performance gate: post-sprint `make bench` against a 150+ pinned-dep
fixture must be ≥4x faster than pre-sprint. Capture both numbers in
the commit message body.

If the OSV.dev batch endpoint behaves differently than the OSV.dev
docs describe (this has happened before), document the divergence
in the sprint file's Status section and in the code's comments.

## Step 5 — Implement Sprint 03

After Sprint 02 lands, move to Sprint 03. This is the smallest sprint
(~0.5 day). Three small deliverables:

  1. Update verify's --help with the supported/unsupported list
  2. Improve the default-branch Reason string in verifycmd.go::Run
  3. Add exit code semantics (0/1/2) to main.go's verify RunE

The sprint requires adding an internal/cli/exit.go helper if it
doesn't already exist. Confirm before creating.

Existing verify tests (~12 of them) must still pass. The four new
exit-code tests live in go/internal/e2e/verify_e2e_test.go under
the e2e build tag. Use `make e2e`, not `make test`, to exercise them.

## Step 6 — Definition of done for the whole phase

After all three commits land:

- `make test` green (Python 174 + Go 21 packages)
- `make e2e` green
- `make bench` shows no SAST throughput regression vs. main; Sprint 02's
  4x speedup on the dep-CVE fixture is captured in PR description
- bin/fendix scan --help shows the new --use-pip-audit flag
- bin/fendix verify --help shows the new exit-code table
- CHANGELOG.md has the v0.11.1 section under [Unreleased] with all
  three sprints' entries combined
- Each sprint file's Status section is filled in with actual-vs-
  estimate, surprises, and any follow-ups
- A PR description is drafted citing FENDIX_AUDIT_REPORT.md §15.5,
  §15.4, and §7 (one per sprint)

Do NOT push to origin or open the PR yourself — leave the branch
locally and report back to the user with:
  - The 3-commit log
  - Bench numbers before/after
  - Any surprises that warrant updates to the plan or other sprint files

## Hard rules

- Do not modify code outside the sprint's scope. The sprint files
  list exact file paths; stay inside.
- Do not change CLI flag names, .fendix.yaml keys, or the Finding
  struct JSON shape. Additive only.
- No new CGo. No new direct deps beyond what the sprint files specify
  (Sprint 02 promotes golang.org/x/sync from indirect to direct;
  nothing else).
- If a sprint's "Read first" list mentions a file you can't find,
  stop and surface that — don't guess.
- If a test is failing in main (not introduced by your work), do not
  fix it as part of these sprints. Note it and continue. Pre-existing
  fuzz failure in python/tests/test_fuzz.py::test_check_auth_never_crashes
  is known and unrelated.
- If you find yourself wanting to defer a sprint feature to make
  ship-date, say so before doing it. The plan has explicit cuts;
  silent cuts erode the plan's value.

## Reference: what's already on main

The work that landed in the previous session:

  046408f feat(engine): Track 4 quality lift — 7 gaps closed, heavy-eval harness + CI
  31cc74d feat(pip-audit): walk subdirectories for requirements.txt (Track 4 gap 1)
  9bd84bd feat(verify): ship `fendix verify <id>` — was a Phase-4 stub (Track 4 gap 2)
  af2bbce fix(auth-probe): dedup JWT-bypass FPs on fully-public endpoints (Track 4 gap 3)
  cf431ce docs: enterprise readiness sprint plan (Phases 1-6, 17 active + 1 deferred sprints)
  5103be5 docs: commit FENDIX_AUDIT_REPORT.md (referenced by enterprise-readiness plan)

You are starting from 5103be5. The plan and audit are at HEAD.

## When in doubt

Read the sprint file's risks section. Each sprint surfaced the
likely surprises during planning; if you hit one, the mitigation
is already documented.

Begin with Step 0. Do not skip it.
```

---

## How to use this prompt

1. Open a new Claude Code session in this repo (or any Claude session
   that can read this filesystem).
2. Paste the fenced block above as the first message.
3. Let the session run. It will:
   - Read the plan + audit + sprint files (~10 minutes)
   - Confirm prerequisites (build/test/pip-audit available)
   - Create the `phase1-trust-fixes` branch
   - Land Sprint 01, then Sprint 02, then Sprint 03 as three commits
   - Report back with the 3-commit log, bench numbers, and any
     surprises

## What to expect back

- A branch `phase1-trust-fixes` locally with 3 commits
- An honest report (not just "done") covering:
  - Actual vs. estimated time per sprint
  - Surprises encountered (and which sprint file they should be
    added to as risks)
  - Any code outside the sprint scope that needed touching
- Tests + bench results in the report
- The PR description drafted but NOT pushed

## If you want the session to take a different shape

The prompt is opinionated for "Phase 1 in one session." Other shapes
that would also work:

- **One sprint per session, three sessions** — replace `Sprints 01-03`
  with `Sprint 01` in the prompt header and adjust Steps 3-5 to a
  single sprint. Lower risk of mid-session fatigue; longer calendar.
- **Sprint 01 only, then evaluate** — same as above but explicitly
  stops after Sprint 01 ships so you can decide whether to continue.

Edit the prompt directly to change the shape. The structure (Step 0
ground yourself, branch off main, one commit per sprint, hard rules
at the bottom) should stay the same regardless of which sprints land.

## When to regenerate this prompt

When the plan evolves enough that Step 0 should point at different
files, or when the next sprint to ship is no longer Sprints 01-03,
update this file. The prompt is committed alongside the plan so
edits land naturally with each plan update.
