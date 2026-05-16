---
name: feedback-fendix-sprint-shipping-pattern
description: "How to ship an enterprise-readiness sprint cleanly — sprint-file fidelity, status-section honesty, and the build-artifact + stash gotchas that bite if you don't know about them."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 911255e3-c2a2-41c3-978e-966f3a6969e0
---

When implementing a sprint from `tasks/enterprise-readiness/sprint-NN-*.md`:

1. **Sprint files sometimes lie about paths and names.** Verify on disk
   before editing. Phase 1 examples: sprint-01 referenced
   `go/internal/models/scan_config.go` (actual: `config.go`); sprint-03
   referenced `verifycmd.StatusNotFoundInBaseline` (actual:
   `StatusNotFound`). Adjust silently when the divergence is purely
   nominal; flag in the commit body or Status section if it changes
   anything material.

2. **The "Read first" section is load-bearing.** Skipping it triggers
   the "this is simpler than the brief implies" trap. The Risks section
   is also worth its weight — it's the planner's pre-mortem.

3. **Tests can surface real bugs the sprint didn't scope.** Sprint 03's
   `TestRunCorrelatedFindingReturnsUnknownWithExplanation` failed on
   first run because the dispatcher was routing by *finding shape*, not
   by *source* — a hidden bug in pre-existing code that contradicted the
   user-facing docs. Sprint 18's new YAML catalog test surfaced a
   pre-existing YAML-quoting bug in `auth.yaml`'s JWT rule that
   semgrep's loose parser tolerated but `gopkg.in/yaml.v3` didn't. The
   right move is to fix the bug as part of the sprint AND document the
   surprise in Status; don't silently weaken the test to dodge the bug.

4. **Sprint briefs sometimes assume infrastructure that doesn't exist.**
   Sprint 18 asked for "30 test cases (15 positive, 15 negative)"
   implying real semgrep invocations against fixtures. But all
   existing semgrep tests use `installFakeSemgrep` (a shell script
   that printf's pre-computed JSON), because semgrep isn't on dev
   machines or CI runners. Forcing 30 mock-semgrep tests would
   re-test the mapping layer (already covered) and lie about what's
   being validated. The honest interpretation: rebuild the test
   shape to fit what the codebase actually does — Sprint 18 went
   with a YAML-only catalog audit that asserts every rule's
   metadata invariants, plus a single `semgrep --validate` test
   gated on `command -v semgrep`. Document this divergence
   explicitly in Status and CHANGELOG so reviewers don't see "8
   tests instead of 30" and think the sprint was cut short. The
   pattern: when a brief's test plan presumes infra you don't have,
   substitute a test shape that exercises the same invariants via a
   different mechanism, and write up the substitution.

5. **Status sections are the most valuable artifact you produce for
   future sessions.** One bullet per surprise, `actual vs. estimate`
   numbers, manual-DoD evidence (real `--help` output, real scan
   output), and bench tables. Future sessions read these to calibrate
   plans and to spot follow-up work.

**Why:** The plan's premise is honesty over heroics. Sessions that ship
fast but skip the Status section leave the next session blind. Sessions
that find a hidden bug and fix it (vs. work around it) compound trust
in the codebase.

**How to apply:** When you pick up a sprint from this directory, allocate
~10 minutes for Step 0 reading (PLAN, prior-Status sections, the
specific sprint's Read-first list) before touching code. When you
finish, allocate ~15 minutes for Status updates and PR-description
draft. Both are non-negotiable parts of "done."

Related: [[gotcha-fendix-build-artifacts-and-stash]] for the two
specific operational traps that wasted time in the prior session.
