---
name: project-fendix-known-failing-tests
description: "Tests that fail on Fendix `main` and are NOT to be fixed as part of any enterprise-readiness sprint. Hard rule from the bootstrap prompt; check before claiming a regression."
metadata: 
  node_type: memory
  type: project
  originSessionId: 911255e3-c2a2-41c3-978e-966f3a6969e0
---

These tests are confirmed-failing on `main` as of 2026-05-14. The
bootstrap prompt's hard rule: *"do not fix it as part of these sprints.
Note it and continue."* Always cross-check a "new" test failure against
this list before assuming your work caused it.

**Python (`make test-python`):**

- `python/tests/test_fuzz.py::TestSpecParserFuzz::test_check_auth_never_crashes`
  — Hypothesis falsifies with `{'servers': None}`; the `spec_parser.py`
  code at line 147 doesn't handle the None case and raises TypeError.
  Pre-existing for at least the duration of the Phase 1 work.

**Go e2e (`make e2e`):**

- `TestCorrelator_HybridScanProducesCorrelatedFinding` — somewhere in
  the hybrid blackbox+whitebox correlation pipeline.
- `TestReachable_HybridScanProducesReachableCorrelated` — same area.

Both confirmed by checking out `main` and running the e2e suite during
the Phase 1 session.

**Go CI-only flakies (pass locally on macOS, fail on GitHub-hosted
Linux runners) — RESOLVED on branch `fix/flaky-ctx-cancel-tests`
(PR #3, off main; not yet merged):**

- `TestScan_ContextCancellationKillsSemgrep`
  (`internal/scanner/semgrep`) — asserts elapsed ≤ 2s after a
  200ms ctx-timeout against a fake semgrep that `sleep 5`s. On
  Linux CI it takes the full 5s because `exec.CommandContext`'s
  default Cancel SIGKILLs only the entrypoint; the orphaned
  `sleep` keeps the I/O pipes alive until it dies.
- `TestRun_Timeout` (`internal/plugin`) — identical pattern with
  a plugin manifest declaring `timeout: 200ms`.

Both fixed by setting `cmd.WaitDelay = 1 * time.Second` on the
subprocess in `plugin.go:244` and `semgrep/scanner.go:120`, plus
bumping the test budgets from 2s → 4s as belt-and-suspenders. After
the merge of PR #3 both should be green on every CI run; remove them
from this list once that merges. Until then, if a future session hits
either failure on `main`-derived work, the cause is "PR #3 not merged
yet" — point them at the PR.

**Go CI flakies still unresolved (intermittent on `main`, pre-existing,
NOT introduced by Phase 1 or PR #3):**

- `TestOrchestrator_BaselineDiffIntegration` (`internal/engine`) —
  asserts that a second scan against an unchanged target produces zero
  new findings vs. baseline. Hit on PR #3's first CI run (2026-05-14)
  AND on main run `25807677016` (2026-05-13). Pass rate ~80–90%
  locally and on CI; passes 5/5 times locally on macOS with `-race`.
  Root cause hypothesis: parallel `Workers: 2` + brute-force endpoint
  discovery against a fake server (`newVulnerableServer`) produces
  slightly-different (endpoint, finding-id) ordering across the two
  scans, generating spurious "new" findings in the diff. Real fix is
  probably to disable brute-force discovery in this test (or shrink
  to `Workers: 1`) — but neither knob is exposed on `ScanConfig`
  today, so it's a 30-60min product change. **Not yet picked up as a
  separate sprint.** If it fires during your session, rerun the job;
  it almost always passes on the second attempt.
- `TestRun_MalformedLineSkippedNotFatal` (`internal/plugin`) —
  appeared in main run `25823902846` (2026-05-13). Has not recurred
  since. Watch list only.

**Go CI "Format check" step (`gofmt -l . then exit-1-if-nonempty`)
was failing on every `main` run for 21 files of cosmetic struct-field
alignment drift. RESOLVED on branch `fix/gofmt-main` (PR #4, off main;
not yet merged). After PR #4 merges, `gofmt -l .` returns zero output;
the format check is green on every subsequent run.

**Why:** The plan's first principle is honest scope. A sprint that
expands to fix unrelated pre-existing bugs grows in ways the plan can't
account for, and a green test suite stops being a useful ship-gate
because everyone learns to expect noise.

**How to apply:** When `make test` or `make e2e` reports a failure
during your sprint:
  1. Check this list. If the failure is here, it's pre-existing —
     mention it in your Status section as "noted and continued" and
     move on.
  2. If the failure is NOT here, it's likely yours. Investigate before
     committing. Don't add it to this list as a workaround.
  3. If you confirm a NEW pre-existing failure (one that was failing
     on main but isn't on this list), update this memory with the
     test name and a one-line cause, so future sessions can skip the
     same investigation.

Verify suspected pre-existing failures by checking out `main`, running
the relevant test, then coming back to your branch — see
[[gotcha-fendix-build-artifacts-and-stash]] for the safe way to do
that round trip.
