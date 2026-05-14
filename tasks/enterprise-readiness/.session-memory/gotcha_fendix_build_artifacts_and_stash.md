---
name: gotcha-fendix-build-artifacts-and-stash
description: "Two operational traps in this repo — `make build` modifies a tracked .gitkeep, and `git stash pop` after a checkout-main round trip can silently drop tracked-file edits because of it."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 911255e3-c2a2-41c3-978e-966f3a6969e0
---

## Trap 1: `make build` re-modifies a tracked file

`make build` re-stamps `go/internal/embedded/engine/.gitkeep` with a
comment line every time it runs. The file is tracked, so this shows up
in `git status` after every build. **Do not stage it; do not commit
it.** Use explicit paths in `git add`, never `git add -A` or `git add
.`. The file is part of the build's "reset embed dir" step (TASK-118
dropped the embedded Python distribution; the .gitkeep keeps the
directory in git but the build re-writes it as documentation).

**Why:** The user has not chosen to commit this churn. Including it in
sprint commits would pollute the diff and confuse later review.

**How to apply:** When staging at end of a sprint, explicitly list every
file you want in the commit. If the working tree shows .gitkeep
modified at end of session, leave it modified — the user will deal with
it (or the next `make build` will overwrite it again anyway).

## Trap 2: `git stash pop` after `checkout main` silently drops edits

If you `git stash` your in-progress sprint work, `git checkout main`
(e.g. to baseline a bench against main), then `git checkout
phase1-trust-fixes && git stash pop`, the stash pop can fail silently
when the .gitkeep build artifact (Trap 1 above) is in the way. The
stash entry stays "in case you need it again" but the worktree only
gets the untracked files back — your tracked-file edits are MISSING.

This bit me in Sprint 03: I stashed my correlated-finding dispatcher
fix, baselined bench against main, came back, popped the stash, and
the dispatcher fix was gone. Recovered via `git stash apply` (not
pop) after `git checkout -- go/internal/embedded/engine/.gitkeep` to
clear the blocker.

**Why:** The .gitkeep modification gets recreated by `make build` (which
runs as part of `make bench` etc.), so it's present whenever you bench.
The stash pop's three-way merge then conflicts on it and silently
chooses to skip the merge of the modified files.

**How to apply:** If you need to baseline against main during a sprint,
prefer one of:
- `git worktree add /tmp/fendix-baseline main && cd /tmp/fendix-baseline && make bench` (no stash needed)
- Commit your work as a WIP, baseline, reset HEAD~1 if you want to
  re-edit, OR just keep the WIP and amend later

If you do use stash, `git stash apply` (not pop) so a failed apply
leaves the stash intact and obvious. After successful apply, drop
explicitly with `git stash drop`.
