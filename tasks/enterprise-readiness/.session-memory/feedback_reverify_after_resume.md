---
name: Re-verify disk state when resuming work — workspace may have pulled
description: If you read disk state in an earlier turn or session, re-check before acting on it; the workspace can fast-forward between checks.
type: feedback
originSessionId: ae5695e5-f6f4-434e-9673-f13fd8d7c1a1
---
When picking work back up — whether across sessions or just across several turns of the same conversation — re-verify any disk state you previously read. Local repos in this workspace can `git pull --tags origin main` between checks, and the new commits don't announce themselves.

**Why:** On 2026-05-11 I read fendix-backend, saw one commit (`6547aea first commit`) and only the legacy `Fendix_Main_App/` apps. I concluded the plan was fictional and edited docs/example_plan.md + tasks/MEMORY.md to "correct" it. When the user later asked me to re-check, fendix-backend had pulled 38 commits and contained a `backend/` directory with the full subscriptions/billing/scanning/accounts apps the plan described. The plan was right; my correction was the error. Reflog confirmed `pull --tags origin main: Fast-forward` happened between my first read and the user's request. Two contributing failures: (a) I scanned past `backend/` at the repo root and only looked at `Fendix_Main_App/`, (b) I trusted the earlier disk read as ground truth instead of re-reading when challenged.

**How to apply:**
- Before claiming "X doesn't exist" based on an earlier `ls`, re-run the `ls` in the current turn.
- When listing a repo root, scan the *entire* listing for relevant dirs — don't anchor on the first plausible one and stop.
- If git history seems unexpectedly thin (one commit on what should be an active project), run `git reflog` and `git rev-list --count HEAD` before concluding the repo is empty.
- If the user pushes back ("check again"), treat that as strong signal you misread, and re-verify *everything*, not just the specific claim they questioned.
