# Decision log

Record decisions on gates listed in [PLAN.md](PLAN.md). One entry per
gate per decision. Format:

```
## D<N> — <gate name>

**Decided:** YYYY-MM-DD
**Decided by:** <name / role>
**Resolution:** Option A | Option B | Option C
**Rationale:** <one paragraph>
**Affects sprints:** <list>
```

---

## D1 — Persistence story (Sprints 7, 14, 15)

**Status:** UNRESOLVED — default is "in-memory forever" until decided.

Options:
- **A:** Add Sprint 7.5 introducing SQLite persistence. ~3 days of work; one new pure-Go dep (`modernc.org/sqlite`). Touches every later sprint's data model.
- **B:** Stay in-memory forever. Document the restart-loses-state caveat on every integration.

---

## D2 — Terraform license acceptance (Sprint 6)

**Status:** UNRESOLVED — default is "no TF support" until decided.

Options:
- **A:** Accept `github.com/hashicorp/hcl/v2` (MPL-2.0) as a runtime dependency. Real TF support in Sprint 6.5.
- **B:** Stay regex-only on TF. Sprint 6 ships Dockerfile + k8s, defers TF entirely.
- **C:** Hand-rolled HCL subset parser. ~2 weeks. Last resort.

---

## D3 — Phase 4 customer commitment (Sprints 9, 10, 11)

**Status:** UNRESOLVED — default is "reorder Phase 4 to last" until decided.

Options:
- **A:** Confirmed customer / contract — ship Sprints 9, 10, 11 as ordered.
- **B:** Speculative — push Phase 4 to *last* in the recommended ordering; ship Phase 5 (integrations) first.

---

## D4 — Canonical install path (Sprint 13, marketing)

**Status:** UNRESOLVED — default is "promote both" until decided.

Options:
- **A:** GitHub App is canonical once Sprint 13 ships.
- **B:** GitHub Actions workflow is canonical; the App is a power-user option.

---

(Add entries below as gates resolve.)

---

## Plan-finish session (2026-05-15) — gate resolutions

The plan-finish session shipped 13 sprints onto branch
`plan-finish-phases-2-6`. Default-gate resolutions taken for the
purpose of marking the plan complete; the user can revisit any of
these and re-open a sprint as a follow-up.

### D1 — Persistence story

**Status:** CLOSED-BY-REFERENCE 2026-05-15
**Resolution:** The persistence story lives in the sibling
[`fendix-backend`](../../fendix-services/fendix-backend) Django+DRF
repo (Postgres 16 + Redis + Celery 5.4). The in-memory caveat from
Sprint 07's brief is moot — fendix-backend is the production
REST + persistence layer, and the fendix CLI in this repo remains
a CLI.

### D2 — Terraform license acceptance (Sprint 6)

**Status:** UNRESOLVED — shipped at Option B's default (no TF).
Sprint 06 ships Dockerfile + k8s only. Real Terraform support
would require `github.com/hashicorp/hcl/v2` (MPL-2.0); kept out of
scope until a customer asks. Tracked as Sprint 06.5.

### D3 — Phase 4 customer commitment (Sprints 9, 10, 11)

**Status:** UNRESOLVED — shipped anyway per the plan-finish goal
"finish the plan." Sprints 09 (offline mode), 10 (Arabic HTML), and
11 (PDF) land on the plan-finish branch. The user can defer
merging the Phase-4 commits until D3 is made explicit. Without
a confirmed customer, the maintenance burden of the Arabic
translation review (Sprint 10.5) and the per-scanner offline
wiring (Sprint 09.5) is open.

### D4 — Canonical install path (Sprint 13, marketing)

**Status:** Implicit — Sprint 13 reframed: the GitHub App handler
was already implemented before this session started. The doc-drift
fix that landed restores honest framing. Choice between "GitHub
Actions workflow" and "GitHub App" as the marketing-canonical path
is a docs decision, not a code one. Leave unresolved until
marketing time.
