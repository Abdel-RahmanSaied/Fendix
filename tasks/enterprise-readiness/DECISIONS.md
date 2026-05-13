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
