# Sprint 12 — NCA ECC compliance report (DEFERRED)

**Phase:** 4.4 | **Estimate:** — | **Risk:** N/A | **Ships:** TBD
**Audit ref:** Source brief Phase 4.4

---

## Status: DEFERRED

This sprint is deliberately not scheduled. Read on for why and what would unblock it.

---

## Why deferred

The source brief provides a hardcoded mapping table:

```go
var eccMapping = map[string][]string{
    "secrets":     {"ECC-2-3-1", "ECC-2-3-2"},
    "injection":   {"ECC-2-7-1", "ECC-2-7-2"},
    "deps":        {"ECC-2-7-3"},
    "auth":        {"ECC-2-3-3", "ECC-2-3-4"},
    "headers":     {"ECC-3-3-1"},
    "cors":        {"ECC-3-3-2"},
    "exposure":    {"ECC-2-7-4"},
    "configleak":  {"ECC-2-7-5"},
}
```

**Cannot verify this mapping against authoritative NCA ECC-1:2018 documents in this repo.** Specifically:

1. The control IDs (`ECC-2-3-1`, `ECC-2-7-2`, etc.) look plausible but the actual ECC-1:2018 PDF would need to be cross-referenced section-by-section.
2. ECC-1:2018 may have been superseded by ECC-2:2024 or later editions. Fendix shouldn't ship a report claiming compliance against a stale framework.
3. The Arabic control names in the brief's JSON shape (e.g. `"name_ar": "الدفاع السيبراني"`) need verification by a native Arabic speaker familiar with NCA's terminology.

Shipping an unverified compliance mapping is **worse than not shipping**. A government customer running `fendix report --format nca-ecc` and finding the control IDs misnumbered would damage trust permanently — and ECC reports are typically submitted to NCA audit teams who WILL catch misnumbering.

---

## What would unblock this sprint

Any one of:

1. **Authoritative ECC-1:2018 (or current edition) document** in PDF or structured form, sourced from NCA directly, cross-referenced against the brief's mapping. ~1 day to verify; ~1 day to ship.
2. **Customer-supplied mapping file** — the customer's CISO or compliance officer supplies a YAML file mapping fendix categories → ECC controls. Fendix ships the engine + JSON shape; customer owns the mapping. **~1 day total to ship** with a `--ecc-mapping <yaml>` flag and a documented schema.
3. **Native Arabic + NCA-familiar reviewer** confirms the brief's mapping AND the Arabic control names. ~3 days including review cycles.

The **fastest** unblock is option 2 (customer-supplied mapping). It lets fendix support the format without claiming knowledge of the framework.

---

## Provisional implementation plan (if unblocked)

When this sprint is funded, implement:

```
go/internal/reporters/nca_ecc.go
  RenderNCAECC(w io.Writer, findings []models.Finding, meta ScanMetadata, opts NCAECCOptions) error

type NCAECCOptions struct {
    MappingPath string  // user-supplied --ecc-mapping <yaml>; empty = error
    Lang        string  // "en" | "ar"
}
```

YAML mapping schema (user-supplied):

```yaml
framework: "NCA ECC-2:2024"
version: "2.1"
domains:
  - id: "ECC-2"
    name_en: "Cybersecurity Defense"
    name_ar: "الدفاع السيبراني"
    controls:
      - id: "ECC-2-3-1"
        name_en: "Identity and Access Management"
        name_ar: "إدارة الهوية والوصول"
        fendix_categories: ["secrets", "auth"]
```

Compliance score per domain = `(controls_with_no_findings / total_controls_in_domain) * 100`.

Output formats:
- JSON to `--output` (machine-consumed)
- Text summary to stdout (human-consumed)

Tests use a tiny fixture mapping; verify domains aggregate correctly and compliance_score is between 0 and 100.

---

## What NOT to do

- **Do not** hardcode the brief's mapping in Go source. The brief acknowledges it can't be verified; shipping it as canonical perpetuates the problem.
- **Do not** add an `--nca-ecc-mapping-builtin` flag that uses the brief's mapping. Same reason — it would be the canonical-by-default behaviour.
- **Do not** ship Arabic translations of NCA control names without native-speaker review. The NCA publishes Arabic text directly; use it verbatim if/when available.

---

## Tracking

When this sprint becomes unblocked, add a row to PLAN.md's roster table and update this file with:
- Date unblocked
- Source of authoritative mapping (NCA doc URL or customer name)
- Estimated days
- Reviewer credentials (for the Arabic / NCA familiarity check)

---

## Status

**DEFERRED — unblock requires authoritative mapping source (NCA doc, customer-supplied, or SME reviewer).**
