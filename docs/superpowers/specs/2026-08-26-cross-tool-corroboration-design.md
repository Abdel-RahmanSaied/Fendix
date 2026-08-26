# Cross-Tool Corroboration — Reachable and Visible

**Date:** 2026-08-26
**Status:** Approved (brainstorm 2026-08-26)
**Scope:** Engine + backend + frontend, one feature cycle.
**Follows:** [2026-08-25-sarif-import-design.md](2026-08-25-sarif-import-design.md)

## Purpose

SARIF import shipped with a hardened cross-tool corroboration engine that the
hosted product cannot reach and no user can see:

- **Unreachable.** The backend never emits `--import`, and `import_file`
  exists only on the standalone import endpoint. Every SaaS import is
  therefore a scan containing *only* imported findings, so
  `CorrelateCrossTool` has no native findings to correlate against.
  Native↔imported corroboration — the differentiated claim — can only happen
  in the CLI today.
- **Invisible.** Corroboration is an internal flag that nudges a confidence
  score and appends a `confidence_reasons` line. There is no structured field
  and no UI affordance, so "both engines confirm" has nothing behind it.

This cycle makes corroboration reachable (attach SARIF at scan launch) and
visible (public fields, badge, filter, collapse count). It deliberately does
NOT re-open the correlation predicate or the proof-union fold: those are
hardened and stay untouched.

## Non-goals

- Retroactive attach to an already-completed scan. The engine correlates at
  scan time only; a retroactive path needs either a new engine capability or
  a second correlation implementation in Python, which would duplicate the
  predicate. Explicitly deferred.
- Loosening exact-CWE matching (parent/child, fuzzy, inference). The v1 trust
  boundary stands.
- Path-prefix skew resolution (see Known limitations).
- Gzip support and the upload-size cap. Independent and bounded; ships
  separately so it cannot blur this spec.

## Engine

### Merge path

`fendix scan --import <file>` already exists and `CorrelateCrossTool` already
runs inside `finalize` for both entry points. No change is required to reach
it — the gap is entirely on the backend.

### Two additive public fields

`models.Finding` gains:

```go
CrossToolCorroborated bool     `json:"cross_tool_corroborated,omitempty"`
CorroboratingTools    []string `json:"corroborating_tools,omitempty"`
```

Both `omitempty`, so every report without corroboration stays byte-identical
and `schema_version` remains `1` (additive keys only, as with
`metadata.imports`).

### Stamped at the end, never projected through

The Evidence-internal correlation outputs stay internal: `evidence.ToFinding`
continues to drop them. The public fields are stamped in `stampDecisions`,
alongside the four decision fields it already writes:

```go
findings[i].CrossToolCorroborated = d.Evidence.CrossToolCorroborated
findings[i].CorroboratingTools    = d.Evidence.CorroboratingTools
```

This is load-bearing, not stylistic. `d.Evidence` is the evidence returned by
`ProvenanceIndex.Restore`, so it carries the **proof-union** value. Projecting
the fields through the render block instead would publish whichever duplicate
won `findingLess` during dedup — silently reintroducing the erasure the
2026-08-25 hardening pass fixed (a corroborated finding losing its proof
because an uncorroborated duplicate became the group primary).

### Collapsed-import accounting

`CorrelateCrossTool` returns a per-tool count of imported findings it
collapsed into native representatives, and `finalize` folds it into each
`metadata.imports` block as `corroborated: N`.

Required because `ImportStats` is computed in `Normalize`, which runs *before*
correlation: `metadata.imports[].results` counts what was imported, not what
merged. Without this count the UI cannot explain why 50 uploaded findings
produced 47 rows.

### SARIF reporter

Fendix's own SARIF output carries `corroborating_tools` as a result property,
so corroboration provenance survives re-export into GitHub rather than being
lost at the boundary.

## Backend

### One config key

The shipped endpoint stores `config["import_file"]` (singular); merge needs a
list. Both unify on:

```text
config["import_files"]: [rel, …]
```

`mode=import` carries exactly one entry. This yields one cleanup path, one
janitor-protection rule and one `build_command` loop instead of two of each.

The rename needs no data migration: SARIF import is committed but **not
deployed**, so no production row carries `import_file`. Doing it now is far
cheaper than living with a permanent singular/plural split.

### Scan attachments

`LaunchScanSerializer` gains `import_files`, a `ListField(child=FileField())`
populated from repeated multipart keys. Each entry runs the same
`check_sarif_upload_size` → `parse_and_validate_sarif` → `write_import_upload`
chain the standalone endpoint uses, so verification and jail semantics are
identical by construction.

- **Bounded at 5 attachments**, each within the existing per-file cap — enough
  for a realistic CI fan-in (CodeQL + Semgrep + Trivy + two more) while
  bounding the synchronous parse cost on the web worker.
- **Feature-gated** on `require_feature(owner, "sarif_import")` only when
  attachments are present; ordinary scans are unaffected.
- **Mutually exclusive with `mode=import`.** Attachments belong to a scan; the
  dedicated endpoint owns the standalone case. Two ways to express one thing
  is a bug generator.

`build_command` appends `--import <abs>` per entry for the scanning modes and
uses the same list for the `fendix import` positional args in import mode.
`execute_scan` cleanup and the janitor's `protected` set iterate the list.

**Non-corroborating imports are still findings.** Attaching SARIF to a scan
imports *every* result in it, exactly as the standalone endpoint does; the
scan's finding set is native findings plus imported ones. Corroboration only
changes what happens to the subset that strongly matches a native finding
(collapse into it, stamped). An attachment whose findings match nothing simply
contributes them as imported findings within that scan — attaching is never a
filter.

Quota and concurrency are unchanged: a scan with attachments is one scan.

### Persistence and filtering

`ScanFinding` gains two additive columns:

| Column | Type | Notes |
| --- | --- | --- |
| `cross_tool_corroborated` | boolean, indexed, default false | coerced in `_finding_defaults` exactly like `proven_path` |
| `corroborating_tools` | JSON list, default `[]` | tool identities, sorted |

Exposed by `FindingSerializer`; `ScanFindingFilter` gains a `corroborated`
boolean filter. The indexed boolean is the reason the design carries a
boolean *and* a list: it makes "only cross-confirmed findings" a cheap
indexed query rather than a JSON-array scan, and that filter is the feature's
point on the findings page.

## Frontend

Three surfaces, each following an existing pattern:

- **`CorroborationBadge`**, beside `ProvenPathBadge`, rendered in the same
  three places (scan detail, findings list, finding detail). Deliberately
  lower visual weight than proven-path: a proven path is Fendix demonstrating
  an exploitable route itself; corroboration is two tools agreeing — strong
  evidence, weaker claim. The badge names the tools ("Confirmed by CodeQL"),
  because the tool name is the substance.
- **Scan detail** shows the collapse story near the By Source block —
  *"3 imported findings confirmed existing Fendix findings"* — turning missing
  rows from a mystery into the headline.
- **Findings page** gains a cross-confirmed filter (what the indexed column
  bought).
- **New-scan form** gains an attach-SARIF section for the three scanning
  modes, collapsed under Advanced Options. Kept unobtrusive because CI is the
  primary consumer; having a SARIF on hand at web-launch time is the rarer
  workflow.

## Error handling

**A bad attachment must never kill a good scan.** The engine fails the whole
run on malformed SARIF (exit 2) — correct for a standalone import, harsh when
it means a Fendix scan died because CodeQL emitted something odd. Attachments
are parsed synchronously before launch, so a bad one returns 400 before the
scan starts and before quota is spent.

**Revision to the 2026-08-25 decision:** `parse_and_validate_sarif` gains a
`version == "2.1.0"` check. That spec deliberately deferred version validation
to the engine to avoid two contracts drifting. For merge mode the trade flips:
a `2.0.0` file passes the gate, launches a scan, and kills it at the engine,
losing the native results too. A single version constant is not meaningfully a
second contract, and the loss it prevents is a whole scan's work. The engine
remains authoritative for everything else.

Remaining cases reuse existing paths: too many or oversized attachments → 400;
Free-plan attach → 403 `FEATURE_RESTRICTED`, which the UI already routes to the
upgrade prompt; dispatch failure refunds quota and deletes every attachment;
the janitor protects live entries and sweeps orphans.

## Known limitations

**Path-prefix skew.** If CodeQL scanned `backend/` while Fendix scanned the
repo root, the import reports `app/views.py` and the native finding
`backend/app/views.py`. Nothing matches, corroboration silently never fires,
and the UI honestly reports zero confirmed. Deferred by decision; revisit with
an `--import-path-prefix` knob only if it bites in practice.

**Exact-CWE conservatism** means corroboration fires less often than it might.
Many Semgrep community rules carry no CWE tag. This is the intended trust
boundary (false non-correlation over false confirmation), but it means the
feature's real-world hit rate should be measured, not assumed.

## Testing

### Engine tests

- Merge fixture pair (native finding + CodeQL SARIF at the same CWE and
  location): corroboration fires, collapsed count reaches
  `metadata.imports[].corroborated`, SARIF re-export carries the tools.
- **The load-bearing regression:** a corroborated finding plus an
  uncorroborated dedup-equivalent duplicate must still publish
  `cross_tool_corroborated: true`. Putting the field on a public surface is
  exactly where the union-fold erasure could silently return.
- Omitempty snapshot: reports without corroboration stay byte-identical.

### Backend tests

- Multi-attachment launch: config list, all files in the jail.
- `build_command` emits one `--import` per attachment, absolute paths.
- 400s: malformed, oversized, too many, wrong SARIF version.
- Mutual exclusivity with `mode=import`.
- Cleanup deletes every attachment on all exit paths; janitor protects live
  entries and sweeps orphans.
- New columns persisted from the report and filterable.
- **Heavy real-engine E2E:** native + attached import → a corroborated finding
  visible through the detail API. Mocks structurally cannot catch this class.

### Frontend tests

- Badge present/absent; filter; attach-section validation; collapse-count copy.
