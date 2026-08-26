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

`CorrelateCrossTool` returns a **per-tool** count of imported findings it
collapsed into native representatives, keyed by normalized `ToolID`:

```go
map[string]int{"codeql": 2, "semgrep": 1}
```

Because import stats are consolidated to exactly one block per tool (below),
`finalize` can fold each count unambiguously into the matching
`metadata.imports` block as `corroborated: N`. A single scalar would not do:
when two tools each collapse findings, there is no way to attribute the total
to either block.

Required because `ImportStats` is computed in `Normalize`, which runs *before*
correlation: `metadata.imports[].results` counts what was imported, not what
merged. Without this count the UI cannot explain why 50 uploaded findings
produced 47 rows.

**Stats consolidate by normalized tool identity.** `Normalize` currently emits
one `ToolStat` per SARIF *run*, so two CodeQL runs — whether two attached
files or one file with two runs — produce two blocks both named `codeql`. A
count keyed by tool then has no unambiguous block to land in: it would either
be duplicated across blocks or assigned arbitrarily.

The fix is to consolidate `ImportStats` by normalized tool identity (folding
across runs *and* across attached files) before correlation, so there is
exactly one block per tool. This deliberately uses the **same key independence
uses** — `ToolID`, not run and not version — so the accounting can never
disagree with the trust model about what counts as one tool. `version` is
retained when every run of that tool reports the same version and left empty
when they differ; mixed-version uploads of one tool are pathological, and the
tool name is what carries provenance.

Locked by a test with two CodeQL runs (one consolidated block, correct
`corroborated` count).

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

**Validation and writing are two phases, not interleaved.** Validating and
writing per file in one loop means attachments 1–2 are already on disk when
attachment 3 fails validation, leaving orphans with no Scan row to hang
cleanup off — they survive until the hourly janitor sweep. So:

1. **Phase one — validate everything, write nothing.** Read and structurally
   validate every attachment, and validate every other field (artifact paths
   included), holding the verified bytes in memory. The 5-attachment cap and
   the per-file size cap bound that memory.
2. **Phase two — write.** Only once nothing can still reject the request, write
   all attachments to the jail.
3. **Unwind on any later failure.** Every path accumulated so far is deleted if
   a write fails midway, or if any subsequent step fails — quota, concurrency,
   `serializer.save()`, or dispatch. The view wraps the whole create in a
   try/except that unlinks the attachment list, rather than only handling the
   dispatch case as it does today.

This also fixes an **existing shipped defect** on the single-file path:
`ImportScanSerializer.validate` writes the SARIF before validating the
`baseline` / `ignore` / `save_baseline` artifact paths below it, so a bad
artifact path already orphans an upload today. Reordering it to validate-then-
write closes that, and the two paths then share one ordering rule.

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
| `cross_tool_corroborated` | boolean, default false | coerced in `_finding_defaults` exactly like `proven_path` |
| `corroborating_tools` | JSON list, default `[]` | tool identities, sorted |

Exposed by `FindingSerializer`; `ScanFindingFilter` gains a `corroborated`
boolean filter. Carrying a boolean *and* a list is deliberate: it makes "only
cross-confirmed findings" a cheap indexed query rather than a JSON-array scan,
and that filter is the feature's point on the findings page.

**Composite index, not a bare boolean one.** A standalone index on a boolean
is largely useless in Postgres — two distinct values over a large table has
too little selectivity for the planner to prefer it. Findings are always
queried within a scan or tenant scope, so the index must match the real query:

```python
models.Index(fields=["scan", "cross_tool_corroborated"], name="finding_scan_corrob_idx")
```

This matches the existing `finding_scan_severity_idx` on the same model, so it
is the house pattern rather than a new one. (A partial index on `scan`
`WHERE cross_tool_corroborated` would be smaller still; take it only if
corroborated findings prove to be a small fraction at real volume — the
composite is the safer default because it also serves the negative filter.)

### Persisting the import accounting

`metadata.imports` is currently **discarded** at ingest: `_finalize` copies
only selected metadata keys onto `Scan` (`version`, `endpoints_scanned`,
`checks_run`, `decisions`, `scanner_status`, the endpoint-discovery counts),
and `reports.py` rebuilds a regenerated report's metadata from `Scan` columns —
so nothing can restore it. The scan-detail collapse story therefore has no
data path today, and this is a gap in the *shipped* feature too: which tool an
import came from, and its version, are lost the moment the scan finishes.

`Scan` gains an `imports` JSON column, mirroring how `decisions` and
`scanner_status` already persist engine metadata blocks:

- Coerced defensively at ingest, like `_coerce_scanner_status` — bounded list,
  type-checked fields, unknown keys dropped.
- Persisted in **both** ingestion paths: `scanning.services._finalize` and the
  runner-ingest twin in `runners/ingest.py`, which is the pair that already
  has to agree on `decisions` and `scanner_status`.
- Exposed by the scan serializer and included in regenerated reports so a
  re-rendered SARIF/HTML carries the same provenance as the original.

The scan-detail collapse count reads `sum(block["corroborated"])` from it.

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
  rows from a mystery into the headline. Reads the persisted `Scan.imports`
  blocks (see *Persisting the import accounting*), which this cycle has to add
  before the copy has any data behind it.
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
- **Two CodeQL runs** (two attached files, and one file with two runs):
  `metadata.imports` consolidates to a single `codeql` block and the
  `corroborated` count is correct — the ambiguity that a per-run block set
  would create.
- **Two different tools each collapsing** (CodeQL 2, Semgrep 1): each count
  lands in its own block. This is the case a scalar return value gets wrong,
  so it is the test that pins the map-keyed contract.
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
- **Atomicity**, one test per unwind path: a malformed attachment N leaves
  *zero* files on disk; a write that fails midway removes the ones already
  written; a failure after writing (quota, concurrency, save, dispatch) removes
  all of them. Plus the single-file regression: a bad `baseline` path must not
  orphan the SARIF.
- Cleanup deletes every attachment on all exit paths; janitor protects live
  entries and sweeps orphans.
- New columns persisted from the report and filterable; `Scan.imports`
  persisted at ingest, exposed by the serializer, and present in a
  regenerated report.
- **Heavy real-engine E2E:** native + attached import → a corroborated finding
  visible through the detail API. Mocks structurally cannot catch this class.

### Frontend tests

- Badge present/absent; filter; attach-section validation; collapse-count copy.
