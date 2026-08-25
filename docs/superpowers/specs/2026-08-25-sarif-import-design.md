# SARIF Import — Design

**Date:** 2026-08-25
**Status:** Approved (brainstorm 2026-08-25)
**Scope:** Engine-first; backend follows in the same feature cycle.

## Purpose

Let fendix ingest SARIF 2.1.0 reports produced by other scanners (CodeQL,
semgrep, trivy, …) and run them through the full fendix flow — fingerprinting,
confidence scoring, dedup, baseline/ignore filtering, confidence-gated
`--fail-on`, reporters — so fendix can act as the single security gate and the
SaaS dashboard can hold findings from scans fendix did not run.

Two consumption modes, both required:

1. **Standalone:** `fendix import <file.sarif>` — foreign findings alone
   produce a fendix report and exit code.
2. **Merge:** `fendix scan --import <file.sarif>` — foreign findings join a
   native scan before dedup/correlation.

SaaS: `POST /api/scans/import` uploads a SARIF, creating a `Scan` with
`mode="import"` that consumes monthly scan quota and is plan-feature-gated.

## Architecture

New engine package `go/internal/sarifimport` with one public entry point:

```go
func Normalize(doc *Document) ([]evidence.Evidence, ImportStats, error)
```

It returns `evidence.Evidence` (the internal superset of `models.Finding`)
rather than bare findings, because the correlation metadata below — weakness
ids, tool identity — lives in Evidence's internal block and must reach the
correlator without a detour through report-facing fields.

`Document` is sarifimport's **own minimal SARIF 2.1.0 struct** — only the
fields the normalization table below reads (runs, tool driver, rules,
results, locations, suppressions, fingerprints). No third-party SARIF
dependency; the existing `reporters/sarif.go` writer types stay untouched
(they model output, not arbitrary foreign input).

Both the `fendix import` command and the `--import` scan flag call it; every
downstream stage (fingerprint stamping, confidence scoring/banding, dedup,
`.fendix-ignore` + `--baseline`, decision pass, reporters) is reused untouched.
This mirrors the existing seam in `reporters/parse.go` where findings already
enter from a file instead of a live scan.

Rejected alternatives: routing import through the plugin system (extensible but
heavy for a single format — SARIF *is* the interop format; lift `Normalize`
into a plugin contract if a second format ever arrives) and extending
`reporters/parse.go` in place (wrong home — reporters own output, not
foreign-tool normalization).

## Normalization rules

`Normalize` walks every `run` in the document (SARIF allows several tools per
file) and maps each `result` to a `models.Finding`:

| Finding field | Mapped from |
| --- | --- |
| `Title` | rule `shortDescription`, falling back to first line of the result `message` |
| `Category` | `import/<toolName>` (lowercased driver name, e.g. `import/codeql`) |
| `Endpoint` | primary location URI (file path for SAST, URL for DAST) |
| `Line` | primary location `startLine` |
| `Severity` | GitHub `security-severity` score when present: ≥9 CRITICAL, ≥7 HIGH, ≥4 MEDIUM, else LOW. Otherwise `level`: error→HIGH, warning→MEDIUM, note→INFO |
| `Confidence` | rule `precision`: `very-high`/`high`→HIGH, `medium`→MEDIUM, `low`→LOW. Fallback from `level`: error→HIGH, warning→MEDIUM, note→LOW |
| `Evidence` | result message + region snippet when present, capped at 2,000 characters |
| `Fix` | rule `help` / `fullDescription` text when present |
| `References` | rule `helpUri`, CWE/tag taxa, and provenance strings `tool:<name>@<version>`, `rule:<ruleId>`, plus original `partialFingerprints` — nothing from the source document is lost |
| `Source` | new constant `SourceImported = "imported"` in `models` |
| `SourceTier` | left **empty**, deliberately: the correlator scores unknown tiers most conservatively, so imports can never bypass the F1 escalation gate or masquerade as tree-sitter-proven |

Fingerprinting stays fendix-native — `sha1(Category|Endpoint|Title)` stamped
by the orchestrator exactly as for native findings — so `.fendix-ignore` and
`--baseline` work on imported findings with zero new code. The source tool's
`partialFingerprints` are provenance only.

**Finding identity ≠ cross-tool correlation identity.** The fingerprint
answers "is this the same logical fendix finding across scans?" — it is NOT
the mechanism that decides whether two independent engines confirmed the same
vulnerability. Correlation uses its own normalized metadata (see the
Cross-tool correlation section below); title, category, and fingerprint
equality never count as cross-engine confirmation.

The `Category` mapping is refined: when the imported rule carries a CWE that
maps cleanly onto a category fendix already understands, the **native fendix
category** is used (`CWE-89/78/77/95 → injection`, `CWE-79 → xss`,
`CWE-918 → ssrf`, `CWE-798/259 → secrets`, `CWE-287/306/862/863 → auth`);
`import/<tool>` is the fallback when no trustworthy mapping exists. The
mapping is a small explicit table, not an attempt to cover the CWE catalog.
Tool provenance is always recorded independently (`tool:<name>@<version>`,
`rule:<ruleId>`).

Suppressed results (accepted `suppressions`) are skipped and counted in
`ImportStats`. Results with no location get `Endpoint: "unknown"` rather than
being dropped, so counts always reconcile.

## CLI surface

### `fendix import <file.sarif>...`

Accepts one or more SARIF files, or `-` for stdin (the backend's invocation).
Flow: parse → `Normalize` → the scanner's finalization chain → reporters.

Flags mirror `scan` where semantics are identical:

- `--fail-on <severity>` — confidence-gated as in v2.0; exit 1 on BLOCK,
  0 otherwise; `--enforce-confidence=false` honored.
- `--format json|html|pdf|sarif` + `--output` — full reporter set. JSON emits
  the same single-document `{metadata, summary, sources, total, findings[]}`
  shape the backend already parses.
- `--baseline`, `--ignore-file` — unchanged.
- `--target <url-or-path>` — optional label stamped into report metadata
  (an import has no scanned target of its own).

Report `metadata` gains an additive `imports` block: per-tool name/version,
result counts, suppressed/skipped counts (`ImportStats`). `schema_version`
stays `1` — additive keys only.

### `fendix scan --import <file.sarif>` (repeatable)

Runs the native scan, calls the same `Normalize`, appends imported findings
**before** the cross-tool correlation pass (which itself runs before dedup).
That ordering is the point of merge mode: a fendix native finding at the same
normalized weakness + location is the strong corroboration that lifts a
MEDIUM-band imported finding into blocking — and vice versa. When a native and
an imported finding strongly match, the native finding remains the
representative and the imported finding's provenance survives as corroboration
(see Cross-tool correlation).

## Cross-tool correlation (identity ≠ correlation)

Imported findings must never strengthen a fendix decision through fingerprint,
title, or category coincidence. A dedicated correlation pass —
`engine.CorrelateCrossTool`, separate from both fingerprinting and the
existing blackbox↔whitebox correlator — reasons over normalized weakness,
normalized location, line proximity, and tool provenance.

**Internal metadata (never serialized).** `evidence.Evidence` gains
internal-only fields: `Weakness []string` (normalized `CWE-NNN` ids —
extracted from SARIF rule taxa/tags for imports, and from exact `CWE-NNN`
reference tokens for native findings, both at the normalization boundary so
the correlator receives structured metadata and never parses free-form
strings), `ToolID` (normalized tool identity), and the correlation outputs
`CrossToolCorroborated` + `CorroboratingTools`.

**Corroboration survives dedup by proof union.** Correlation establishes
trust; dedup only decides which occurrence represents the issue, and may
only preserve or conservatively discard already-established trust — never
create it. The correlation outputs are therefore carried through dedup by
`ScoringProvenance` under a **proof-union** fold, a deliberate exception to
the "agree or drop" rule the other producer-set flags use: when duplicate
occurrences of one logical vulnerability merge, their `CorroboratingTools`
records union (sorted, deduped) and the merged flag is derived from that
union. An uncorroborated duplicate occurrence cannot erase a validly
established independent-engine confirmation — and occurrences that were
never stamped contribute an empty record, so grouping can never manufacture
one. A bare flag without its tool-identity proof does not survive the merge.
Only `CorrelateCrossTool` may ever write a tool into `CorroboratingTools`. `models.Finding` is untouched.

**Match levels.**

- *Strong corroboration* — ALL of: different effective tool (see
  independence), same normalized CWE, same normalized file/endpoint, and same
  or very-near location: `abs(lineA−lineB) <= 5` when both carry valid lines,
  with overlapping regions preferred over raw proximity when both sides have
  ranges. Only strong corroboration counts as cross-engine confirmation.
- *Medium similarity* (same weakness + same file but outside the threshold,
  etc.) — informational only, never blocking, never satisfies the F1 /
  corroboration gate. Classified for tests; no product surface in v1.
- *Weak similarity* (same category / similar titles / same file only) — never
  affects anything.

**Exact-CWE equality is a deliberate trust boundary, not a bug.** Strong
corroboration in v1 requires an exact intersection of normalized `CWE-N`
identifiers. CWE parent/child relationships, taxonomy graph traversal, fuzzy
weakness matching, title/category/message-based weakness inference, and any
model-based classification are intentionally NOT resolved — `CWE-89` and its
taxonomic child `CWE-564` do not corroborate each other. This produces false
negatives by design: false non-correlation is preferable to taxonomy
inference weakening the "both engines confirm" guarantee.

**Independence.** Tool identity is normalized: imported findings carry the
lowercased driver name; native findings are `fendix` — except semgrep-shim
findings, which are `semgrep`, so fendix's own semgrep pass and an imported
semgrep SARIF are correctly NOT independent. The same external tool across
multiple runs/files gains nothing by duplication. SARIF filename is never
identity.

**Effect of strong corroboration.** The decision layer's `corroborations()`
gains one arm — independent cross-tool corroboration — and the confidence
scorer a matching bonus. That is the ONLY channel by which imported evidence
influences another finding: severity never escalates, `Reachable`/`Route`/
`TaintChain`/`SourceTier` are never set on imports (empty tier keeps the F1
escalation gate's most-conservative treatment), imports are fenced OUT of the
blackbox↔whitebox correlator (no `SourceCorrelated`, no `mergeFindings`), and
imported findings dedup in their own key-space so a title collision can never
transfer a confidence enum onto a native finding. Uncertain → no escalation:
missing CWE or missing location simply excludes a finding from strong
corroboration.

**Representative selection.** When a native finding and an imported finding
strongly match, the imported row is collapsed into the native representative
(references and tool provenance folded in, corroboration stamped) — the
report shows one finding confirmed by two engines, not duplicate rows, and
the corroborating evidence survives dedup via the provenance index.

**Standalone imports** still gate on their own mapped severity/precision
(`security-severity`, `level`, `precision`) — an imported HIGH-precision
finding can block by itself under `--fail-on`; corroboration is only about
lifting MEDIUM-band findings and never about masquerading as native
verification.

## Backend API & pipeline

### Endpoint

`POST /api/scans/import` — multipart upload (`file` = the SARIF, optional
`target` label). Implemented as an `@action` on the existing `ScanViewSet`,
inheriting auth (JWT + `X-API-Key`), the `scan_create` 10/hour throttle scope,
and the `{detail, code}` error shape.

### Request path

1. `ImportScanSerializer`: file size cap 10 MB; must parse as JSON with a
   `runs` array (cheap structural check — deep validation belongs to the
   engine). No SSRF validators (nothing is fetched); no `config["auth"]`.
2. `require_feature(user, "sarif_import")` — new `PlanFeature` (Pro+, same
   tier as API keys), added to the seeded plan matrix used by test fixtures.
3. `check_scan_quota(user)` — consumes one scan from the monthly quota.
4. Persist `Scan(mode="import", status=QUEUED)` (new mode choice); write the
   uploaded SARIF to the shared media volume (already shared by `django` and
   `celery-scans`); dispatch `execute_import_scan.delay(scan.id)`.

### Celery task

Thin variant of `execute_scan`. `FendixEngine` gains
`run_import(sarif_path, ...)` shelling out to
`fendix import <file> --format json`. Because the import command emits the
identical report shape, everything downstream is existing code: bulk-create
`ScanFinding` rows, stamp terminal status + counters, `post_save` signal fires
the completion email / critical-finding alert untouched. The uploaded SARIF is
deleted after the task finishes (success or failure) — the normalized findings
are persisted, not the foreign document.

### Downloads & contract

`/api/scans/{id}/report?format=html|sarif` already pipes persisted findings
through `fendix report` — imported scans get re-export for free.

Contract sync (mandatory loop): new endpoint + new mode enum value + new
finding `source: "imported"` → `make schema`, commit `openapi.json`, frontend
`npm run codegen`, `make schema-check`.

## Error handling & edge cases

### Engine

- Malformed JSON, not-SARIF, or `version != "2.1.0"`: exit 2 naming the file
  and the problem. Versions below 2.1.0 are rejected explicitly, not
  best-effort parsed — a wrong guess silently corrupts severity mapping.
- Empty `runs` or zero results: valid — clean report with `total: 0` (a
  passing gate on a clean scan is the normal case).
- Large files: results streamed per-run; evidence/message fields length-capped
  at normalization time.
- Absolute paths / `file://` URIs normalized to repo-relative where
  `originalUriBaseIds` allows; otherwise kept verbatim — never dropped, since
  `Endpoint` feeds the fingerprint.
- A malformed file fails the whole command (exit 2) — importing half a file
  would misrepresent coverage. A valid file from an unrecognized tool imports
  fine; tool name is metadata.

### Backend

- Engine exit 2 → `Scan.status=FAILED` with the engine's stderr line as the
  error message — same failure surface as a crashed scan; no new frontend
  state.
- A fendix-produced SARIF uploaded back in is allowed (tool name
  `import/fendix`) — harmless, and blocking it costs more than it's worth.
- Quota is consumed at launch and not refunded on later task failure — same
  policy as native scans.

## Testing

### Engine tests (`go/internal/sarifimport`)

- Table-driven tests over small fixture SARIFs, one per normalization rule:
  severity from `security-severity` vs `level`, confidence from `precision`,
  suppressions skipped, multi-run files, missing locations.
- Golden-file test: fixture SARIF → `fendix import --format json` →
  byte-stable report.
- Real-world fixtures from CodeQL, semgrep, and trivy checked into
  `testdata/` to catch drift against actual tools.
- Merge-mode test: native + imported finding at the same location → dedup
  picks the native one; corroboration lifts an imported MEDIUM to blocking.

### Backend tests (pytest)

- Serializer rejects oversize / non-JSON uploads.
- Feature gate: 403 for Free plan; quota consumption and 429 at the limit.
- Happy path with `FendixEngine.run_import` mocked: `ScanFinding` rows created,
  notification fired.
- SARIF file removed from the media volume after task completion.
- `make schema-check` green.
