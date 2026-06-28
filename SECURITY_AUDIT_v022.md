# Security Audit — Fendix v0.22 (Evidence Architecture)
Audited by: Security Agent
Date: 2026-06-28
Scope: the internal Engine→Evidence→Finding→Decision refactor. v0.22 changes
*internal data flow only*; the public JSON/SARIF/HTML output is byte-identical
(proven by the output-snapshot + schema + reporter suites).

## Changes audited
| Area | Files |
|------|-------|
| Evidence model + adapter | `internal/evidence/` |
| Decision layer | `internal/decision/` |
| Correlation V2 | `internal/engine/correlator_v2.go` |
| Scanner re-plumb | `internal/scanner/**`, `internal/scanner/deps/**`, `internal/scanner/secrets/`, `internal/scanner/semgrep/`, `internal/scanner/textscan/` |
| Orchestrator accumulator + worker pool + dep helpers + Python/plugin ingestion | `internal/engine/{orchestrator,workerpool,scannerstatus}.go` |

## Findings

### CRITICAL — none.
### HIGH — none introduced.
### MEDIUM — none.

### LOW
- **L-1 (forward-looking) — Evidence.Payload / Evidence.Response.** The new
  Evidence type can carry a raw request payload and response excerpt
  (DAST provenance). Today **no scanner populates them** and they are
  **internal-only**: Evidence has no JSON tags and is projected to
  models.Finding via ToFinding, which drops them (verified by
  `TestProvenanceIsInternal`). So there is **no new data in any report**. IF a
  future feature serializes Evidence directly (e.g. a debug bundle or the
  v0.24 decision report), Payload/Response must be redacted with the same care
  as the configleak "body not captured" principle. Captured now so it isn't
  forgotten.

## Data-exposure analysis
- **Public output unchanged.** Reporters still marshal `[]models.Finding`; the
  Evidence provenance never reaches the JSON/SARIF/HTML (round-trip + byte-
  identical-JSON tests lock this). No new fields, no new data in reports.
- **No new egress / exec / temp files / secrets.** The migration was type
  swaps (`models.Finding` → `evidence.Evidence`) + field-copy adapters
  (`FromFinding`/`ToFinding`) + the orchestrator accumulator flip. No outbound
  call, subprocess, file path, or credential handling was added or changed.
- **IPC contracts intact.** The Python NDJSON bridge and plugin protocol still
  unmarshal to `models.Finding` (the wire format); they adapt to Evidence at
  the Go ingestion boundary. No change to what crosses the process boundary.

## Other checks
- [x] No `fmt.Sprintf` into SQL; no new SQL.
- [x] No new goroutines (worker-pool concurrency unchanged; only its element
      type changed from Finding to Evidence).
- [x] Error handling preserved (no swallowed errors introduced).
- [x] `import ev "…/evidence"` alias in the scanner package is cosmetic
      (avoids shadowing local `evidence` finding-text vars) — no behavior change.
- [x] gofmt / vet clean across the module; full test suite green.

## Sign-off
- [x] No CRITICAL findings unresolved
- [x] No new HIGH findings introduced by v0.22
- [x] Public output byte-identical (no new exposure surface)
- [x] All v0.22 changes are internal data-flow refactors
