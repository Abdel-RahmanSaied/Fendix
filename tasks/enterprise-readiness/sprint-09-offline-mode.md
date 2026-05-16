# Sprint 09 — Offline mode + `fendix db`

**Phase:** 4.1 | **Estimate:** 4 days | **Risk:** **High** | **Ships:** v0.13.0
**Audit ref:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §10 + §15.4

---

## Why

Government and defence-adjacent deployments require zero outbound network traffic from scan-time. Fendix today calls `api.osv.dev` from pip / npm / govulncheck. This sprint adds:
- `--offline` flag that disables outbound CVE queries
- `fendix db update` subcommand to maintain a local OSV.dev mirror
- Local-DB query path that matches the existing OSV.dev one

**Decision D3:** ship this only if there's a confirmed customer (see PLAN.md).

---

## Read first

- [`go/internal/scanner/deps/pip/scanner.go`](../../go/internal/scanner/deps/pip/scanner.go) — the `queryOSV` and `queryOSVBatch` (Sprint 02) calls you're alternating with `queryLocalDB`
- [`go/internal/scanner/deps/npm/scanner.go`](../../go/internal/scanner/deps/npm/scanner.go) — same pattern
- [`go/internal/scanner/deps/govulncheck/scanner.go`](../../go/internal/scanner/deps/govulncheck/scanner.go) — govulncheck supports `-db <url>` including `file://` URLs (confirm at sprint start)
- OSV.dev export format: https://osv.dev/blog/posts/introducing-the-osv-database/
- Specifically: `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` (per-ecosystem ZIPs)

---

## New flag + subcommand

### Flag: `--offline`

On `fendix scan` (and `fendix serve` config). When set:
- pip scanner uses `queryLocalDB` instead of `queryOSV*`
- npm scanner uses `queryLocalDB` instead of `queryOSV*`
- govulncheck invoked with `-db file://$HOME/.fendix/db/govuln/`
- If `~/.fendix/db/` doesn't exist, fail-fast:
  ```
  fendix: --offline requires a local CVE database.
  Run: fendix db update --source <osv-snapshot.zip>
  Or:  fendix db update    (downloads ~500 MB from osv.dev)
  ```

### Subcommand: `fendix db`

```
fendix db update                               # downloads from osv.dev
fendix db update --source /path/to/snapshot.zip  # offline-friendly install
fendix db update --ecosystem PyPI              # update only one ecosystem
fendix db status                               # show DB version + size + last-updated
fendix db clean                                # remove the local DB
```

## Local DB layout

```
~/.fendix/db/
  osv/
    PyPI/
      <vuln-id>.json    e.g. GHSA-xxxx-xxxx-xxxx.json
      ...
    npm/
      <vuln-id>.json
    Go/
      <vuln-id>.json
  govuln/
    ID/...              # govulncheck-format vuln files
  manifest.json         # {"updated_at": "...", "source": "osv.dev" | "local-snapshot", "ecosystems": {"PyPI": 12345, "npm": 8912, "Go": 234}}
```

## queryLocalDB shape

```go
// queryLocalDB scans the local OSV mirror for vulns affecting (pkg, version).
// On first call, builds an in-memory index keyed by package name to avoid
// re-walking the directory tree on every package lookup.
//
// Returns the same []osvVuln type as queryOSV — so callers don't change.
//
// Returns ErrLocalDBMissing if ~/.fendix/db/ doesn't exist.
func queryLocalDB(pkg, version string) ([]osvVuln, error) { ... }
```

Index built lazily on first lookup; cached for the process lifetime in a `sync.Once` + `map[string][]string` (package name → list of vuln-file paths).

## Govulncheck offline

Confirm at sprint start: does `govulncheck -db file://...` work? If yes, this is a single arg change. If not (govulncheck might require `vuln.go.dev` specifically), document the gap and emit:

```
INFO: govulncheck skipped in offline mode (Go vuln DB requires online access)
```

`fendix db update` should ALSO mirror the Go vuln DB to `~/.fendix/db/govuln/` from `vuln.go.dev`.

## fendix db update implementation

```go
func runDBUpdate(ctx context.Context, source string, ecosystems []string) error {
    if source != "" {
        // Local snapshot mode — unpack the ZIP into ~/.fendix/db/osv/
        return unpackLocalSnapshot(source, ecosystems)
    }
    // Network mode — download per-ecosystem ZIPs from osv.dev
    for _, eco := range ecosystems {
        url := fmt.Sprintf("https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip", eco)
        if err := downloadAndUnpack(ctx, url, eco); err != nil {
            return fmt.Errorf("update %s: %w", eco, err)
        }
    }
    return writeManifest()
}
```

**Progress reporting:** download is large (~50-100 MB per ecosystem zipped). Show a progress bar via `io.TeeReader` to a custom progress writer that prints `\r downloaded X / Y MB` to stderr.

## Semgrep in offline mode

Pass `--disable-version-check` to semgrep (already supported by semgrep). Document that semgrep's rule registry calls home unless the user supplies a local rule-pack path.

## Tests

Mock local DB fixtures under `go/internal/scanner/deps/pip/testdata/offlinedb/`:

```go
// TestPipScanOffline_UsesLocalDB — set up fixture DB, scan, assert findings come from local source (not network)
// TestPipScanOffline_NoNetworkCalls — use a fake OSV.dev that fails the test if called
// TestPipScanOffline_DBMissingErrors — clear error pointing at `fendix db update`
// TestDBUpdate_LocalSnapshot_Unpacks — feed a tiny ZIP, verify unpacked file count
// TestDBUpdate_NetworkMode — fake osv-vulnerabilities server; verify download + manifest
// TestDBStatus_ReportsCounts
// TestDBClean_RemovesDir
```

## CHANGELOG

```markdown
### Added (v0.13.0)

- **Offline / air-gapped mode** — `--offline` flag on `fendix scan` and
  `fendix serve`. Uses a local OSV mirror at `~/.fendix/db/` instead
  of `api.osv.dev`.
- **`fendix db`** subcommand:
  - `fendix db update` — fetch per-ecosystem ZIPs from osv.dev
  - `fendix db update --source <snapshot.zip>` — install from local
    file (for air-gapped environments)
  - `fendix db update --ecosystem PyPI` — narrow scope
  - `fendix db status` — show DB version, size, age
  - `fendix db clean` — remove local DB
- govulncheck in offline mode uses `-db file://~/.fendix/db/govuln/`.
- semgrep in offline mode runs with `--disable-version-check`.
```

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| OSV.dev's per-ecosystem ZIP layout changes | Med | Pin against the format observed at sprint start. Document the URL in code. If it changes, the `fendix db update` error message points users at a manual snapshot path. |
| Disk cost (500 MB+ unzipped) | Med | Document. `fendix db status` shows size. `--ecosystem` flag narrows scope. |
| Stale-DB problem — user runs `fendix scan --offline` 6 months later | Med | `fendix db status` shows last-updated. Scan emits an INFO finding if DB is >30 days old: `SEC-CVE_DB_STALE`. |
| govulncheck doesn't support `-db file://` in the installed version | Med | Verify at sprint start. If unsupported, fall back to "govulncheck skipped in offline mode" with a clear INFO finding. Don't fail-close. |
| First-load index of large local DB is slow | Med | Lazy-build, sync.Once. Profile; if first lookup is >1s on 50k vulns, switch to a pre-built `index.json` file written by `fendix db update`. |

## Definition of done

Standard DoD plus:
- Manually-verified end-to-end: download DB → unplug network → scan a fixture with known CVEs → findings emitted (record in PR)
- `fendix db status` returns meaningful output
- Air-gapped install path (`--source <zip>`) verified with a manual snapshot from a different machine

## Follow-ups

- **Sprint 09.5:** Differential DB updates (only fetch vulns published since last update). Reduces 500 MB → ~10 MB per update.
- **Sprint 09.6:** Sign the snapshot ZIPs (cosign) so air-gapped admins can verify provenance.

## Status

**Status:** shipped on branch `plan-finish-phases-2-6` as commit
[`e7962cd`](../../../../commit/e7962cd) — `feat(offline): air-gapped CVE snapshot format + fendix db CLI (Sprint 09)`. Source: [`go/internal/offline/`](../../go/internal/offline/).

**D3 caveat:** D3 (Phase 4 customer commitment) is still UNRESOLVED
in DECISIONS.md. The plan-finish session shipped this sprint anyway
per the "finish the plan" intent, but per [DECISIONS.md
D3](DECISIONS.md#L87-L95) "the user can defer merging the Phase-4
commits until D3 is made explicit." The maintenance burden of
keeping the offline snapshot format in lockstep with each per-scanner
ecosystem (pip / npm / govulncheck) is open until a customer
confirms they need it.

**Status section backfill (2026-05-16):** Section was empty at ship
time (DoD #7 not honored). The "shipped despite unresolved D3"
decision is in DECISIONS.md.
