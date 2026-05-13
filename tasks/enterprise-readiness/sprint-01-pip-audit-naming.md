# Sprint 01 — pip-audit naming accuracy + fallback flag

**Phase:** 1.1 (Honesty & Trust Fixes)
**Estimate:** 1 day
**Risk:** Low
**Ships in:** v0.11.1
**Audit reference:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §15.5 — "single most important fix before external evaluation"

---

## Why this sprint exists

The audit (§15.5, §13) calls out a credibility gap: code comments and prior commits reference "pip-audit parity," but the actual implementation in [`go/internal/scanner/deps/pip/scanner.go`](../../go/internal/scanner/deps/pip/scanner.go) is a direct OSV.dev `/v1/query` REST client. It never invokes the `pip-audit` binary.

An external security evaluator who reads the code and sees the mismatch loses trust in the entire report. This sprint either:
1. Makes the naming honest ("OSV.dev client, not pip-audit"), AND
2. Adds an opt-in fallback to actually shell out to `pip-audit` when the user wants it.

Both, in one PR. Cheap and unblocks external evaluation.

---

## Read first (do not skip)

Before writing a single line:

- [`go/internal/scanner/deps/pip/scanner.go`](../../go/internal/scanner/deps/pip/scanner.go) — full file. Note the package-doc comment (lines 1–26) that mentions "pip-audit parity." Understand `Scan`, `ScanRecursive`, `parseRequirements`, `queryOSV`, `buildFinding`.
- [`go/internal/scanner/deps/pip/scanner_test.go`](../../go/internal/scanner/deps/pip/scanner_test.go) — see the existing `httptest.NewServer` pattern for `TestScan_HappyPath_AgainstFakeOSV`. Your subprocess test will follow the same shape (fake binary on PATH instead of fake HTTP).
- [`go/internal/engine/orchestrator.go`](../../go/internal/engine/orchestrator.go) lines 217–237 (the `pip.ScanRecursive` call site). Note the log message wording.
- [`go/cmd/fendix/main.go`](../../go/cmd/fendix/main.go) — find the scan subcommand flag registration (search for `scanCmd.Flags()`). Note the existing flag style.
- [`go/internal/models/scan_config.go`](../../go/internal/models/scan_config.go) — find `ScanConfig`. Your new flag value needs to land here.
- pip-audit JSON output schema: run `pip-audit --format json` against any project locally to confirm the shape, OR see [pip-audit docs](https://github.com/pypa/pip-audit/blob/main/docs/cli.md#--format).

---

## Concrete deliverables

### 1. Update package doc comment in `pip/scanner.go`

Replace the top-of-file doc (lines 1–26) with:

```go
// Package pip queries the OSV.dev /v1/query API to find vulnerabilities in
// Python dependencies declared in requirements.txt manifests. It provides
// behavioural parity with pip-audit (same advisory sources, same finding
// shape) but does NOT shell out to pip-audit by default.
//
// Users who require an actual pip-audit invocation (for reproducibility
// in environments that audit subprocess calls, or to pick up pip-audit-
// specific patches ahead of OSV.dev's index) can pass --use-pip-audit
// to fendix scan. When set, the scanner runs `pip-audit --format json -r
// <manifest>` for every manifest discovered by findRequirementsManifests
// and converts the output to []models.Finding using the same shape as
// the native OSV.dev path. If pip-audit is not on PATH, a warning is
// logged to stderr and the OSV.dev path is used as fallback — never
// fails-closed silently.
//
// Limitations (unchanged from existing implementation):
//   - Only pinned `==` versions are checked. Range specifiers
//     (`>=`, `~=`, `>`) are skipped with a stderr warning.
//   - No transitive resolution. Direct deps only.
//
// Cache (OSV.dev path only):
//   ~/.fendix/cache/osv-pypi/<package>@<version>.json with a 24h TTL.
package pip
```

### 2. Update orchestrator log message

In [`orchestrator.go`](../../go/internal/engine/orchestrator.go) around line 220 (search for `"native pypi deps scan complete"`), the message stays as-is. Add a *second* log line at the start of the pip block:

```go
mode := "OSV.dev"
if o.cfg.UsePipAudit {
    mode = "pip-audit subprocess"
}
slog.Debug("native pypi dep-CVE scan starting", "mode", mode)
```

This makes the log honest about which path ran without changing the existing info-level "complete" line.

### 3. Add the flag

In [`go/cmd/fendix/main.go`](../../go/cmd/fendix/main.go), in the `scan` subcommand flag block:

```go
scanCmd.Flags().Bool("use-pip-audit", false, "Shell out to the pip-audit binary for Python dep-CVE scanning instead of the native OSV.dev client. Falls back to OSV.dev with a warning if pip-audit is not on PATH.")
```

Wire to `ScanConfig.UsePipAudit` (new field).

In [`go/internal/models/scan_config.go`](../../go/internal/models/scan_config.go) `ScanConfig` struct:

```go
// UsePipAudit, when true, shells out to the pip-audit binary instead of
// using the native OSV.dev /v1/query client. Falls back to OSV.dev if
// pip-audit is not on PATH. Surfaced by Sprint 01 (Track 4 trust fixes).
UsePipAudit bool
```

### 4. Add `pip.Options` struct + plumb through

In `pip/scanner.go`, add:

```go
// Options controls runtime behaviour of ScanRecursive. The zero value
// uses the native OSV.dev client (current default).
type Options struct {
    // UsePipAudit, when true, shells out to `pip-audit --format json`
    // for every discovered manifest instead of querying OSV.dev directly.
    // If pip-audit is not on PATH, a warning is emitted and the OSV.dev
    // path is used as fallback (never fails-closed silently).
    UsePipAudit bool
}

// ScanRecursiveWithOptions is the explicit-options variant of ScanRecursive.
// ScanRecursive itself is preserved as a wrapper for backward compat.
func ScanRecursiveWithOptions(ctx context.Context, codePath string, maxDepth int, opts Options) ([]models.Finding, error) {
    if opts.UsePipAudit {
        if path, err := exec.LookPath("pip-audit"); err == nil {
            return scanViaSubprocess(ctx, codePath, maxDepth, path)
        }
        fmt.Fprintln(os.Stderr, "[fendix] pip: --use-pip-audit set but pip-audit not found on PATH; falling back to OSV.dev client")
        // intentional fallthrough to OSV.dev path
    }
    return scanViaOSV(ctx, codePath, maxDepth)
}

// ScanRecursive preserves the existing signature for backward compat.
// Callers that want the new flag use ScanRecursiveWithOptions.
func ScanRecursive(ctx context.Context, codePath string, maxDepth int) ([]models.Finding, error) {
    return ScanRecursiveWithOptions(ctx, codePath, maxDepth, Options{})
}
```

Rename the existing `ScanRecursive` body to `scanViaOSV` (unexported, same body).

### 5. Implement `scanViaSubprocess`

New function in `pip/scanner.go`:

```go
// scanViaSubprocess runs `pip-audit --format json -r <manifest>` for every
// requirements.txt manifest discovered under codePath up to maxDepth levels.
// Stamps the relative manifest path on each finding's Endpoint so users can
// tell which service owns each CVE (parity with scanViaOSV).
//
// pip-audit's JSON output shape (--format json):
//   {
//     "dependencies": [
//       {"name": "...", "version": "...", "vulns": [{"id": "...", "fix_versions": [...], "description": "..."}, ...]},
//       ...
//     ]
//   }
//
// We map pip-audit's vuln IDs (which are OSV IDs) into the SEC-DEPS-<id>
// shape used by scanViaOSV's buildFinding. Title/severity/fix shape is
// identical to the OSV.dev path so downstream dedup, correlator, and
// reporters cannot tell the two paths apart.
//
// pip-audit's JSON shape has changed twice in 2024. This implementation
// targets pip-audit >= 2.7.0 schema. Older versions: parsing returns an
// error with a clear "upgrade pip-audit" hint.
func scanViaSubprocess(ctx context.Context, codePath string, maxDepth int, pipAuditPath string) ([]models.Finding, error) {
    abs, err := filepath.Abs(codePath)
    if err != nil {
        return nil, fmt.Errorf("pip: resolve path: %w", err)
    }
    manifests, err := findRequirementsManifests(abs, maxDepth)
    if err != nil {
        return nil, fmt.Errorf("pip: walk for requirements.txt: %w", err)
    }
    var all []models.Finding
    for _, m := range manifests {
        rel, _ := filepath.Rel(abs, m)
        if rel == "" {
            rel = "requirements.txt"
        }
        cmd := exec.CommandContext(ctx, pipAuditPath, "--format", "json", "-r", m)
        out, err := cmd.Output()
        if err != nil {
            // pip-audit exits 1 when findings exist. Distinguish: exit-1 + JSON output = expected, other exits = failure.
            if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 && len(out) > 0 {
                // findings exist; proceed to parse
            } else {
                fmt.Fprintf(os.Stderr, "[fendix] pip: pip-audit failed on %s: %v\n", m, err)
                continue
            }
        }
        findings, err := parsePipAuditJSON(out, rel)
        if err != nil {
            return nil, fmt.Errorf("pip: parse pip-audit output for %s: %w (run with --verbose for stderr)", rel, err)
        }
        all = append(all, findings...)
    }
    sortFindingsByID(all)
    return all, nil
}

// parsePipAuditJSON maps pip-audit's --format json output to []models.Finding.
// Targets pip-audit >= 2.7.0 schema. Returns a clear error on older schemas.
func parsePipAuditJSON(jsonBytes []byte, manifestRelPath string) ([]models.Finding, error) {
    var report struct {
        Dependencies []struct {
            Name    string `json:"name"`
            Version string `json:"version"`
            Vulns   []struct {
                ID          string   `json:"id"`
                FixVersions []string `json:"fix_versions"`
                Description string   `json:"description"`
                Aliases     []string `json:"aliases"`
            } `json:"vulns"`
        } `json:"dependencies"`
    }
    if err := json.Unmarshal(jsonBytes, &report); err != nil {
        return nil, fmt.Errorf("decode pip-audit JSON (expected schema from pip-audit >= 2.7.0): %w", err)
    }
    var findings []models.Finding
    for _, d := range report.Dependencies {
        for _, v := range d.Vulns {
            // Reuse buildFinding for shape parity. Convert pip-audit's vuln
            // record to the same osvVuln shape buildFinding consumes.
            osv := osvVuln{
                ID:      v.ID,
                Summary: v.Description,
                Aliases: v.Aliases,
            }
            // pip-audit returns fix_versions as a list; preserve the first.
            if len(v.FixVersions) > 0 {
                osv.Affected = []osvAffected{{
                    Ranges: []osvRange{{Events: []osvEvent{{Fixed: v.FixVersions[0]}}}},
                }}
            }
            findings = append(findings, buildFinding(
                pinnedPackage{name: d.Name, version: d.Version},
                osv,
                manifestRelPath,
            ))
        }
    }
    return findings, nil
}
```

### 6. Wire orchestrator to pass Options

In [`orchestrator.go`](../../go/internal/engine/orchestrator.go), replace the `pip.ScanRecursive(ctx, o.cfg.CodePath, pip.DefaultRecurseDepth)` call with:

```go
pipFindings, err := pip.ScanRecursiveWithOptions(
    ctx, o.cfg.CodePath, pip.DefaultRecurseDepth,
    pip.Options{UsePipAudit: o.cfg.UsePipAudit},
)
```

### 7. New tests in `scanner_test.go`

Add **at least** these test functions. Each follows the existing `httptest.NewServer` style.

```go
// TestScanViaSubprocess_HappyPath uses a fake pip-audit binary on PATH.
// Verifies that --use-pip-audit causes the subprocess path to run and
// converts pip-audit's JSON shape to []models.Finding correctly.
func TestScanViaSubprocess_HappyPath(t *testing.T) {
    // Setup: write a fake pip-audit shell script to a tempdir.
    // Script prints a canned --format json output and exits 1 (findings present).
    // Prepend tempdir to PATH for the test duration.
    // Verify: findings have the right ID shape, manifest path is stamped on Endpoint.
}

// TestScanViaSubprocess_PipAuditNotInstalled verifies that --use-pip-audit
// with no pip-audit on PATH falls back to the OSV.dev client cleanly with a
// stderr warning, NOT a hard error.
func TestScanViaSubprocess_PipAuditNotInstalled(t *testing.T) {
    // Setup: PATH=""; use a httptest fake OSV.dev to verify the OSV.dev path runs.
    // Capture stderr; assert the warning is present.
}

// TestScanViaSubprocess_ExitCode1WithFindingsIsNormal asserts that pip-audit's
// "exit 1 = findings exist" convention is handled — we don't treat it as failure.
func TestScanViaSubprocess_ExitCode1WithFindingsIsNormal(t *testing.T) { ... }

// TestScanViaSubprocess_RealFailureLogsAndContinues asserts that a fake
// pip-audit exiting 127 or 2 (real failure) logs to stderr and continues
// the scan (does NOT propagate as an error to the orchestrator).
func TestScanViaSubprocess_RealFailureLogsAndContinues(t *testing.T) { ... }

// TestParsePipAuditJSON_HappyPath asserts the schema mapping.
func TestParsePipAuditJSON_HappyPath(t *testing.T) { ... }

// TestParsePipAuditJSON_BadSchemaErrors asserts that pre-2.7.0 output
// (or any malformed JSON) returns a clear "upgrade pip-audit" error.
func TestParsePipAuditJSON_BadSchemaErrors(t *testing.T) { ... }
```

Helper for the fake binary:

```go
func writeFakePipAudit(t *testing.T, dir, jsonOutput string, exitCode int) {
    t.Helper()
    script := fmt.Sprintf("#!/bin/sh\ncat <<'EOF'\n%s\nEOF\nexit %d\n", jsonOutput, exitCode)
    path := filepath.Join(dir, "pip-audit")
    if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
        t.Fatal(err)
    }
    t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}
```

### 8. CHANGELOG entry

Add under `[Unreleased]` heading, before any v0.11.0 content:

```markdown
## [Unreleased]

### Fixed (v0.11.1 — Track 4 honesty fixes)

- **pip-audit naming gap**: Package doc + log messages now state honestly
  that the native dep-CVE path is an OSV.dev `/v1/query` REST client, not
  a pip-audit invocation. Behavioural parity with pip-audit is preserved
  (same advisory sources, same finding shape). Closes audit §15.5.

### Added

- `--use-pip-audit` flag on `fendix scan`: opt-in to shell out to the
  actual pip-audit binary instead of the native OSV.dev client. Falls
  back to OSV.dev with a stderr warning if pip-audit is not on PATH —
  never fails-closed silently. Targets pip-audit >= 2.7.0 JSON schema;
  older versions produce a clear "upgrade pip-audit" error.
```

---

## Definition of done

- [ ] All 4 cross-cutting requirements from [`PLAN.md`](PLAN.md) honored
- [ ] `make test` passes — zero failures, zero race-detector hits
- [ ] `make e2e` passes
- [ ] `make bench` shows no regression vs. pre-sprint baseline (capture both numbers in PR description)
- [ ] `bin/fendix scan --help` shows the new `--use-pip-audit` flag with the description above
- [ ] `bin/fendix scan --use-pip-audit --code <fixture-with-CVEs>` works end-to-end against a real `pip-audit` installation (manually verified, screenshot in PR)
- [ ] `bin/fendix scan --use-pip-audit --code <fixture>` with no pip-audit on PATH emits the warning AND completes with OSV.dev results (manually verified, screenshot in PR)
- [ ] [`CHANGELOG.md`](../../CHANGELOG.md) updated under `[Unreleased]`
- [ ] PR description cites `FENDIX_AUDIT_REPORT.md §15.5`
- [ ] This sprint file updated with actual-vs-estimate, surprises, follow-ups

---

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| pip-audit JSON schema differs from documented in some installed version | Med | Pin against the 2.7.0+ schema in `parsePipAuditJSON`. Clear error message on schema mismatch. Test against the latest pip-audit at sprint start. |
| `exec.CommandContext` with a slow pip-audit (large requirements.txt) blocks the scan budget context | Low | Inherits the same ctx the orchestrator passes; no new timeout needed. Document in code comment. |
| Some pip-audit version exits 2 (instead of 1) when findings exist | Low | Test handles only exit 0 (no findings) + exit 1 (findings) as normal; everything else logs and continues. Cite pip-audit source if behaviour found different in the wild. |

---

## Follow-ups (NOT in scope for this sprint)

- pip-audit subprocess could honor the existing OSV.dev cache by passing `--cache-dir`. Useful but adds complexity; defer.
- npm has the same naming gap (the npm scanner is also OSV.dev, not `npm audit`). Mirror this sprint for npm in a follow-up. ~0.5 days.
- govulncheck path is already honest (uses `golang.org/x/vuln/scan` in-process; no third-party binary involved). No fix needed there.

---

## Status

**Started:** 2026-05-14 (AI implementer)
**Branch:** `phase1-trust-fixes` (off main; Phase 1 lands all three sprints
on one branch per the bootstrap plan, not one branch per sprint)
**PR:** drafted; not pushed
**Status:** done
**Actual effort:** ~0.5 day (sprint file estimated 1 day; the bulk of
the saved time was that the existing `httptest.NewServer` plumbing in
`scanner_test.go` was already shaped exactly the way Sprint 02 will
also need, so the new fake-binary + captured-stderr helpers slotted in
without refactoring the existing tests.)

**Surprises:**

- **`scan_config.go` doesn't exist.** The sprint file pointed at
  `go/internal/models/scan_config.go`; the `ScanConfig` struct actually
  lives in `go/internal/models/config.go`. Adjusted the path; no
  behavioural change.
- **pip-audit returns transitive deps too.** A live invocation against
  a fixture pinning only `flask==2.0.1` + `requests==2.20.0` produced
  17 dep-CVEs, including `urllib3` advisories that are pulled in
  transitively. Our scanner doc says "no transitive resolution"
  because that's the OSV.dev path; the pip-audit path inherits
  pip-audit's own resolver, so the `--use-pip-audit` flag is also a
  *transitive coverage* upgrade for users who want it. Documented in
  CHANGELOG; not surfaced in `--help` text since the docstring is the
  honest place for the nuance.
- **`pip-audit` install pulled in `defusedxml-0.7.1` and surfaced a
  pre-existing PyJWT version conflict** in the dev environment. Not
  caused by this sprint; flagging in case anything in the global
  Python env starts misbehaving.
- **Bench numbers are within run-to-run noise as expected.** The
  engine bench fixture doesn't exercise the dep-CVE path so a
  no-regression result was the predicted outcome (and the actual
  one). Captured for the PR description regardless.

**Bench (BenchmarkScan_Throughput/endpoints=1000):**

| Branch | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| main | 31,802,692 | 25,091,868 | 235,724 |
| phase1-trust-fixes (post-Sprint 01) | 31,824,142 | 25,081,948 | 235,683 |

Δ < 0.1% on every metric — within noise.

**Follow-ups created:**

- npm scanner mirrors the same naming gap (it's also OSV.dev, not
  `npm audit`). Not added as a separate ticket here; tracked in this
  sprint file's "Follow-ups" section above and revisited in Sprint 02
  (which already has to touch the npm scanner for batch queries).
- pip-audit's transitive-resolution behaviour deserves a `--help`
  hint or doc note so users picking the flag know they get more
  than just "the same scan via a different binary." Tracked in the
  Status section here; not blocking.
