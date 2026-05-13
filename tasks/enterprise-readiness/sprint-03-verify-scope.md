# Sprint 03 — `fendix verify` scope + exit codes

**Phase:** 1.3 (Honesty & Trust Fixes)
**Estimate:** 0.5 day
**Risk:** Low
**Ships in:** v0.11.1
**Audit reference:** [`FENDIX_AUDIT_REPORT.md`](../../FENDIX_AUDIT_REPORT.md) §7 — "`fendix verify` current state"

---

## Why this sprint exists

`fendix verify` (shipped in Sprint 0 / current `fix/track4-engine-gaps` branch) handles three finding shapes: URL-anchored DAST, file-anchored SAST, and dep-CVE. Two shapes are unsupported and return `status: unknown`:
- Correlated findings (`source: correlated`)
- Active injection probe findings (require `--enable-active`)

The current `--help` text doesn't mention this. A user who runs verify on a correlated finding and gets `unknown` thinks the tool is broken. Also: the CLI exits 0 regardless of status — useless in CI scripts.

This sprint adds the missing scope docs and proper exit codes. Both small, both high-leverage for trust.

---

## Read first

- [`go/cmd/fendix/main.go`](../../go/cmd/fendix/main.go) — find `newVerifyCmd()` (search for it). Note the existing `Long:` field and `RunE` closure.
- [`go/internal/verifycmd/verifycmd.go`](../../go/internal/verifycmd/verifycmd.go) — read the package doc (lines 1–34). Find the `Run` function and the `switch` near the bottom that dispatches by finding shape. Note the `default:` branch.
- [`go/internal/verifycmd/verifycmd_test.go`](../../go/internal/verifycmd/verifycmd_test.go) — test patterns you'll follow.

---

## Concrete deliverables

### 1. Update `newVerifyCmd().Long`

Replace the current `Long:` field with:

```go
Long: `Re-test a specific finding from a saved baseline scan report and
report whether it is still present, resolved, or unverifiable.

Supported finding shapes:
  - URL-anchored DAST findings    (source: blackbox)
  - File-anchored SAST findings   (source: whitebox, category: secrets/injection/headers/...)
  - Dependency CVE findings       (category: deps)

Not yet supported (returns status "unknown" with an explanatory reason):
  - Correlated findings           (source: correlated)
  - Active injection probe findings (require --enable-active to reproduce)

Exit codes:
  0   resolved          — the finding no longer fires
  1   still-present     — the finding still fires; CI should fail
  2   unknown OR
      not-found-in-baseline — verify could not produce a confident result

Use in CI:

  fendix verify SEC-001-abc --baseline scan.json --url $TARGET_URL \\
      || (echo "still present"; exit 1)
`,
```

### 2. Improve `Run`'s `default:` branch reason

In [`verifycmd.go`](../../go/internal/verifycmd/verifycmd.go), find the `switch` that dispatches by finding shape (look for `case isDepFinding(...)`, `case isURLFinding(...)`, `case isFileFinding(...)`). Update the `default:` branch:

```go
default:
    out.Status = StatusUnknown
    out.Reason = fmt.Sprintf(
        "verify does not yet support this finding shape (source=%q, category=%q). "+
        "Correlated and active-probe findings are MVP-deferred — see "+
        "tasks/enterprise-readiness/sprint-03-verify-scope.md. "+
        "Workaround: re-run the full scan that produced the baseline "+
        "(fendix scan --code <path> --url <url> --enable-active if applicable) "+
        "and diff against the baseline.",
        original.Source, original.Category)
```

### 3. Add exit code semantics in CLI handler

In `main.go`'s `newVerifyCmd().RunE`, after the `Run` call and before/around the `Render` call:

```go
result, err := verifycmd.Run(cmd.Context(), args[0], opts)
if err != nil {
    return err
}
if err := verifycmd.Render(os.Stdout, result, jsonOut); err != nil {
    return err
}

// Exit code semantics for CI scripting. Set via os.Exit at the very end
// of execution; cobra's RunE returning a non-error nil keeps the deferred
// cleanups running.
switch result.Status {
case verifycmd.StatusResolved:
    return nil // exit 0 (default for RunE returning nil)
case verifycmd.StatusStillPresent:
    return cli.ExitWithCode(1, "finding still present")
case verifycmd.StatusUnknown, verifycmd.StatusNotFoundInBaseline:
    return cli.ExitWithCode(2, fmt.Sprintf("verification %s", result.Status))
default:
    return cli.ExitWithCode(2, fmt.Sprintf("unexpected status %q", result.Status))
}
```

If `cli.ExitWithCode` doesn't exist, add the simplest viable equivalent in a new `internal/cli/exit.go`:

```go
// Package cli holds tiny shared CLI utilities. Today it has one type:
// ExitError, which carries a custom exit code that cobra honors via its
// SilenceErrors + SilenceUsage flags.
package cli

import "fmt"

type ExitError struct {
    Code    int
    Message string
}

func (e *ExitError) Error() string {
    if e.Message == "" {
        return fmt.Sprintf("exit %d", e.Code)
    }
    return e.Message
}

func ExitWithCode(code int, msg string) error {
    return &ExitError{Code: code, Message: msg}
}
```

In `main.go`'s top-level error handler (where cobra returns the error), catch `*cli.ExitError` and call `os.Exit(e.Code)` explicitly.

Verify cobra's `SilenceUsage: true` and `SilenceErrors: true` on the verify command so the exit-1 / exit-2 paths don't dump a help-banner to the user.

### 4. Update package doc in `verifycmd.go`

Update the top-of-file comment to match the new scope statement, including the exit-code semantics.

### 5. Tests

Add to [`go/internal/verifycmd/verifycmd_test.go`](../../go/internal/verifycmd/verifycmd_test.go):

```go
// TestRunCorrelatedFindingReturnsUnknownWithExplanation asserts that
// verify on a correlated finding emits status=unknown AND a Reason
// string that mentions correlated findings + the workaround.
func TestRunCorrelatedFindingReturnsUnknownWithExplanation(t *testing.T) {
    // Setup: baseline JSON with one finding where Source == SourceCorrelated.
    // Call Run; assert Status == StatusUnknown and Reason contains "correlated".
}

// TestRunActiveProbeFindingReturnsUnknown verifies the same for
// findings carrying the active-probe marker.
func TestRunActiveProbeFindingReturnsUnknown(t *testing.T) { ... }

// TestRenderJSONIncludesAllFields confirms the JSON output shape is stable
// (status, reason, original, latency_ms, verified_at all present).
func TestRenderJSONIncludesAllFields(t *testing.T) { ... }
```

Add to `go/internal/e2e/verify_e2e_test.go` (new file under the `e2e` build tag):

```go
// e2e test: verify exits with the right code for each status.
// Uses the existing fendixBinary helper.
func TestE2EVerifyExitCodes(t *testing.T) {
    cases := []struct {
        name     string
        baseline string // path to a fixture
        wantExit int
    }{
        {"resolved finding", "fixtures/verify/resolved.json", 0},
        {"still-present", "fixtures/verify/still-present.json", 1},
        {"unknown shape", "fixtures/verify/correlated.json", 2},
        {"not-found-in-baseline", "fixtures/verify/empty.json", 2},
    }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            cmd := exec.Command(fendixBinary, "verify", "SEC-001-abc",
                "--baseline", c.baseline, "--url", "http://localhost:1")
            err := cmd.Run()
            got := 0
            if exitErr, ok := err.(*exec.ExitError); ok {
                got = exitErr.ExitCode()
            }
            if got != c.wantExit {
                t.Errorf("exit code: got %d want %d", got, c.wantExit)
            }
        })
    }
}
```

Fixtures live under `go/internal/e2e/fixtures/verify/` — small JSON files with hand-crafted findings.

### 6. CHANGELOG entry

Add under `[Unreleased]`:

```markdown
### Changed (v0.11.1)

- `fendix verify` exit codes are now CI-script-friendly:
  - **0** — finding is resolved
  - **1** — finding is still present
  - **2** — verify could not produce a confident result (unknown shape,
    not in baseline, or correlated/active-probe finding that needs a
    full re-scan to verify)
  Previously, verify always exited 0. CI scripts that wanted to fail
  the build on still-present findings had to parse JSON output.
- `fendix verify --help` now lists supported and unsupported finding
  shapes explicitly. Correlated and active-probe findings are
  documented as MVP-deferred (Sprint 03 of the enterprise-readiness
  plan).
```

---

## Definition of done

- [ ] `fendix verify --help` shows the new scope statement + exit code table
- [ ] `fendix verify <id-of-resolved-finding> ...; echo $?` prints `0`
- [ ] `fendix verify <id-of-still-present-finding> ...; echo $?` prints `1`
- [ ] `fendix verify <id-of-correlated-finding> ...; echo $?` prints `2`
- [ ] `fendix verify --json <id-of-not-in-baseline> ...; echo $?` prints `2`
- [ ] `make test` passes — including the 3 new unit tests and the 4 new e2e cases
- [ ] [`CHANGELOG.md`](../../CHANGELOG.md) entry under `[Unreleased]`
- [ ] PR description cites `FENDIX_AUDIT_REPORT.md §7`

---

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Existing callers of `fendix verify` assume exit 0 always = success | Low (verify is too new for many callers) | CHANGELOG note flags as a breaking change at the exit-code level. Anyone running `fendix verify && ...` will now correctly fail on still-present findings, which is what they wanted. |
| cobra's `SilenceUsage` config not present on verify | Low | Confirm during implementation; add if missing. |

---

## Follow-ups (NOT in scope)

- **Real verify for correlated findings.** Once a correlated finding's underlying blackbox AND whitebox findings can each be verified, the correlator could be re-run on the diff. Add to Sprint roster as Sprint 03.5 if customers ask.
- **Active-probe verify** — would need to invoke the injection scanner against a single endpoint. Doable but bigger than this sprint.

---

## Status

**Not started.**
