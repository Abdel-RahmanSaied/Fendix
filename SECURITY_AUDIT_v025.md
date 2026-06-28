# Security Audit — Fendix v0.25 (Developer Experience)
Audited by: Security Agent (+ 6-lens adversarial review workflow)
Date: 2026-06-29
Scope: CLI-success-rate instrumentation (metrics), CLI error/help UX, faster
incremental scans (diff-aware fast path), triage-first PR comment + init.

## Findings
### CRITICAL / HIGH — none.

### MEDIUM (found + FIXED this phase)
- **Diff fast-path symlink scope-escape (M1/M2).** The B3 secrets/textscan
  fast paths rejected only a final-component symlink; `os.Lstat` follows
  *intermediate* symlinked directories, so an allowlist entry traversing a
  symlinked parent (pointing outside the repo) was read while the full
  `WalkDir` — which never descends symlinks — skipped it. A real walk-parity
  break + repo-scope escape on the exported `ScanWithAllowlist`.
  **Fixed** (43cbbae): `gitdiff.TraversesSymlink` Lstats each parent component
  and refuses any symlinked/out-of-root path; both fast paths gate on it, so
  their reachable file set is a strict subset of the walk's. Tests added.
  Reachability was low (the production `git diff --name-only` flow never emits
  such paths), but the documented control was genuinely broken — fixed anyway.

## Privacy analysis — the new telemetry (B0/B1)
- **No PII / no content.** The new opt-in `cli`-phase events record the
  subcommand NAME (`scan`, `version`, …), exit code, a success flag, and a
  coarse error CLASS (`usage`/`scan-error`/`runtime`). Never arguments, paths,
  hostnames, targets, secrets, or error text. Verified by the `metrics` struct
  + classifier (command name + class only) and documented in `privacy.md`.
- **Opt-in, local-only, unchanged.** Off unless `FENDIX_METRICS` is set (zero
  events + zero I/O when off — tested); still never transmitted.
- **No exit-code interference.** The metric write is best-effort; failures are
  dropped and never alter the user's exit code (adversarial `refute:metrics`
  confirmed).

## Output / injection analysis
- **PR comment (B4).** F-L11 Markdown/HTML escaping intact (titles/endpoints
  escaped; status/score are our own enum/int). The triage copy-sort
  (`append(r.Findings[:0:0], …)`) does not mutate the source slice. Verdict
  banner uses our own decision counts and no longer shows a false green when
  the decisions object is absent.
- **CLI error/help/init text.** Teaching errors, usage hints, quickstart, and
  `init` scan recommendations interpolate no untrusted input unsafely.
- **Exit refactor (B1).** `os.Exit(code)` → `cli.ExitWithCode(code,"")` is
  byte-identical for all outcomes (A/B verified vs the prior tag); no leaked
  output.

## Sign-off
- [x] No CRITICAL/HIGH findings unresolved
- [x] The two MEDIUM symlink findings fixed + tested (net security improvement)
- [x] New telemetry carries no sensitive data; opt-in; never transmitted
- [x] No existing security control weakened (diff fast path is a strict subset of the walk)
