# Security Audit — Fendix v0.21 (Earn Trust)
Audited by: Security Agent
Date: 2026-06-28
Scope: code/docs CHANGED in v0.21. The pre-existing HIGH fixes (F-H1/H2/H3/
H5a/H5b) were verified in place during scoping (see `TASK_MANIFEST_v021.md`)
and are not re-derived here.

## Changes audited
| Change | Files |
|--------|-------|
| V1 config-leak FP fix | `go/internal/scanner/configleak.go` (+test) |
| V4 install verification | `scripts/install.sh` |
| V5 token-scrub lock | `go/internal/ghapp/scanner_test.go` (test only) |
| V6 trust docs | `docs/trust-center.md`, `docs/privacy.md`, `README.md` (docs only) |

## Findings

### CRITICAL — none.
### HIGH — none introduced.

### MEDIUM — none.

### LOW
- **L-1 — config-leak FN edge case.** The SPA guard suppresses a 200 when the
  response is HTML. A server misconfigured to serve a real `.env`/`.git/HEAD`
  with `Content-Type: text/html` would now be missed. This is rare (config
  files are plaintext/binary) and is the correct precision/recall trade-off:
  the prior behavior produced phantom CRITICALs on *every* SPA. Documented in
  the code comment. Net: large FP reduction for a negligible FN risk.

## Per-change notes

**V1 (`configleak.go`)** — Outbound still goes through the existing
SSRF-guarded `cc.Client` (no new egress surface). The body is read only as a
bounded 512-byte sniff prefix + a discarded size drain (≤1 MiB); it is **never
stored** — the no-secret-in-evidence property is preserved. `http.DetectContentType`
is the stdlib detector. No new `exec`, no user-controlled format strings.

**V4 (`install.sh`)** — Strictly hardening: fail-OPEN → fail-CLOSED. The
bypass (`FENDIX_ALLOW_UNVERIFIED=1`) is explicit and loud. cosign is invoked
with controlled args; the identity uses `SIGN_REPO` (default = the main engine
repo whose OIDC identity signs releases), NOT `$REPO` (the homebrew tap) — a
wrong identity there would have failed every verification. `sh -n` clean.
Signature mismatch aborts the install.

**V5 / V6** — Test-only and docs-only; no runtime attack surface. The trust
docs make no claim that isn't backed by code/tests, and explicitly state no
SOC2/ISO certification (no overclaim — Rule 5).

## SSRF surface map (new/changed code)
| Call site | Destination | Attacker-controllable? |
|-----------|-------------|------------------------|
| `configleak.go` GET | scan target, via SSRF-guarded client | No (unchanged guard) |
| `install.sh` curl `.sig`/`.crt` | same release host as the binary | No |
| `install.sh` cosign verify-blob | local exec; queries Sigstore (Rekor/Fulcio) | No (verification only) |

## Secrets audit
- No secrets in changed code. `configleak.go` actively avoids persisting the
  served-file body. `scrubTokenFromEnv` test uses a fake token literal.

## Sign-off
- [x] No CRITICAL findings unresolved
- [x] No new HIGH findings introduced by v0.21 changes
- [x] All v0.21 changes are hardening, accuracy, test, or documentation
- [x] Build / vet / gofmt / full test suite green; `sh -n` clean
