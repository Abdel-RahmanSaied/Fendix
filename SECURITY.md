# Security Policy

Thanks for taking the time to make Fendix safer to ship and to use.

This document covers two things:

1. How to report a vulnerability **in Fendix itself** (the scanner — the
   binary, the Python engine, the release pipeline). For a higher-level
   discussion of how Fendix is *designed* to be safe when scanning targets
   that are not your own, see [`docs/threat-model.md`](docs/threat-model.md).
2. The release artifacts you should trust, and how to verify them.

---

## Supported versions

Security fixes are backported only to the most recent minor release.

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | ✅ active           |
| 0.4.x   | ✅ critical only    |
| < 0.4   | ❌ end of life      |

Pre-1.0 releases follow SemVer at the minor level: `0.5.x` → `0.6.x` is
considered a minor version bump, and only the latest minor receives
non-critical fixes. Once Fendix reaches `1.0.0`, this policy will move to
"latest two minor versions, security fixes only on the previous one."

## Reporting a vulnerability

**Please do not open a public GitHub issue.**

Use one of the following private channels:

- **GitHub private vulnerability report** (preferred):
  <https://github.com/Abdel-RahmanSaied/Fendix/security/advisories/new>
- **Email**: `security@fendix.dev` (PGP key on request)

Include in your report:

- A clear description of the vulnerability and the affected component
  (Go binary, Python engine, release pipeline, embedded dependency, etc.).
- Steps to reproduce, or a minimal proof of concept.
- Fendix version (`fendix version`).
- Impact assessment if you have one — what an attacker can do, what
  privileges they need, what they can read/modify/destroy.
- Whether you intend to publish a write-up, and on what timeline. We
  prefer coordinated disclosure but will not block legitimate research.

You will receive an acknowledgement within **72 hours**, and a full
triage response within **7 days**. If we accept the report we'll work
with you on a fix and a release timeline; if we decline, you'll get a
written reason. If you don't hear back in 7 days, please escalate by
emailing the maintainer directly.

## Scope

In scope for this policy:

- The `fendix` binary built from this repo (`go/cmd/fendix`).
- The Python engine and its analyzers (`python/`).
- Vulnerabilities in dependencies that are reachable from a default
  scan (i.e. not just present in `go.sum` but actually called).
- The release pipeline (`.github/workflows/release.yml`) and its
  outputs — signed binaries, Docker image, Homebrew tap.
- Misuse of the active scanner that goes beyond the documented
  safety envelope (see [`docs/threat-model.md`](docs/threat-model.md)
  §"Active scanner safety envelope").

Out of scope:

- Findings produced by Fendix against a third-party target — those
  belong to the target's vendor.
- Theoretical issues that require an attacker to already control the
  machine running Fendix (e.g. "if I write a malicious `.fendix-ignore`
  file I can suppress findings"). The threat model assumes the host
  user is trusted.
- Self-DoS via input parameters — Fendix is a CLI scanner, not a
  service. If you can crash Fendix by feeding it a 50 MB malformed
  spec, that's a bug, but it's not a security issue.

## Verifying release artifacts

Starting with the first cosign-enabled release after v0.5.0, every
release binary and the Docker image are signed with **cosign in
keyless mode** — Sigstore Fulcio + GitHub Actions OIDC. There is no
shared key to leak; signatures are bound to the GitHub Actions
identity that produced them.

### Verifying a binary

```sh
# After downloading both fendix-vX.Y.Z-linux-amd64 and the .sig + .crt
# sidecars from the GitHub release page:
cosign verify-blob \
  --certificate fendix-vX.Y.Z-linux-amd64.crt \
  --signature   fendix-vX.Y.Z-linux-amd64.sig \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-vX.Y.Z-linux-amd64
```

A successful verification prints `Verified OK`. Any mismatch — wrong
identity, wrong signing time, tampered binary — exits non-zero.

### Verifying the Docker image

```sh
cosign verify ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

### Until cosign is enabled

Pre-cosign releases (v0.5.0 and earlier) ship with `.sha256` sidecars
only. Verify the SHA matches what GitHub publishes on the release page
and that the URL is the canonical one
(`https://github.com/Abdel-RahmanSaied/Fendix/releases/download/...`).
We recommend pinning to a specific tag rather than `:latest` until
you've cut a cosign-verified upgrade path into your installer.

## Disclosure timeline

Once a fix is ready, we publish it via **all** of:

- A GitHub Security Advisory, with CVE assignment (we are a CNA-eligible
  open-source project under GitHub's CNA umbrella).
- A patched release on the supported branch (e.g. `0.5.1` for a `0.5.x`
  fix), with the security advisory linked from the release notes.
- A `### Security` block in `CHANGELOG.md` summarising the issue and the
  fix.
- Credit to the reporter (unless they request anonymity).

We aim to publish within **14 days** of the fix landing. Reporters can
request a longer embargo if downstream coordination is needed.

## Policy for active-scanner misuse

Fendix's active scanner sends real payloads (SQLi, CMDi, CRLF) to a
target host. This is *only* legitimate when:

- The target is owned by the operator (`localhost`, staging, the org's
  own production), **or**
- The operator has written authorisation to test it (a pentest scope of
  work, a CTF, a bug-bounty program with explicit authorisation for
  active probing).

Reports of the form "Fendix can be used as an attack tool" without
evidence that the safety envelope is broken (see threat-model doc) are
not in scope. Reports that the safety envelope itself can be bypassed
**are** in scope and should be filed via the channels above.

## Recognition

A `SECURITY.md` Hall of Fame section will be added as soon as we
receive our first valid report. If you'd rather not be listed, just
say so in your report.
