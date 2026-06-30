# Fendix v1.0 Release Runbook (operator)

The engine is at verified v1.0-readiness on `main` (see `V1.0_READINESS.md`):
every accuracy number reproduced, repo green, the release pipeline validated
through nfpm packaging. The steps below are the **operator-only** actions an
agent cannot perform (credentials, DNS, business/architecture decisions). They
take ~30 min of wall-clock plus one CI run.

---

## Step 0 — one-time prerequisites (the hard blockers)

1. **Cosign signing variable.** Repo → Settings → Secrets and variables →
   Actions → Variables → add `COSIGN_ENABLED = true`.
   (The release workflow's first job *fails the tag loudly* without this — by
   design, so an unsigned "official" release can't happen by accident. To ship
   an intentionally-unsigned debug tag, set it to `allow-unsigned` instead.)
2. **Download domain DNS.** Point `get.fendix.dev` at the install-script host
   (the `curl … | sh` install path + the mirror upload glob assume it). If you
   are not using that domain yet, the GitHub Release artifacts still publish;
   only the `get.fendix.dev` convenience installer depends on this.
3. **Open-source posture (TASK-112).** Confirm the MIT license is final and the
   repo is intended fully public (README + ADR-007 already declare MIT). If any
   code must stay private, do the repo split before tagging.

## Step 1 — cut the release candidate (validates the pipeline cheaply)

```bash
# Roll the changelog: rename "## [Unreleased]" to "## [0.6.0-rc1] - <date>"
#   (the entries are already written — see CHANGELOG.md), then:
git checkout main && git pull
git tag -a v0.6.0-rc1 -m "v0.6.0-rc1 — validate signed release pipeline"
git push origin v0.6.0-rc1          # fires .github/workflows/release.yml
```

## Step 2 — verify the rc1 release

- Actions → Release run is green (the `Require cosign on v* tags` gate passes).
- The GitHub Release has: per-arch binaries, `.deb` + `.rpm`, Docker image,
  and the cosign `.sig`/`.crt` sidecars.
- Verify a signed artifact:
  ```bash
  cosign verify-blob --certificate fendix-…​.crt --signature fendix-…​.sig \
    --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' fendix-…​
  ```
- Install-smoke the package: `sudo dpkg -i fendix_0.6.0-rc1_amd64.deb && fendix version`.
  (Local nfpm dry-run already confirmed payload paths/perms/deps; this confirms
  the *signed CI build*.)

## Step 3 — tag v1.0.0

If rc1 is clean: roll `CHANGELOG` `[0.6.0-rc1]` → `[1.0.0] - <date>`, then
`git tag -a v1.0.0 -m "Fendix v1.0.0" && git push origin v1.0.0`.

---

## Post-v1.0 — the standing engine fork (not a v1.0 blocker)

**Java-parser architecture decision** gates the *deep* Java taint engine + any
real OWASP Benchmark number. Options (an agent can implement once you choose):
- **WASM tree-sitter-java via wazero** — keeps `CGO_ENABLED=0` (recommended;
  preserves the single-static-binary invariant).
- **javalang on the optional Python side** — zero Go-binary risk; unmaintained.
- **CGo tree-sitter** — rejected unless you explicitly relax the static-binary
  invariant (it breaks reproducible `CGO_ENABLED=0` builds).

OWASP stays SKIP (machine-pinned) until a real Java taint analyzer + a labeled
`benchmarks/targets/owasp-known.json` exist — see that file's `_definition_of_done`.

---

*Hand-off note: an agent took this to the last pre-trigger step. Everything
before "set the secret + push the tag" is done and verified. The remaining
actions require your credentials and decisions, by design.*
