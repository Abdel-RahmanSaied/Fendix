# Fendix — GitLab CI next steps

`fendix init --ci gitlab` wrote `.gitlab-ci.fendix.yml` to your repo
root. GitLab CI doesn't merge multiple files in `.gitlab-ci.yml`
locations automatically; you wire the snippet in by adding an
`include:` line to your main `.gitlab-ci.yml`:

```yaml
include:
  - local: .gitlab-ci.fendix.yml
```

If you don't have a `.gitlab-ci.yml` yet, create one containing just
the `include:` block above (plus a `stages:` line that lists `test`).

## Pinning the Fendix version

`fendix init` pins `FENDIX_VERSION` in `.gitlab-ci.fendix.yml` to the
Fendix release that generated it, so every pipeline installs the same
verified binary. To upgrade, change it to a newer tag from
<https://github.com/Fendix-app/Fendix/releases>:

```yaml
variables:
  FENDIX_VERSION: "vX.Y.Z"
```

The install step rejects anything that is not a release tag, including
"latest". It fetches the installer at `FENDIX_INSTALLER_COMMIT`, the
commit that release was built from; the installer works for any release,
so it needs no change when you upgrade. Set `FENDIX_SHA256` to the
`.sha256` of `fendix-<version>-linux-amd64` to bind the job to that exact
binary. The job installs cosign and requires a verified release
signature (`FENDIX_REQUIRE_SIGNATURE=1`).

## Required project settings

- **Report download** — `fendix-results.sarif` is retained as a job
  artifact on every tier. It is SARIF 2.1.0, not the GitLab native SAST
  schema, so this job does not declare `artifacts:reports:sast`. Import it
  into a SARIF-compatible consumer or Fendix workspace.
- **Python engine** — the standalone binary does not bundle the Python
  analyzers. Prepare a version-matched Python tree and its requirements,
  set `FENDIX_ENGINE`, and run `fendix engine sync` before the scan, or
  use the official Fendix container. Required analyzers must be checked
  with `--fail-on-coverage-gap` and `--require-analyzers`; exit 0 alone
  does not establish complete coverage.
- **No tokens needed for the public install path.** If your scan
  target requires credentials, plumb them via masked CI variables
  and reference them in the `script:` block.

## Commit

```bash
git add .gitlab-ci.fendix.yml
git commit -m "Add Fendix security scanning"
```
