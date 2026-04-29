# Shipping Fendix — Release Runbook

> Use this every time you cut a new version. Last updated: 2026-04-29 (after v0.4.1 ship).

---

## Quick path: tag + push

```bash
# 1. Pick the next version per SemVer
#    - patch (v0.4.2): bug fixes only, no behavior change
#    - minor (v0.5.0): new features, backward-compatible (e.g., Phase 12 ships)
#    - major (v1.0.0): breaking changes (CLI flag rename, JSON schema break)

# 2. Roll the CHANGELOG: rename [Unreleased] → [X.Y.Z] - YYYY-MM-DD,
#    write a 1-paragraph summary, then bullet under ### Added/Changed/Fixed.
#    Keep the empty ## [Unreleased] heading at the top.

# 3. Commit the CHANGELOG roll
git add CHANGELOG.md
git commit -m "chore(release): roll CHANGELOG to vX.Y.Z"
git push origin main

# 4. Annotated tag — the multi-line message becomes the GitHub Release body
git tag -a vX.Y.Z -m "vX.Y.Z — short headline

What changed:
- bullet 1
- bullet 2"

# 5. Push tag → triggers release.yml
git push origin vX.Y.Z

# 6. Watch (4 job groups, ~2–3 min total)
gh run watch $(gh run list --workflow=Release --limit 1 --json databaseId --jq '.[0].databaseId')
```

---

## What the workflow does

The pipeline at `.github/workflows/release.yml` runs end-to-end on every `v*` tag without manual intervention:

| Job | What it does | Output |
|---|---|---|
| `release` (×3 matrix) | Cross-compiles for linux/amd64, darwin/amd64, darwin/arm64 with embedded Python engine; computes sha256 | Workflow artifacts `fendix-{linux,darwin}-{amd64,arm64}` |
| `publish` | Downloads matrix artifacts, creates engine-repo GitHub Release | <https://github.com/Abdel-RahmanSaied/Fendix/releases/tag/vX.Y.Z> |
| `docker` | Builds + pushes container image to GHCR (linux/amd64 only) | `ghcr.io/abdel-rahmansaied/fendix:X.Y.Z` and `:latest` |
| `mirror` | Creates mirror release with binaries+sha256, auto-rewrites `Formula/fendix.rb` in mirror's main with fresh SHA256s | <https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/tag/vX.Y.Z> |

The mirror exists because the engine repo is private — anonymous users can't pull from a private GitHub Releases page, so install paths are routed through the public `homebrew-fendix` mirror.

---

## After the workflow finishes

```bash
# Verify (~30 sec)
gh release view vX.Y.Z -R Abdel-RahmanSaied/Fendix
gh release view vX.Y.Z -R Abdel-RahmanSaied/homebrew-fendix
docker pull --platform linux/amd64 ghcr.io/abdel-rahmansaied/fendix:X.Y.Z
```

Optional: spot-check that `brew install fendix` (with the tap already added) picks up the new version.

No README update needed for normal patch/minor releases — the install commands in `README.md` are version-agnostic. Only update the README install section when adding a brand-new install path (e.g., `.deb`/`.rpm` in Phase 13).

---

## Versioning rules of thumb

| Bump | When | Examples from history |
|---|---|---|
| Major (`vX.0.0`) | Breaking change to anything users depend on (CLI flag removal/rename, JSON schema break, finding ID format change). Avoid until v1.0. | (not yet) |
| Minor (`v0.X.0`) | New features, backward-compatible. New CLI flag, new check type, new output format, new analyzer. | v0.4.0 = Phase 11 coverage parity |
| Patch (`v0.X.Y`) | Bug fixes, build/CI/distribution fixes, doc-only changes. No new user-visible features. | v0.4.1 = build infra fixes |

When unsure, prefer the larger bump. Cheap.

---

## Troubleshooting

### `mirror` job failed

- **First check:** is `DIST_REPO_TOKEN` still valid? Fine-grained PATs expire (max 1 year). Renew at github.com → Settings → Developer settings → Personal access tokens → Fine-grained tokens.
- **Logs:** `gh run view <id> --log-failed | grep -A 5 -i "Mirror"`
- **Re-run flow:** if it's a transient failure (rare), re-running just the failed job won't work because the mirror job uses `gh release create` which fails on duplicate tags. Easier to fix-forward: push a new commit to main with the fix, delete the tag, re-tag.

### `docker` job failed

- **Docker build error?** Likely a Dockerfile issue — read the buildx output. Test locally with `docker build .`.
- **Push 401/403?** Check that the workflow has `permissions: packages: write` (it does at workflow level).
- **Image visibility:** new packages on a private source repo default to **private**. The first time you publish a brand-new image (different repo, different name), flip it to Public via github.com → your packages → fendix → Package settings → Change visibility → Public. Existing `:latest` and `:X.Y.Z` tags don't need re-flipping.

### `release` matrix or `publish` failed

- These are the simplest jobs (just `go build` + `gh release create`). If they fail, it's usually a real build error.
- `gh run view <id> --log-failed | grep -E "FAIL|error"`
- Fix on main; either re-tag (`gh release delete vX.Y.Z --cleanup-tag --yes`, then re-tag from fixed HEAD), or cut the next patch.

### Re-tag vs. cut next patch — when to choose which

| Situation | Action |
|---|---|
| The release was never visible to anyone (no install path works) | **Re-tag.** v0.4.1's first attempt was redone this way. |
| Some users may have already pulled the broken release | **Cut next patch.** Re-tagging the same version is harmful — caches and tags propagate fast. |
| Workflow failed before any user-facing artifact was published | **Re-tag.** Cleaner history. |

To re-tag:

```bash
gh release delete vX.Y.Z -R Abdel-RahmanSaied/Fendix --cleanup-tag --yes
git tag -d vX.Y.Z
# fix on main, push, then:
git tag -a vX.Y.Z -m "..."
git push origin vX.Y.Z
```

---

## What's permanent vs. what's per-release

**One-time setup (already done; don't redo):**

- Public mirror repo: `Abdel-RahmanSaied/homebrew-fendix`
- `DIST_REPO_TOKEN` secret on engine repo (PAT with `Contents: write` on the mirror)
- GHCR package visibility set to public for `ghcr.io/abdel-rahmansaied/fendix`
- Homebrew tap usable as `brew tap Abdel-RahmanSaied/fendix`

**Every release:**

- Roll CHANGELOG, commit, tag, push, verify. That's it.

---

## Known limitations / planned improvements

These are non-blocking but worth knowing:

- **Docker `version` string is hardcoded as `docker`** — `docker run fendix version` shows `fendix version docker` instead of the real `vX.Y.Z`. Cosmetic; fix is a 1-line change in the Dockerfile to read the real version. Worth folding into the next patch.
- **linux/arm64 binary missing** — only linux/amd64, darwin/amd64, darwin/arm64 are built today. Cloud runners + Apple Silicon Mac users with Docker Desktop need `--platform linux/amd64` to pull the Docker image. Add to the matrix in Phase 13 / TASK-099.
- **No signed binaries** — Phase 13 / TASK-099 plans cosign signatures.
- **`get.fendix.dev` short-URL installer** — not set up yet. Phase 13 / TASK-100.
- **`.deb` / `.rpm` packages** — Phase 13 / TASK-100.

When any of these land, update the corresponding section of `README.md` install instructions.

---

## Discovery / awareness (the next bottleneck)

Now that anonymous installs work, the bottleneck is "no one knows Fendix exists." Some asymmetric-leverage moves:

- **Show HN post** — title + 1-paragraph hook + GitHub link to the mirror's release page. Best Tuesday or Wednesday morning ET.
- **r/devops, r/netsec** — same hook, more emphasis on hybrid scan + 16× CVE coverage on test fixtures.
- **awesome-* lists** — submit PRs to `awesome-security`, `awesome-devops-tools`, `awesome-go`. Low effort, long-tail traffic.
- **Comparison content** — "Fendix vs. ZAP/gitleaks/semgrep" blog post once you have benchmarks (Phase 13 / TASK-104).
- **Frontend marketing site** — already deployed; hook a real domain (`fendix.dev`?) to it before posting anywhere.

These are not engineering tasks but they're what turns a working tool into an adopted one.
