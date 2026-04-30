# `get.fendix.dev` — mirror-repo bootstrap

This directory holds the static files that need to live in the
[`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix)
mirror repo so that GitHub Pages can serve `https://get.fendix.dev`.

The engine repo's `.github/workflows/release.yml` syncs these files into
the mirror on every `v*` tag (alongside the existing Formula sync) — so
the canonical source is here, in this repo, and the mirror is regenerated
each release.

## Files

| File          | Purpose                                                           |
|---------------|-------------------------------------------------------------------|
| `CNAME`       | Tells GitHub Pages to bind `get.fendix.dev` as the custom domain. |
| `.nojekyll`   | Skips Jekyll processing — files go up unchanged, faster builds.   |
| `index.html`  | Browser landing page when someone visits `https://get.fendix.dev/`. Static, no JS, dark-mode friendly. |

The `install.sh` script lives at `scripts/install.sh` in the engine repo
and is also synced to the mirror root by the same release job. Together
those four files make the curl one-liner work.

## One-time operator actions (required to go live)

These are not code changes; they need to happen once on the operator's
GitHub account and DNS provider. Run **after** the next release tag has
synced these files into the mirror, or commit them into the mirror by
hand to bootstrap.

### 1. DNS records at your registrar (the one that owns `fendix.dev`)

Add a `CNAME` record on the `fendix.dev` zone:

```
get   CNAME   abdel-rahmansaied.github.io.
```

(Note the trailing dot in the value — required by most DNS UIs that
accept FQDNs.)

If your registrar requires an `A` record at the apex instead of a CNAME
on a subdomain, GitHub Pages also accepts these IPs at the apex:

```
185.199.108.153
185.199.109.153
185.199.110.153
185.199.111.153
```

For `get.fendix.dev` specifically — a subdomain — the `CNAME` form above
is the right call.

### 2. Enable GitHub Pages on the mirror repo

In the mirror repo settings (`Settings` → `Pages`):

- **Source:** "Deploy from a branch"
- **Branch:** `main`
- **Folder:** `/ (root)`
- **Custom domain:** `get.fendix.dev` (Pages will read this from the
  `CNAME` file once the next release lands; setting it manually first
  surfaces propagation errors sooner)
- **Enforce HTTPS:** check this box once the cert provisions
  (5–60 minutes after DNS propagates)

GitHub auto-provisions a Let's Encrypt cert for the custom domain — no
manual cert work. `.dev` is HTTPS-only by Google policy, so this is
mandatory.

### 3. Verify

After DNS propagates (usually 1–10 minutes; up to 24h worst-case):

```bash
# DNS resolves
dig +short get.fendix.dev
# Expected: a CNAME chain ending at <username>.github.io.

# HTTPS works
curl -I https://get.fendix.dev/install.sh
# Expected: HTTP/2 200, content-type something like text/x-shellscript or text/plain

# Smoke-test the install pipe (in a throwaway VM!)
curl -fsSL https://get.fendix.dev/install.sh | sh
```

Once the smoke test passes, the engine repo can swap the README +
`docs/install.md` URLs to `https://get.fendix.dev/install.sh` in a single
follow-up PR (already drafted on a branch — see the open PR for the
cutover).

## Why these files don't live in the engine repo's GitHub Pages

The mirror repo (`homebrew-fendix`) is the public-facing artifact host —
binaries, Homebrew formula, install script. The engine repo is private
and ships nothing user-facing on its own. Pointing `get.fendix.dev` at
the mirror keeps the trust chain clean: every artifact a user
downloads — binary, package, install script — lives in the same
public, signed, auditable repo.
