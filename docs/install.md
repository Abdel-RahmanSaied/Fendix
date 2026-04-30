# Installing Fendix

This page covers every supported install path. The README's
[Quick Start](../README.md#installation) section points at the most common
ones; this document is the canonical reference for ops shops that need to
choose between them or want signature-verification details.

> Engine source lives in this repo; install artifacts (binaries, packages,
> Homebrew formula, install script) are mirrored to the public install repo
> at [`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix)
> on every `v*` tag. Every download path below pulls from the mirror.

---

## Choose a path

| You want… | Use |
|---|---|
| One command on a developer laptop (macOS or Linux) | [Homebrew](#homebrew-macos--linux) |
| One command on a CI runner (POSIX) | [`install.sh`](#install-script-curl--sh) |
| `apt install` / `apt upgrade` integration on Debian/Ubuntu | [.deb package](#debian--ubuntu-deb) |
| `dnf install` / `yum install` integration on RHEL/Fedora | [.rpm package](#rhel--fedora--centos-rpm) |
| Containers, no host install | [Docker](#docker) |
| Pinned, signature-verified, reproducible install | [Manual binary download](#manual-binary-download) + [cosign verification](#verifying-release-artifacts-cosign) |
| Building from source | [Build from source](#build-from-source) |

---

## Homebrew (macOS / Linux)

```bash
brew tap Abdel-RahmanSaied/fendix
brew install fendix
```

The formula auto-selects the right binary for your arch (Apple Silicon vs
Intel; arm64 Linux vs amd64 Linux). Updates land via `brew upgrade fendix`
once the next release tag mirrors.

## Install script (curl | sh)

```bash
curl -fsSL https://raw.githubusercontent.com/Abdel-RahmanSaied/homebrew-fendix/main/install.sh | sh
```

Downloads the latest release binary, verifies its sha256 checksum, and
installs to `/usr/local/bin/fendix`. Override:

- `FENDIX_DIR=$HOME/.local/bin` — install to a user-writable directory.
- `FENDIX_VERSION=v0.5.0` — pin a specific version.
- `FENDIX_REPO=...` — pull from a fork or private mirror.

Sudo is requested only if `FENDIX_DIR` isn't writable.

A short-URL installer at `https://get.fendix.dev` is on track for v1.0;
see [`get.fendix.dev` rollout](#getfendixdev-rollout-status) below.

## Debian / Ubuntu (.deb)

```bash
# Pick the right architecture for your host
ARCH=$(dpkg --print-architecture)         # amd64 or arm64
VERSION=v0.5.0                            # latest release at time of install
URL="https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${ARCH}.deb"

# Download + verify + install
curl -fsSL -o fendix.deb "${URL}"
curl -fsSL -o fendix.deb.sha256 "${URL}.sha256"
sha256sum -c fendix.deb.sha256
sudo dpkg -i fendix.deb
sudo apt-get install -f       # pull in python3 if it isn't already there
```

The package depends on `python3` and recommends `semgrep` (for deeper
white-box coverage). All Fendix files land under `/usr/bin/fendix` plus
docs in `/usr/share/doc/fendix/`.

Uninstall with `sudo apt-get remove fendix` (or `dpkg -r`).

## RHEL / Fedora / CentOS (.rpm)

```bash
ARCH=$(uname -m)                          # x86_64 or aarch64
case "$ARCH" in
  x86_64)  PKG_ARCH=amd64 ;;
  aarch64) PKG_ARCH=arm64 ;;
esac
VERSION=v0.5.0
URL="https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${PKG_ARCH}.rpm"

curl -fsSL -o fendix.rpm "${URL}"
curl -fsSL -o fendix.rpm.sha256 "${URL}.sha256"
sha256sum -c fendix.rpm.sha256
sudo dnf install ./fendix.rpm   # or: sudo rpm -i ./fendix.rpm
```

Note: nfpm builds Fendix `.rpm` files using the canonical Go-style arch in
the *filename* (`amd64`/`arm64`) but the rpm metadata reports the rpm-side
canonical arch (`x86_64`/`aarch64`) — `dnf install` matches on the
metadata side, so a `*-amd64.rpm` will install fine on `x86_64` hosts.

Uninstall with `sudo dnf remove fendix`.

## Docker

```bash
docker pull ghcr.io/abdel-rahmansaied/fendix:latest
docker run --rm ghcr.io/abdel-rahmansaied/fendix scan --url https://api.example.com
```

The image is multi-arch (linux/amd64 + linux/arm64); `docker pull` picks
the right one. Python and the white-box analyzer are baked in, so hybrid
mode works out of the box.

## Manual binary download

Pick a binary for your platform from the
[latest release](https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/latest)
(linux/amd64, linux/arm64, darwin/amd64, darwin/arm64), verify the
matching `.sha256` file, and place it on your PATH:

```bash
VERSION=v0.5.0
URL="https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}/fendix-${VERSION}-darwin-arm64"

curl -fsSL -o fendix "${URL}"
curl -fsSL -o fendix.sha256 "${URL}.sha256"
shasum -a 256 -c fendix.sha256

chmod +x fendix
sudo mv fendix /usr/local/bin/fendix
fendix version
```

## Build from source

Requires Go 1.21+ and Python 3.9+.

```bash
git clone https://github.com/Abdel-RahmanSaied/Fendix.git
cd Fendix
make build
./bin/fendix version
```

The white-box engine needs Python at runtime:

```bash
pip install -r python/requirements.txt
```

---

## Verifying release artifacts (cosign)

When `COSIGN_ENABLED=true` is set on the engine repo, every release
ships `.sig` + `.crt` sidecar files alongside each binary, `.deb`, `.rpm`,
and Docker image. Verification is keyless via Sigstore Fulcio — no static
public key to distribute.

Verify a binary:

```bash
cosign verify-blob \
  --certificate fendix-v0.6.0-linux-amd64.crt \
  --signature   fendix-v0.6.0-linux-amd64.sig \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-v0.6.0-linux-amd64
```

Verify a `.deb` or `.rpm` package (same pattern, swap the asset name):

```bash
cosign verify-blob \
  --certificate fendix-v0.6.0-linux-amd64.deb.crt \
  --signature   fendix-v0.6.0-linux-amd64.deb.sig \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-v0.6.0-linux-amd64.deb
```

Verify the Docker image (signs the multi-arch manifest digest):

```bash
cosign verify ghcr.io/abdel-rahmansaied/fendix:v0.6.0 \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Releases cut **before** `COSIGN_ENABLED=true` rolled out won't have these
sidecars — fall back to the `.sha256` file for those. See
[`SECURITY.md`](../SECURITY.md) for the broader artifact-trust policy.

---

## `get.fendix.dev` rollout status

The plan: `curl -fsSL https://get.fendix.dev | sh` becomes the canonical
one-liner. Today the equivalent works via the
[install script](#install-script-curl--sh) at
`raw.githubusercontent.com`.

The short URL is gated on three operator actions, none of which require
code changes:

1. **Domain registration** for `fendix.dev` (or just the `get.` subdomain
   delegated through the registrar).
2. **GitHub Pages** enabled on the
   [`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix)
   mirror, serving `install.sh` from the repo root at
   `abdel-rahmansaied.github.io/homebrew-fendix/install.sh`.
3. **DNS CNAME** `get.fendix.dev → abdel-rahmansaied.github.io` plus a
   `CNAME` file in the mirror repo so GitHub Pages binds the custom
   domain.

When all three are in place, the README + this doc swap the install URL
to `https://get.fendix.dev` in a single PR.

---

## Troubleshooting

**`fendix: command not found` after install.sh.**
Add `/usr/local/bin` to your `PATH`, or set `FENDIX_DIR=$HOME/.local/bin`
and re-run the installer.

**`Couldn't resolve host 'github.com'` from `apt`/`dnf`.**
The `.deb` / `.rpm` paths above download from GitHub Releases; corporate
networks may need a proxy. Use the `Manual binary download` path with
`curl --proxy …` instead.

**Hybrid scans skip white-box findings with `python3 not found`.**
Install Python 3.9+. The `.deb` and `.rpm` packages declare `python3` as
a dependency, so `apt-get install -f` (or `dnf install --setopt=install_weak_deps=False`)
should pull it in. Manual installs need it too.

**Cosign verify fails with "no matching signatures".**
Either the release predates `COSIGN_ENABLED=true` rolling out, or the
`.crt`/`.sig` filenames don't match the asset filename. Check that the
release page shows the sidecar files; if it doesn't, verify by sha256
instead.
