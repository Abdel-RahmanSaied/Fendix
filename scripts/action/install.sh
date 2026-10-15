#!/usr/bin/env bash
# Install step of the composite Action (action.yml "Install Fendix").
#
# The Action owns this installation contract: the release comes from the
# official repository, its cosign signature MUST verify (there is no
# checksum-only path), and later steps see the binary only after every check
# below has passed. Cosign is installed by the step before this one.
#
#   VERSION      the version input: an exact release tag, or latest
#   ACTION_PATH  github.action_path, to find the bundled installer
#   RUNNER_TEMP / GITHUB_PATH   provided by the runner
#
# Order: resolve one exact tag -> run the installer bundled with this Action
# revision (it verifies the checksum, then the signature, and only then
# installs and first runs the binary) -> check the exact version of the binary
# at its private path -> publish that private directory to $GITHUB_PATH.
set -euo pipefail

OFFICIAL_REPO="Fendix-app/Fendix"
# vX.Y.Z with an optional pre-release (the project publishes v3.5.0-rc.2 and
# v1.2.0-rc1). Never the moving v1 tag or the fendix-app-* image tags.
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'

fail() {
  local message=${1//%/%25}
  message=${message//$'\r'/%0D}
  echo "::error title=Fendix install::${message//$'\n'/%0A}"
  exit 1
}

[ -n "${RUNNER_TEMP:-}" ] || fail "RUNNER_TEMP is not set; this script runs inside the composite Action"
[ -f "${ACTION_PATH:-}/scripts/install.sh" ] || fail "the bundled installer was not found under the Action path"

# --- 1. One exact release tag -------------------------------------------------
requested=${VERSION:-latest}
if [ "$requested" = "latest" ]; then
  # Resolved exactly once, against the official repository only.
  release=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${OFFICIAL_REPO}/releases/latest") \
    || fail "could not resolve 'latest' from https://api.github.com/repos/${OFFICIAL_REPO}/releases/latest"
  tag=$(printf '%s\n' "$release" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
  [[ $tag =~ $TAG_RE ]] || fail "the latest release of ${OFFICIAL_REPO} did not name an exact release tag (got '${tag}')"
  echo "latest resolved to ${tag}"
else
  tag=$requested
  [[ $tag =~ $TAG_RE ]] || fail "version must be an exact release tag such as v3.6.1, or latest (got '${requested}')"
fi

# --- 2. The bundled installer, in an environment the Action controls ----------
# A unique private directory: no sudo, nothing left in /usr/local/bin on a
# self-hosted runner, and no other fendix on PATH can stand in for this one.
dir=$(mktemp -d "${RUNNER_TEMP%/}/fendix-bin.XXXXXXXX")
curl_home=$(mktemp -d "${RUNNER_TEMP%/}/fendix-curl.XXXXXXXX")
published=0
# On any failure nothing usable is left behind: not even a binary that
# failed the version check, though it was never published.
cleanup() {
  rm -rf "$curl_home"
  [ "$published" = 1 ] || rm -rf "$dir"
}
trap cleanup EXIT

# No inherited FENDIX_* variable reaches the installer: none can change the
# source repository, the signer it expects, the install directory or the
# version, or weaken verification (FENDIX_ALLOW_UNVERIFIED, FENDIX_SHA256).
# FENDIX_SIGN_REPO stays unset so the installer keeps its own historical
# signer selection for older releases. A private CURL_HOME keeps a .curlrc
# from changing its downloads. The process-local PATH lets the installer's
# own post-install check run the binary it just installed.
clean_env=()
while IFS= read -r name; do
  clean_env+=(-u "$name")
done < <(compgen -e | grep '^FENDIX_' || true)

echo "Installing Fendix ${tag} from ${OFFICIAL_REPO} with the bundled installer (signature required) into ${dir}"
env "${clean_env[@]}" \
  FENDIX_REPO="$OFFICIAL_REPO" \
  FENDIX_VERSION="$tag" \
  FENDIX_DIR="$dir" \
  FENDIX_REQUIRE_SIGNATURE=1 \
  CURL_HOME="$curl_home" \
  PATH="${dir}:${PATH}" \
  sh "${ACTION_PATH}/scripts/install.sh" \
  || fail "Fendix ${tag} was not installed: the bundled installer refused it (see its output above). The Action never installs a release whose checksum and cosign signature do not both verify."

# --- 3. The exact release, at the private path --------------------------------
binary="${dir}/fendix"
[ -x "$binary" ] || fail "the installer reported success but ${binary} is not an executable file"
output=$("$binary" version 2>/dev/null) || fail "${binary} version failed"
reported=${output%%$'\n'*}
actual=$(printf '%s\n' "$reported" | sed -n 's/^fendix version \([^ ]*\) (.*$/\1/p')
[ "$actual" = "$tag" ] || fail "requested Fendix ${tag} but the installed binary reports '${reported}'"
if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$binary")
else
  digest=$(shasum -a 256 "$binary")
fi
echo "Verified Fendix ${tag} at ${binary} (sha256 ${digest%% *})"

# --- 4. Only now do later steps see it ----------------------------------------
echo "$dir" >>"$GITHUB_PATH"
published=1
