#!/bin/sh
# Regenerate python/requirements.lock: the hash-locked dependency set the
# composite Action installs for a Fendix release's own Python engine tree.
#
# python/requirements.txt is the declaration; the lock is derived from it.
# Regenerating is a deliberate maintenance step (it takes about 20 minutes):
# run it whenever requirements.txt changes and before a release, never in CI.
# CI only validates the committed lock (python/tests/test_requirements_lock.py).
#
# Resolution runs for the runner the Action targets, CPython 3.11 on
# linux/amd64, in a digest-pinned image with a pinned pip-tools. Pins already in
# the lock are kept unless requirements.txt forces a change; --upgrade
# re-resolves everything to the newest versions the declaration allows.
#
#   sh scripts/release/regenerate-python-lock.sh [--upgrade]
set -eu

IMAGE="docker.io/library/python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce"
PIP_TOOLS="pip-tools==7.6.2"
MARK="# Resolved from python/requirements.txt sha256:"

root=$(cd "$(dirname "$0")/../.." && pwd)
upgrade=""
[ "${1:-}" = "--upgrade" ] && upgrade="--upgrade"

docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" --env HOME=/tmp \
  --volume "$root/python:/work" --workdir /work "$IMAGE" sh -c "
    python -m venv /tmp/tools &&
    /tmp/tools/bin/pip install --quiet --disable-pip-version-check '$PIP_TOOLS' &&
    /tmp/tools/bin/pip-compile --quiet --generate-hashes --allow-unsafe --strip-extras $upgrade \
      --output-file requirements.lock requirements.txt"

# Record the declaration this lock was resolved from, so the lock test fails
# when requirements.txt changes without a regeneration.
if command -v sha256sum >/dev/null 2>&1; then
  sum=$(sha256sum "$root/python/requirements.txt")
else
  sum=$(shasum -a 256 "$root/python/requirements.txt")
fi
sum=${sum%% *}
tmp=$(mktemp)
{
  echo "$MARK$sum"
  grep -v "^$MARK" "$root/python/requirements.lock"
} >"$tmp"
mv "$tmp" "$root/python/requirements.lock"
echo "python/requirements.lock regenerated from requirements.txt sha256:$sum"
