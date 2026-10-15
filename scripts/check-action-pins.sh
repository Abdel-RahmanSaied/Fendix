#!/bin/sh
# SHA-pin policy (docs/threat-model.md §T6): every executable `uses:` line
# in the given files must name a full 40-character commit SHA. A tag or a
# branch (@v4, @v4.38.3, @main) can be moved by the action's owner to new
# code; a commit SHA cannot. Local actions (`uses: ./…`) are exempt, and
# YAML comment lines are ignored because they never run.
#
#   check-action-pins.sh FILE...    exit 1 listing every unpinned line
#   check-action-pins.sh --self-test
#                                   plant floating references and prove
#                                   the check rejects each one
set -eu

check() {
  unpinned=$(grep -EHn '^[[:space:]]*(-[[:space:]]+)?uses:' "$@" \
    | grep -Ev "^[^:]+:[0-9]+:[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[\"']?([^[:space:]\"'@#]+@[0-9a-f]{40}|\./[^[:space:]\"']*)[\"']?([[:space:]]|$)" \
    || true)
  if [ -n "$unpinned" ]; then
    printf '%s\n' "$unpinned"
    echo "::error::Found a uses: line not pinned to a 40-char commit SHA. Pin it as owner/repo@<sha> # vX.Y.Z (see docs/threat-model.md §T6)." >&2
    return 1
  fi
}

self_test() {
  t=$(mktemp -d)
  trap 'rm -rf "$t"' EXIT
  printf '      - uses: actions/checkout@v4\n' >"$t/major-tag.yml"
  printf '      uses: github/codeql-action/upload-sarif@v4.38.3\n' >"$t/full-tag.yml"
  printf '      - uses: some/action@main\n' >"$t/branch.yml"
  printf '      uses: github/codeql-action/upload-sarif@24c5418\n' >"$t/short-sha.yml"
  printf '      uses: "some/action@v1"\n' >"$t/quoted-tag.yml"
  printf '      uses: some/action\n' >"$t/no-ref.yml"
  rejected=0
  for f in major-tag full-tag branch short-sha quoted-tag no-ref; do
    if check "$t/$f.yml" >/dev/null 2>&1; then
      echo "sha-pin self-test FAILED: $f.yml was accepted" >&2
      exit 1
    fi
    rejected=$((rejected + 1))
  done
  cat >"$t/pinned.yml" <<'EOF'
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
      - uses: "actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830"
      - uses: ./
#   - uses: actions/checkout@v4   (a comment: never executed)
EOF
  if ! check "$t/pinned.yml" >/dev/null 2>&1; then
    echo "sha-pin self-test FAILED: pinned.yml was rejected" >&2
    exit 1
  fi
  echo "sha-pin self-test passed ($rejected floating references rejected, pinned file accepted)"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi
[ "$#" -gt 0 ] || { echo "usage: $0 FILE... | --self-test" >&2; exit 2; }
check "$@"
echo "✓ every uses: line in $# file(s) is pinned to a commit SHA"
