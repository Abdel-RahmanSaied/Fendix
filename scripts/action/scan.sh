#!/usr/bin/env bash
# Local-mode scan step of the composite Action (action.yml "Run Fendix scan").
#
# Inputs arrive as environment variables and are never interpolated into this
# script: CODE URL SPEC FAIL_ON FORMAT OUTPUT DIFF EXTRA_ARGS.
#
# Writes to $GITHUB_OUTPUT:
#   report-present  false before the scan starts; true only when OUTPUT then
#                   exists and is non-empty. Never inferred from the exit code.
#   report          the OUTPUT path
#   exit-code       the fendix exit code (2 when the scan could not start)
#
# Always exits 0. The job is decided by the gate step (enforce.sh), which runs
# after the SARIF upload so findings are visible even when the gate fails.
set -uo pipefail

echo "report-present=false" >>"$GITHUB_OUTPUT"

# A newline in the path would let the value write outputs of its own.
case "$OUTPUT" in
  *$'\n'* | *$'\r'*)
    echo "::error title=Fendix::The output input must be a single-line path."
    echo "exit-code=2" >>"$GITHUB_OUTPUT"
    exit 0
    ;;
esac

args=()
[ -n "$CODE" ] && args+=(--code "$CODE")
[ -n "$URL" ] && args+=(--url "$URL")
[ -n "$SPEC" ] && args+=(--spec "$SPEC")
[ -n "$FAIL_ON" ] && args+=(--fail-on "$FAIL_ON")
args+=(--format "$FORMAT" --output "$OUTPUT")

# Diff-aware scoping. On a pull_request event, 'auto'/'true' scope the scan to
# files changed versus the PR base ref. Requires fetch-depth: 0 on checkout.
if [ "$DIFF" = "true" ] || { [ "$DIFF" = "auto" ] && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; }; then
  base="${GITHUB_BASE_REF:-}"
  if [ -n "$base" ]; then
    git fetch --no-tags --depth=1 origin "$base" 2>/dev/null || true
    args+=(--diff="origin/$base")
  else
    args+=(--diff)
  fi
fi

# shellcheck disable=SC2206  # intentional word-split into multiple flags
[ -n "$EXTRA_ARGS" ] && args+=($EXTRA_ARGS)

# A file left at OUTPUT by an earlier step must not pass for this scan's report.
rm -f -- "$OUTPUT"

# %q keeps every argument on this one log line, whatever it contains.
printf 'fendix scan'
printf ' %q' "${args[@]}"
printf '\n'
fendix scan "${args[@]}"
code=$?

present=false
[ -s "$OUTPUT" ] && present=true
{
  echo "report=$OUTPUT"
  echo "exit-code=$code"
  echo "report-present=$present"
} >>"$GITHUB_OUTPUT"
exit 0
