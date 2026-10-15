#!/usr/bin/env bash
# Local-mode gate of the composite Action (action.yml "Enforce fail-on
# threshold"). The scan's exit code alone decides the job: reporting steps
# never do, and a value this script cannot read fails closed.
#
#   EXIT_CODE       steps.scan.outputs.exit-code, empty when the scan never ran
#   FAIL_ON         the fail-on input, named in the BLOCK message
#   REPORT          the output input
#   REPORT_PRESENT  steps.scan.outputs.report-present
#   SARIF_UPLOAD    outcome of the SARIF upload step (success, failure, skipped)
set -u

# Escape a value for a workflow-command line, so it can never end the line
# and start a command of its own.
esc() {
  local s=${1//%/%25}
  s=${s//$'\r'/%0D}
  printf '%s' "${s//$'\n'/%0A}"
}

report_note() {
  if [ "${REPORT_PRESENT:-}" = "true" ]; then
    printf ' Report: %s.' "$(esc "${REPORT:-}")"
  else
    printf ' No report was written.'
  fi
  if [ "${SARIF_UPLOAD:-}" = "success" ]; then
    printf ' The SARIF report was uploaded to GitHub code scanning.'
  fi
}

code=${EXIT_CODE:-}
case "$code" in
  "")
    echo "::error title=Fendix did not run::A setup step failed before the scan, so there is no result to enforce. See the first failed step above."
    exit 2
    ;;
  0)
    echo "✓ Fendix: no finding reached BLOCK status.$(report_note)"
    exit 0
    ;;
  1)
    echo "::error title=Fendix policy BLOCK::At least one finding reached BLOCK status (fail-on: $(esc "${FAIL_ON:-not set}")). See the scan log above.$(report_note)"
    exit 1
    ;;
  2)
    echo "::error title=Fendix scan error::The scan did not complete (fendix exited 2). See the scan log above for the cause.$(report_note)"
    exit 2
    ;;
  *)
    echo "::error title=Fendix gate::Unexpected scan exit code '$(esc "$code")'; failing closed. See the scan log above."
    exit 2
    ;;
esac
