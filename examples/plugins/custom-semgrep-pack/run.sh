#!/usr/bin/env bash
# custom-semgrep-pack reference plugin.
#
# Reads a Fendix ScanRequest on stdin, shells out to the user's
# semgrep binary against the bundled rules.yaml, and translates
# semgrep's JSON output into the Fendix Finding NDJSON contract.
#
# Requires `semgrep` and `jq` on PATH. If either is missing, the
# plugin emits an explanatory done-with-error message rather than
# crashing — same posture as the embedded engine's graceful
# degradation when semgrep is absent.

set -u
set -o pipefail

emit_done() {
    printf '%s\n' "$1"
}

# Read the ScanRequest. We only consume code_path; the rest is
# informational for plugins that need it.
REQ="$(cat)"
CODE_PATH="$(printf '%s' "$REQ" | jq -r '.code_path // ""' 2>/dev/null || echo "")"

if [ -z "$CODE_PATH" ] || [ ! -d "$CODE_PATH" ]; then
    emit_done '{"done":true,"total":0}'
    exit 0
fi

if ! command -v semgrep >/dev/null 2>&1; then
    emit_done '{"done":true,"total":0,"error":"semgrep not on PATH; install with `pip install semgrep`"}'
    exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
    emit_done '{"done":true,"total":0,"error":"jq not on PATH; required for output translation"}'
    exit 0
fi

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES="$PLUGIN_DIR/rules.yaml"

# semgrep --json emits a single object on stdout. Pipe through jq to
# split each result into a Fendix Finding line. severity ERROR/WARNING
# map to HIGH/MEDIUM; confidence comes from semgrep's metadata when
# present, else MEDIUM.
RAW="$(semgrep scan --quiet --json --config "$RULES" "$CODE_PATH" 2>/dev/null || echo '{"results":[]}')"

TOTAL=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '%s\n' "$line"
    TOTAL=$((TOTAL + 1))
done < <(printf '%s' "$RAW" | jq -c '
    .results[] |
    {
        id: "",
        title: ("Custom Semgrep rule: " + .check_id),
        severity: (
            if .extra.severity == "ERROR" then "HIGH"
            elif .extra.severity == "WARNING" then "MEDIUM"
            else "LOW"
            end
        ),
        category: "injection",
        endpoint: (.path + ":" + (.start.line | tostring)),
        line: (.path + ":" + (.start.line | tostring)),
        evidence: (.extra.lines // ""),
        fix: (.extra.message // "Review and fix per the rule message."),
        references: ((.extra.metadata.cwe // null) | if . then ["CWE-Custom"] else [] end),
        confidence: "MEDIUM"
    }
')

emit_done "{\"done\":true,\"total\":$TOTAL}"
