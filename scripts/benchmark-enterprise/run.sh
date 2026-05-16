#!/usr/bin/env bash
# Sprint 16 — enterprise benchmark runner.
#
# Compares fendix vs. semgrep vs. bandit on a shared Python SAST fixture.
# Produces a markdown table on stdout and writes RESULTS.md next to this
# script for the CI job-summary step.
#
# Honesty constraint: this measures Python SAST on a single 100-LOC
# fixture. It does NOT measure DAST (only fendix), cross-language SAST
# (varies wildly by rule pack), or coverage on real-world projects.
# The fixture README documents every labeled vuln.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURE="${1:-${SCRIPT_DIR}/fixtures/python-vulns}"
RESULTS="${SCRIPT_DIR}/RESULTS.md"

if [[ ! -d "$FIXTURE" ]]; then
    echo "fixture dir not found: $FIXTURE" >&2
    exit 1
fi

MANIFEST="${FIXTURE}/manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
    echo "manifest not found: $MANIFEST" >&2
    exit 1
fi

# Detect GNU `time` for peak-RSS reporting. macOS `/usr/bin/time -v`
# is BSD time and ignores -v silently; install GNU time via:
#   brew install gnu-time   (macOS)
#   apt install time         (Debian/Ubuntu)
TIME_BIN=""
if command -v gtime >/dev/null 2>&1; then
    TIME_BIN="gtime"
elif /usr/bin/time -v true >/dev/null 2>&1; then
    TIME_BIN="/usr/bin/time"
fi

PY="${PYTHON:-python3}"

run_tool() {
    # run_tool <name> <reads-json-from-stdout?> <cmd...>
    # On success, emits one line to stdout: NAME|WALL_SEC|RSS_KB|EXIT|OUTFILE
    local name="$1"; shift
    local cmd_argv=("$@")
    local out
    out=$(mktemp)
    local stderr_out
    stderr_out=$(mktemp)

    local start_ns end_ns elapsed_ns
    start_ns=$(date +%s%N 2>/dev/null || $PY -c 'import time;print(int(time.time()*1e9))')

    local exit_code=0
    if [[ -n "$TIME_BIN" ]]; then
        # -v emits "Elapsed (wall clock) time" + "Maximum resident set size"
        "$TIME_BIN" -v "${cmd_argv[@]}" >"$out" 2>"$stderr_out" || exit_code=$?
    else
        "${cmd_argv[@]}" >"$out" 2>"$stderr_out" || exit_code=$?
    fi

    end_ns=$(date +%s%N 2>/dev/null || $PY -c 'import time;print(int(time.time()*1e9))')
    elapsed_ns=$((end_ns - start_ns))
    local elapsed_sec
    elapsed_sec=$($PY -c "print(f'{$elapsed_ns/1e9:.2f}')")

    local rss_kb=""
    if [[ -n "$TIME_BIN" ]]; then
        rss_kb=$(grep -E 'Maximum resident set size' "$stderr_out" 2>/dev/null | awk -F': ' '{print $2}' || true)
    fi
    rss_kb="${rss_kb:-NA}"

    echo "${name}|${elapsed_sec}|${rss_kb}|${exit_code}|${out}"
}

# Compute TP/FP counts via a Python helper that reads the tool's output
# (fendix JSON, semgrep --json, bandit -f json) plus the manifest line
# numbers, and emits "TP=X FP=Y" on stdout.
score_output() {
    local tool="$1"
    local outfile="$2"
    "$PY" "${SCRIPT_DIR}/score.py" --tool "$tool" --manifest "$MANIFEST" --output "$outfile"
}

# ---------------------------------------------------------------------------
# Build the table
# ---------------------------------------------------------------------------
echo "## Enterprise benchmark — Python SAST"
echo ""
echo "Fixture: \`$FIXTURE\`"
echo ""
echo "**Scope:** apples-to-apples comparison of three Python-aware SAST"
echo "tools on the same ~100-LOC fixture. Does NOT measure DAST"
echo "coverage (only fendix), JS coverage (semgrep), or general-purpose"
echo "SAST against a customer's full repo. See"
echo "\`fixtures/python-vulns/README.md\` for the labeled vulnerabilities."
echo ""
echo "| Tool | Wall-clock (s) | Peak RSS (KB) | TP / 5 | FP / 5 | Notes |"
echo "|---|---:|---:|---:|---:|---|"

# Fendix
FENDIX_BIN="${FENDIX_BIN:-${REPO_ROOT}/bin/fendix}"
if [[ -x "$FENDIX_BIN" ]]; then
    line=$(run_tool fendix "$FENDIX_BIN" scan --code "$FIXTURE" --format json)
    IFS='|' read -r _name wall rss exit_code outfile <<< "$line"
    tp_fp=$(score_output fendix "$outfile" || echo "TP=NA FP=NA")
    tp=$(echo "$tp_fp" | awk -F'TP=' '{print $2}' | awk '{print $1}')
    fp=$(echo "$tp_fp" | awk -F'FP=' '{print $2}' | awk '{print $1}')
    echo "| fendix | ${wall} | ${rss} | ${tp} | ${fp} | exit ${exit_code} |"
else
    echo "| fendix | n/a | n/a | n/a | n/a | binary not at ${FENDIX_BIN}; build with \`make build\` |"
fi

# Semgrep (optional)
if command -v semgrep >/dev/null 2>&1; then
    line=$(run_tool semgrep semgrep --config auto --json --quiet "$FIXTURE")
    IFS='|' read -r _name wall rss exit_code outfile <<< "$line"
    tp_fp=$(score_output semgrep "$outfile" || echo "TP=NA FP=NA")
    tp=$(echo "$tp_fp" | awk -F'TP=' '{print $2}' | awk '{print $1}')
    fp=$(echo "$tp_fp" | awk -F'FP=' '{print $2}' | awk '{print $1}')
    echo "| semgrep | ${wall} | ${rss} | ${tp} | ${fp} | \`--config auto\` |"
else
    echo "| semgrep | skipped | skipped | skipped | skipped | not on PATH |"
fi

# Bandit — Python-only
if command -v bandit >/dev/null 2>&1; then
    line=$(run_tool bandit bandit -r "$FIXTURE" -f json -q)
    IFS='|' read -r _name wall rss exit_code outfile <<< "$line"
    tp_fp=$(score_output bandit "$outfile" || echo "TP=NA FP=NA")
    tp=$(echo "$tp_fp" | awk -F'TP=' '{print $2}' | awk '{print $1}')
    fp=$(echo "$tp_fp" | awk -F'FP=' '{print $2}' | awk '{print $1}')
    echo "| bandit | ${wall} | ${rss} | ${tp} | ${fp} | Python-only |"
else
    echo "| bandit | skipped | skipped | skipped | skipped | not on PATH (\`pip install bandit\`) |"
fi

echo ""
echo "_Generated by \`scripts/benchmark-enterprise/run.sh\`. TP = labeled vulnerable line in the manifest; FP = finding on a safe-but-similar line._"
