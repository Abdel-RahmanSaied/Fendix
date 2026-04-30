#!/usr/bin/env bash
# Fendix benchmark runner — OWASP Juice Shop.
#
# Spins up juice-shop in Docker, runs `fendix scan` against it, captures
# findings + timing into a structured results directory. Cleans up the
# container on exit (success or failure).
#
# Usage:
#   scripts/benchmark/run-juice-shop.sh [OUTPUT_DIR]
#
# OUTPUT_DIR defaults to bench-results/juice-shop/<timestamp>/.
#
# Requirements on the host:
#   - Docker daemon running
#   - fendix on PATH (or set FENDIX_BIN=/path/to/fendix)
#   - jq for JSON parsing
#   - curl
#
# Designed to run in GitHub Actions ubuntu-latest (Docker + jq +
# curl preinstalled) and on a developer macOS laptop with Docker
# Desktop.

set -euo pipefail

# ─── Config ────────────────────────────────────────────────────────────
JS_IMAGE="bkimminich/juice-shop:v17.1.1"  # pinned for reproducible numbers
JS_PORT="${JS_PORT:-3000}"
JS_NAME="fendix-bench-juice-shop"
JS_HEALTH_TIMEOUT="${JS_HEALTH_TIMEOUT:-120}"  # seconds

FENDIX_BIN="${FENDIX_BIN:-fendix}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-300}"  # max seconds for the fendix scan

OUTPUT_DIR="${1:-bench-results/juice-shop/$(date -u +%Y-%m-%dT%H-%M-%SZ)}"

# ─── Helpers ───────────────────────────────────────────────────────────
log()  { printf '\033[36m→\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

cleanup() {
    if docker ps -a --format '{{.Names}}' | grep -q "^${JS_NAME}$"; then
        log "stopping juice-shop container..."
        docker rm -f "$JS_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ─── Pre-flight ────────────────────────────────────────────────────────
require docker
require curl
require jq
require "$FENDIX_BIN"

mkdir -p "$OUTPUT_DIR"
log "output dir: $OUTPUT_DIR"

# Stop any leftover container from a prior run
cleanup

# ─── Start juice-shop ──────────────────────────────────────────────────
log "starting $JS_IMAGE on :$JS_PORT..."
docker run -d \
    --name "$JS_NAME" \
    --rm \
    -p "$JS_PORT:3000" \
    "$JS_IMAGE" >/dev/null

log "waiting up to ${JS_HEALTH_TIMEOUT}s for juice-shop to be ready..."
deadline=$(( $(date +%s) + JS_HEALTH_TIMEOUT ))
while true; do
    if curl -sf --max-time 2 "http://localhost:${JS_PORT}/rest/admin/application-version" >/dev/null 2>&1; then
        log "juice-shop ready"
        break
    fi
    if [ "$(date +%s)" -gt "$deadline" ]; then
        docker logs "$JS_NAME" > "$OUTPUT_DIR/juice-shop.log" 2>&1 || true
        fail "juice-shop did not become ready within ${JS_HEALTH_TIMEOUT}s; see $OUTPUT_DIR/juice-shop.log"
    fi
    sleep 2
done

# ─── Run fendix scan ───────────────────────────────────────────────────
log "running fendix scan (max ${SCAN_TIMEOUT}s)..."
SCAN_START=$(date +%s)

# We capture to JSON for parseability. HTML is generated separately
# from the JSON via `fendix report` if the consumer wants it.
set +e
timeout "$SCAN_TIMEOUT" "$FENDIX_BIN" scan \
    --url "http://localhost:${JS_PORT}" \
    --format json \
    --output "$OUTPUT_DIR/findings.json" \
    >"$OUTPUT_DIR/scan.stdout" \
    2>"$OUTPUT_DIR/scan.stderr"
SCAN_EXIT=$?
set -e

SCAN_END=$(date +%s)
SCAN_DURATION=$(( SCAN_END - SCAN_START ))

if [ "$SCAN_EXIT" -ne 0 ] && [ "$SCAN_EXIT" -ne 1 ]; then
    # exit 1 = findings at fail-on threshold (expected); anything
    # else = a real scan error.
    warn "fendix exited non-zero ($SCAN_EXIT); check $OUTPUT_DIR/scan.stderr"
fi

# ─── Parse + summarize ─────────────────────────────────────────────────
if [ ! -f "$OUTPUT_DIR/findings.json" ]; then
    fail "no findings.json produced; scan likely crashed before writing output"
fi

FENDIX_VERSION=$("$FENDIX_BIN" version 2>/dev/null | head -1 || echo "unknown")

jq -n \
    --arg target "OWASP Juice Shop" \
    --arg image "$JS_IMAGE" \
    --arg fendix_version "$FENDIX_VERSION" \
    --argjson scan_duration_seconds "$SCAN_DURATION" \
    --argjson scan_exit_code "$SCAN_EXIT" \
    --slurpfile report "$OUTPUT_DIR/findings.json" \
    '{
        target: $target,
        target_image: $image,
        fendix_version: $fendix_version,
        scan_duration_seconds: $scan_duration_seconds,
        scan_exit_code: $scan_exit_code,
        timestamp: (now | todateiso8601),
        total_findings: ($report[0].findings | length),
        by_severity: ($report[0].summary // {}),
        by_source: ($report[0].sources // {}),
        endpoints_scanned: ($report[0].metadata.endpoints_scanned // 0)
    }' >"$OUTPUT_DIR/summary.json"

# ─── Print human-readable summary ──────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════"
echo "  Fendix benchmark — OWASP Juice Shop"
echo "═══════════════════════════════════════════════════════════════"
jq -r '
    "  Fendix version:          " + .fendix_version,
    "  Target image:            " + .target_image,
    "  Scan duration (seconds): " + (.scan_duration_seconds | tostring),
    "  Scan exit code:          " + (.scan_exit_code | tostring),
    "  Endpoints scanned:       " + (.endpoints_scanned | tostring),
    "  Total findings:          " + (.total_findings | tostring),
    "",
    "  By severity:",
    "    CRITICAL: " + ((.by_severity.critical // 0) | tostring),
    "    HIGH:     " + ((.by_severity.high     // 0) | tostring),
    "    MEDIUM:   " + ((.by_severity.medium   // 0) | tostring),
    "    LOW:      " + ((.by_severity.low      // 0) | tostring),
    "    INFO:     " + ((.by_severity.info     // 0) | tostring),
    "",
    "  By source:",
    "    correlated: " + ((.by_source.correlated // 0) | tostring),
    "    blackbox:   " + ((.by_source.blackbox   // 0) | tostring),
    "    whitebox:   " + ((.by_source.whitebox   // 0) | tostring)
' "$OUTPUT_DIR/summary.json"
echo "═══════════════════════════════════════════════════════════════"
echo "  Full results: $OUTPUT_DIR/"
echo
