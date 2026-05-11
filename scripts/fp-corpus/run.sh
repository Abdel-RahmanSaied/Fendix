#!/usr/bin/env bash
# Fendix FP-corpus runner (TASK-122).
#
# Scans a curated set of targets and writes raw JSON output to
# fp-corpus-results/<timestamp>/. Human review then classifies each
# finding as TP or FP and updates tasks/FP_CORPUS.md.
#
# Targets:
#   - fendix-self      : python/ tree of this repo (test fixtures inside;
#                        used to validate that the scanner finds its own
#                        intentional vulns, AND surfaces the "test
#                        fixture as prod finding" FP pattern)
#   - juice-shop       : OWASP Juice Shop v17.1.1 (passive blackbox scan
#                        against http://localhost:3000; same image as the
#                        TASK-106 benchmark)
#
# Usage:
#   scripts/fp-corpus/run.sh [TARGET...]
#
#   Defaults to all targets when none specified.
#
# Output: fp-corpus-results/<UTC-timestamp>/<target>.json plus a
# combined summary.json listing finding counts per target.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FENDIX_BIN="${FENDIX_BIN:-$REPO_ROOT/bin/fendix}"
OUTDIR="$REPO_ROOT/fp-corpus-results/$(date -u +%Y-%m-%dT%H-%M-%SZ)"

mkdir -p "$OUTDIR"

log() { printf '\033[36m→\033[0m %s\n' "$*"; }
fail() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

[ -x "$FENDIX_BIN" ] || fail "fendix binary not found at $FENDIX_BIN — set FENDIX_BIN or run 'make build'"

# ─── target: fendix-self ───────────────────────────────────────────────
# Scans this repo's own python/ tree. Most findings will be from
# tests/fixtures/ (intentional vulns) — the FP pattern is "test fixture
# flagged as prod finding," which is the dominant FP class for any user
# scanning a repo that includes test code.
scan_fendix_self() {
  local out="$OUTDIR/fendix-self.json"
  log "scan: fendix-self (python/ tree, $REPO_ROOT)"
  "$FENDIX_BIN" scan --code "$REPO_ROOT/python" --format json --output "$out" \
    >"$OUTDIR/fendix-self.stderr" 2>&1 || true
  python3 -c "import json; d=json.load(open('$out')); print(f'  → {d[\"total\"]} findings, {d[\"summary\"]}')"
}

# ─── target: juice-shop (blackbox) ─────────────────────────────────────
# Spins up juice-shop in Docker, runs a passive scan, captures findings.
# Re-uses the same image as scripts/benchmark/run-juice-shop.sh for
# parity with TASK-106. NOT --enable-active: that surfaces juice-shop's
# real vulns; for FP corpus purposes we want passive findings that
# correspond to noise (missing headers etc.) the user might consider FPs.
scan_juice_shop() {
  local out="$OUTDIR/juice-shop.json"
  local name="fendix-fp-juice-shop"
  local img="bkimminich/juice-shop:v17.1.1"

  log "scan: juice-shop (blackbox passive, $img)"
  command -v docker >/dev/null 2>&1 || { log "  skip: docker not available"; return; }

  docker rm -f "$name" >/dev/null 2>&1 || true
  trap 'docker rm -f '"$name"' >/dev/null 2>&1 || true' EXIT
  docker run -d --name "$name" -p 3000:3000 "$img" >/dev/null

  # Wait for juice-shop to be ready (it boots in ~30s).
  local i=0
  until curl -sf http://localhost:3000/ >/dev/null 2>&1; do
    sleep 2
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
      docker rm -f "$name" >/dev/null 2>&1 || true
      fail "juice-shop did not become healthy in 120s"
    fi
  done

  "$FENDIX_BIN" scan --url http://localhost:3000 --format json --output "$out" \
    >"$OUTDIR/juice-shop.stderr" 2>&1 || true
  python3 -c "import json; d=json.load(open('$out')); print(f'  → {d[\"total\"]} findings, {d[\"summary\"]}')"

  docker rm -f "$name" >/dev/null 2>&1 || true
  trap - EXIT
}

# ─── main ──────────────────────────────────────────────────────────────
TARGETS=("$@")
if [ "${#TARGETS[@]}" -eq 0 ]; then
  TARGETS=(fendix-self juice-shop)
fi

for t in "${TARGETS[@]}"; do
  case "$t" in
    fendix-self) scan_fendix_self ;;
    juice-shop)  scan_juice_shop ;;
    *) fail "unknown target: $t (known: fendix-self juice-shop)" ;;
  esac
done

log "done — results in $OUTDIR"
log "review: see tasks/FP_CORPUS.md for classification methodology"
