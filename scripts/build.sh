#!/bin/bash
# Fendix build script — produces a single Go binary with embedded Python engine.
#
# Usage:
#   ./scripts/build.sh              # Build for current platform
#   ./scripts/build.sh v1.0.0       # Build with specific version

set -euo pipefail

VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo "dev")}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "→ Building Fendix ${VERSION}..."

cd "$PROJECT_ROOT"

# 1. Bundle Python engine into Go embed directory
echo "  Bundling Python engine..."
make embed-engine

# 2. Build Go binary
echo "  Compiling Go binary..."
cd go
go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o "../bin/fendix" \
    ./cmd/fendix/

cd "$PROJECT_ROOT"
echo "✓ Built: bin/fendix ($(du -h bin/fendix | awk '{print $1}'))"
echo ""
bin/fendix version
