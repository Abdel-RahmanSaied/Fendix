#!/usr/bin/env bash
set -euo pipefail

# Fendix GitHub App — Deployment Script
#
# This script guides you through deploying the fendix-app webhook server
# to Fly.io. It's the lightest path to a publicly-reachable webhook endpoint.
#
# Prerequisites:
#   - flyctl installed (brew install flyctl)
#   - Authenticated: fly auth login
#   - A GitHub App private key PEM file
#   - Your App ID and webhook secret from the GitHub App settings
#
# Usage:
#   ./scripts/deploy-app.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Fendix GitHub App Deployment (Fly.io) ==="
echo ""

# Check prerequisites
if ! command -v fly &>/dev/null; then
    echo "ERROR: flyctl not found. Install with: brew install flyctl"
    exit 1
fi

if ! fly auth whoami &>/dev/null; then
    echo "ERROR: Not authenticated with Fly.io. Run: fly auth login"
    exit 1
fi

echo "Authenticated as: $(fly auth whoami)"
echo ""

# Collect secrets
read -rp "FENDIX_APP_ID (from GitHub App settings): " APP_ID
read -rp "Path to private-key.pem: " KEY_PATH
read -rp "FENDIX_WEBHOOK_SECRET: " WEBHOOK_SECRET

if [[ ! -f "$KEY_PATH" ]]; then
    echo "ERROR: Private key not found at: $KEY_PATH"
    exit 1
fi

echo ""
echo "--- Step 1: Launch the Fly app (first time only) ---"
echo ""

cd "$ROOT_DIR"

if fly status &>/dev/null 2>&1; then
    echo "Fly app already exists. Skipping launch."
else
    fly launch --copy-config --no-deploy --region iad
fi

echo ""
echo "--- Step 2: Set secrets ---"
echo ""

fly secrets set \
    "FENDIX_APP_ID=$APP_ID" \
    "FENDIX_APP_PRIVATE_KEY=$(cat "$KEY_PATH")" \
    "FENDIX_WEBHOOK_SECRET=$WEBHOOK_SECRET"

echo ""
echo "--- Step 3: Deploy ---"
echo ""

fly deploy

echo ""
echo "--- Step 4: Verify ---"
echo ""

APP_URL="$(fly status --json | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'https://{d[\"Name\"]}.fly.dev')" 2>/dev/null || echo "https://<your-app>.fly.dev")"

echo "Healthcheck:"
curl -sf "$APP_URL/healthz" && echo " OK" || echo " (may take a moment to boot)"

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Next steps:"
echo "  1. Go to your GitHub App settings"
echo "  2. Set Webhook URL to: $APP_URL/webhook"
echo "  3. GitHub will send a 'ping' event — check logs with: fly logs"
echo "  4. Install the App on your repos and open a PR to test"
echo ""
echo "Useful commands:"
echo "  fly logs          — stream webhook handler logs"
echo "  fly status        — check machine status"
echo "  fly deploy        — redeploy after code changes"
echo "  fly secrets list  — list configured secrets"
