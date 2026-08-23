#!/usr/bin/env bash
set -e

# Script to upload all environment secrets to Cloudflare Pages via Wrangler CLI
PROJECT_NAME="${1:-fire-crow}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="$SCRIPT_DIR/cf_secrets.json"

if [ ! -f "$SECRETS_FILE" ]; then
    echo "❌ Error: Secrets file not found at $SECRETS_FILE"
    exit 1
fi

echo "🚀 Uploading environment secrets to Cloudflare Pages project '$PROJECT_NAME'..."
npx wrangler pages secret bulk "$SECRETS_FILE" --project-name="$PROJECT_NAME"

echo "✅ Successfully uploaded secrets to Cloudflare Pages project '$PROJECT_NAME'."
