#!/usr/bin/env bash
# set-token.sh — (re)set the CF_BROKER_TOKEN secret on a deployed broker, no redeploy.
# Reads the worker name from the wrangler config (via `-c`). Usage:
#   ./set-token.sh wrangler.my-instance.jsonc
set -euo pipefail
config="${1:?usage: ./set-token.sh <wrangler-config.jsonc>}"
[ -f "$config" ] || { echo "✗ config not found: $config" >&2; exit 1; }
dir="$(cd "$(dirname "$0")" && pwd)"
echo "→ paste the ~40-char Cloudflare API token for the worker in $config (input hidden):"
"$dir/wr" secret put CF_BROKER_TOKEN -c "$config"
echo "✓ CF_BROKER_TOKEN set — re-run the apply dry-run to verify the mint works"
