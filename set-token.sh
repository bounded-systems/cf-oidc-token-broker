#!/usr/bin/env bash
# set-token.sh — verify a Cloudflare API token, then set it as CF_BROKER_TOKEN on the broker
# named in a wrangler config (no redeploy). Refuses to set an invalid token.
#   ./set-token.sh wrangler.my-instance.jsonc
set -euo pipefail
config="${1:?usage: ./set-token.sh <wrangler-config.jsonc>}"
[ -f "$config" ] || { echo "✗ config not found: $config" >&2; exit 1; }
dir="$(cd "$(dirname "$0")" && pwd)"

printf 'paste the Cloudflare API token (input hidden): '
read -rs TOK; echo
[ -n "${TOK:-}" ] || { echo "✗ empty token" >&2; exit 1; }

echo "→ verifying token with Cloudflare…"
status="$(curl -s "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer $TOK" | jq -r '.result.status // "invalid"')"
if [ "$status" != "active" ]; then
  echo "✗ token is NOT valid (status: $status)." >&2
  echo "  Roll the token in the Cloudflare dashboard (API Tokens → … → Roll) and copy the fresh value." >&2
  unset TOK; exit 1
fi
echo "✓ token valid (active) — setting secret…"
printf '%s' "$TOK" | "$dir/wr" secret put CF_BROKER_TOKEN -c "$config"
unset TOK
echo "✓ CF_BROKER_TOKEN set on the broker in $config — re-run the apply dry-run to confirm"
