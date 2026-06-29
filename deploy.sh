#!/usr/bin/env bash
# deploy.sh — deploy one cf-oidc-token-broker instance, set its minting secret, and (best-effort)
# wire CF_BROKER_URL on the GitHub repo it serves.
#
#   ./deploy.sh <wrangler-config.jsonc>
#
# Reads everything from the config (worker name via `-c`, GH_REPOSITORY for the var). Bootstraps
# node via `nix` if `npx` isn't already on PATH. Prompts once (hidden) for the master token.
set -euo pipefail

config="${1:?usage: ./deploy.sh <wrangler-config.jsonc>}"
[ -f "$config" ] || { echo "✗ config not found: $config" >&2; exit 1; }

# Don't let a stray read-only token shadow your wrangler login.
unset CLOUDFLARE_API_TOKEN 2>/dev/null || true

# Run wrangler — prefer an on-PATH npx, else bootstrap node through nix.
wr() {
  if command -v npx >/dev/null 2>&1; then
    npx --yes wrangler "$@"
  elif command -v nix >/dev/null 2>&1; then
    nix shell nixpkgs#nodejs --command npx --yes wrangler "$@"
  else
    echo "✗ need node/npx (or nix) on PATH" >&2; exit 1
  fi
}

echo "→ deploying broker from $config"
out="$(wr deploy -c "$config")"
printf '%s\n' "$out" | tail -n 4
url="$(printf '%s\n' "$out" | grep -oE 'https://[a-z0-9.-]+\.workers\.dev' | head -1 || true)"

echo "→ paste the master token for this broker (input hidden):"
wr secret put CF_BROKER_TOKEN -c "$config"

# Wire CF_BROKER_URL on the repo named in the config (GH_REPOSITORY), best-effort.
repo="$(grep -oE '"GH_REPOSITORY"[[:space:]]*:[[:space:]]*"[^"]+"' "$config" | grep -oE '"[^"]+"$' | tr -d '"' || true)"
if [ -n "${url:-}" ] && [ -n "${repo:-}" ] && command -v gh >/dev/null 2>&1; then
  gh variable set CF_BROKER_URL --repo "$repo" --body "$url" && echo "✓ set CF_BROKER_URL=$url on $repo"
else
  echo "ℹ set CF_BROKER_URL yourself — url='${url:-?}' repo='${repo:-?}'"
fi

echo "✓ done: $config"
