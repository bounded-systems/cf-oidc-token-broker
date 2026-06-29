# cf-oidc-token-broker

**GitHub Actions OIDC → short-lived, scoped Cloudflare API tokens.** A ~200-line Cloudflare
Worker that lets your CI authenticate to the Cloudflare API with **no stored Cloudflare secret in
GitHub** — it proves identity with a GitHub OIDC token instead.

Cloudflare's API [doesn't support GitHub OIDC federation yet](https://community.cloudflare.com/t/openid-connect-authentication-for-cloudflare-api/492897),
so this Worker is the bridge: it verifies the Actions OIDC JWT against GitHub's JWKS, pins
owner/repo/workflow, and mints a least-privilege, short-lived Cloudflare token for that one run.
When Cloudflare ships native OIDC, delete the broker and consume the OIDC token directly.

```
GitHub Action (permissions: id-token: write)
   │  requests an OIDC JWT, aud = GH_AUDIENCE
   │  POST { Authorization: Bearer <jwt> }  →  broker Worker
   ▼
broker:  verify JWT vs GitHub JWKS (RS256, alg-pinned)
         pin  iss · aud · exp/nbf/iat · repository_owner · repository · job_workflow_ref
         derive scope (read, or environment-gated "edit")
         mint a Cloudflare API token (least-privilege policy, expires_on = +10 min)
   │  { token, expires_on, scope }
   ▼
Action exports the token → uses it against the Cloudflare API for that run only
```

## Why

- **No Cloudflare secret in GitHub.** The Action holds nothing; it proves identity via OIDC.
- The only powerful credential — `CF_BROKER_TOKEN` (token-minting) — lives as a **Worker Secret in
  Cloudflare**, reachable only behind the broker's OIDC check.
- Minted tokens are **per-run, scoped, and short-lived** (10 min) — a leak is bounded.
- **Two tiers:** a low-privilege "read" workflow, and an optional "edit" workflow that only gets
  the elevated token when its job entered a **reviewer-gated GitHub Environment** (a claim GitHub
  signs — it can't be forged).

## How it works (the trust boundary)

`src/index.mjs` is the whole thing. `verifyOIDC` + the token policy are the entire trust boundary:

- **RS256 pinned before verify** — rejects `alg: none`/`HS256` algorithm confusion outright.
- **Real signature check** against GitHub's JWKS (cached, refetched once on `kid` rotation).
- **Full claim pinning** — `iss`, `aud`, `exp`/`nbf`/`iat` (with skew), `repository_owner`,
  `repository`, and `job_workflow_ref`. The workflow ref includes `@refs/heads/main`, so a token
  from any PR or branch is rejected.
- **Environment-gated edit** — `deriveEdit` grants the elevated scope only when the edit workflow
  presents the configured `environment` claim (i.e. it passed required-reviewer approval).
- **Fail-closed policy** — `policyFor` throws (→ 500, never a token) if any zone/scope var is
  missing. No wildcard, no placeholder scope.

Everything is configured via Worker vars (below), so you deploy it for your repo without editing
code. The one part you adapt is `policyFor` — it decides *what* Cloudflare scope gets minted. The
shipped example mints **DNS-as-code** tokens (read = Zone/DNS/Workers reads; edit = + DNS edit).

## Configure (Worker vars)

| Var | Purpose |
|---|---|
| `GH_AUDIENCE` | the OIDC `aud` your workflow requests |
| `GH_OWNER` / `GH_REPOSITORY` | pinned `repository_owner` / `repository` |
| `READ_WORKFLOW_REF` | the read workflow's `job_workflow_ref` (e.g. `owner/repo/.github/workflows/snapshot.yml@refs/heads/main`) |
| `EDIT_WORKFLOW_REF` / `EDIT_ENVIRONMENT` | optional; the edit workflow + its reviewer-gated Environment. Leave empty for a read-only broker |
| `CF_ACCOUNT_ID`, `CF_ZONE_IDS` | the account + comma-separated zone ids minted tokens are pinned to |
| `CF_PG_*` | Cloudflare permission-group ids (global constants; see `wrangler.jsonc`) |

Secret (never in git): `CF_BROKER_TOKEN` — see Deploy.

## Deploy

```sh
# 1) Create a Cloudflare API token with "API Tokens: Edit" + the scopes you want to delegate
#    (for the DNS example: DNS:Edit on your zones). This is CF_BROKER_TOKEN.
npx wrangler secret put CF_BROKER_TOKEN

# 2) Fill in wrangler.jsonc vars (trust pins + CF_* policy). The CF_PG_* ids are global constants;
#    confirm with:  curl .../user/tokens/permission_groups  (run with the master token)

# 3) Deploy, then set the repo variable CF_BROKER_URL to the printed *.workers.dev URL.
npx wrangler deploy
```

Or use the helper, which deploys, prompts for the secret, and wires `CF_BROKER_URL` on the repo
named in the config (bootstraps node via `nix` if `npx` isn't on PATH):

```sh
./deploy.sh wrangler.my-instance.jsonc
```

In your consumer workflow, request the OIDC token and POST it to the broker:

```yaml
permissions:
  id-token: write
steps:
  - name: Get a scoped Cloudflare token from the broker
    run: |
      oidc=$(curl -sf "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=cf-oidc-token-broker" \
        -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" | jq -r .value)
      tok=$(curl -sf -X POST "${{ vars.CF_BROKER_URL }}" -H "Authorization: Bearer $oidc" | jq -r .token)
      echo "::add-mask::$tok"
      echo "CLOUDFLARE_API_TOKEN=$tok" >> "$GITHUB_ENV"
```

## Verify

- **Unit tests** (no network/secrets): `node --test src/index.test.mjs` — also runs in CI.
- **Live rejection/liveness:** `.github/workflows/broker-e2e.yml` (manual; dormant until
  `CF_BROKER_URL` is set) asserts `GET → 405`, tampered `→ 401`, wrong-aud `→ 401`.
- **Positive mint** is proven by your real consumer workflow succeeding.

## Security

Read [`SECURITY.md`](./SECURITY.md) before relying on this. Highlights: the endpoint is public
(security rests on JWT validation — add a rate-limit rule), and `CF_BROKER_TOKEN` is
**account-admin-equivalent** (`API Tokens: Edit` can mint up to the account owner's full scope), so
treat it as an incident-grade secret: Worker-Secret-only, rotate it, minimize exposure.

## License

MIT — see [`LICENSE`](./LICENSE).
