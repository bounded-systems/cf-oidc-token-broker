# cf-oidc-token-broker — security

The JWT verification + token scoping in `src/index.mjs` are the **entire trust boundary**. Anyone
on the internet can POST to the Worker; security rests on these checks. Review them before relying
on the broker.

## What the boundary enforces

- **F1 — edit scope is gated on approval, not a filename.** The elevated "edit" token is granted
  only when `job_workflow_ref == EDIT_WORKFLOW_REF` **and** the `environment` claim ==
  `EDIT_ENVIRONMENT`. GitHub only sets `environment` after the job enters that protected
  Environment (i.e. it passed required-reviewer approval). A dry-run of the edit workflow (which
  doesn't enter the Environment) correctly gets read-only.
- **F2 — algorithm pinned.** Rejects any `alg != "RS256"` before verifying — defeats `none`/HS256
  algorithm confusion independent of the verify step. The public key is imported as RS256
  regardless of the JWK's own `alg`.
- **F3 — `aud` shape.** Handles `aud` as string or array; requires the configured audience present.
- **F4 — owner + repo + workflow pinned.** `repository_owner`, `repository`, and `job_workflow_ref`
  are all checked. The workflow ref includes `@refs/heads/main`, so a token minted by any PR or
  non-main branch is rejected.
- **F5 — no error oracle.** 401s are generic ("unauthorized"); the specific reason is logged
  server-side only, so an attacker can't probe which check failed.
- **F6 — clock + freshness.** Checks `exp`, `nbf`, and a sanity bound on `iat`. The minted token
  gets `not_before` + `expires_on` (10 min) and the response is `cache-control: no-store`.
- **F7 — JWKS rotation.** Refetches GitHub's JWKS once on an unknown `kid` (fails closed otherwise).
- **F8 — fail-closed scope.** `policyFor` throws (→ 500, never a token) if any zone/scope var is
  unset. No `zone.*` wildcard, no placeholder permission group.

The trust boundary is unit-tested in `src/index.test.mjs` (Node's built-in runner). Tests mint
their own RS256 keypair, serve it as a mock JWKS, freeze the clock, and assert the valid path plus
every rejection (alg `none`/`HS256`, wrong aud, tampered/flipped signature, wrong repo/owner/iss,
expired/`nbf`/`iat`, unknown `kid`, malformed JWT, disallowed workflow ref) and every scope branch.

## Residual risks / hardening

- **R1 — replay within the JWT window.** The OIDC JWT has no single-use guarantee; a captured
  token can be replayed until its `exp` (minutes) to mint multiple short-lived tokens. Bounded by
  the short TTL + tight scope. For single-use, track `jti` in KV / a Durable Object.
- **R2 — public endpoint + JWKS-refetch amplification.** Anyone can POST; security rests entirely
  on JWT validation. `verifyOIDC` also force-refetches GitHub's JWKS on any unknown `kid` (before
  signature verify), so unauthenticated `alg:RS256` + random-`kid` POSTs can make the broker hammer
  GitHub's JWKS per request. **Add a Cloudflare rate-limit rule** on the route. (Cloudflare Access
  can't cleanly gate it — the Actions auth *is* the bearer JWT, not an Access login.)
- **R3 — token over-scope.** Closed in code: `policyFor` is fail-closed and zone-pinned (see F8).
  When you adapt `policyFor` for your own scope, keep it least-privilege and avoid wildcards.
- **R4 — master credential blast radius (account-wide).** `CF_BROKER_TOKEN` has `API Tokens: Edit`.
  Cloudflare does **not** limit a created token to the *creating* token's other permissions —
  `API Tokens: Edit` can mint tokens up to the **account owner's full scope**. So a leaked
  `CF_BROKER_TOKEN` is effectively **account-admin-equivalent**, not bounded to what your policy
  mints. There is no Cloudflare-native cap on this, so: keep it a **Worker Secret only** (never in
  git/GitHub), reachable only behind the OIDC gate; **rotate** it; minimize exposure; treat any
  suspected leak as a full-account incident.

## Verdict

Design is sound — fixed-RS256 verify + full claim pinning + environment-gated scope + fail-closed
least-privilege policy, with unit coverage and a live rejection/liveness e2e. Before relying on it
in production: run `broker-e2e.yml` once (green), add the **R2 rate-limit rule**, and treat **R4**
(`CF_BROKER_TOKEN`) as incident-grade. R1 (replay) is optional `jti` hardening.

## Reporting

Found an issue in the trust boundary? Open an issue, or for anything sensitive, contact the
maintainer privately rather than filing publicly.
