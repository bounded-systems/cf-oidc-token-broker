// cf-oidc-token-broker — GitHub Actions OIDC → short-lived, scoped Cloudflare API token.
//
// Cloudflare's API cannot validate a GitHub OIDC token itself, so this tiny Worker does it: it
// verifies the Actions OIDC JWT against GitHub's JWKS, PINS the allowed owner/repo/workflow (with
// an optional environment-gated "edit" tier), then mints a least-privilege, short-lived Cloudflare
// API token. No long-lived Cloudflare secret ever lives in GitHub — the only powerful credential
// (token-minting) is env.CF_BROKER_TOKEN, a Worker Secret that lives here in Cloudflare.
//
// ⚠️ SECURITY-CRITICAL. verifyOIDC + the token policy are the entire trust boundary. See
// SECURITY.md. The trust pins are read from Worker vars (loadConfig) so this broker is reusable
// across repos without editing code; the token policy (policyFor) is the one part you adapt to
// your own Cloudflare scope needs.

export const GH_ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = `${GH_ISSUER}/.well-known/jwks`;
const TOKEN_TTL_MS = 10 * 60 * 1000;

// Trust policy — read from Worker vars (set per deployment; see wrangler.jsonc + README).
// A request is only honored if it comes from this owner/repo and one of the allowed workflows.
export function loadConfig(env) {
  const need = (k) => {
    const v = env[k];
    if (!v) throw new Error(`${k} not configured`);
    return v;
  };
  return {
    audience: need("GH_AUDIENCE"),
    owner: need("GH_OWNER"),
    repository: need("GH_REPOSITORY"),
    // Low-privilege "read" tier — the workflow ref allowed to mint a read token. Required.
    readWorkflowRef: need("READ_WORKFLOW_REF"),
    // Optional high-privilege "edit" tier: granted ONLY to this workflow AND only when GitHub
    // asserts the job entered this protected Environment (i.e. it passed required-reviewer
    // approval). Leave both unset for a read-only broker.
    editWorkflowRef: env.EDIT_WORKFLOW_REF || null,
    editEnvironment: env.EDIT_ENVIRONMENT || null,
  };
}

const b64urlToBytes = (s) => {
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const b64urlToJSON = (s) => JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));

let jwksCache = null, jwksAt = 0;
// Production JWKS source: GitHub's real JWKS, cached an hour, refetchable on a `kid` miss.
// Exposed as the default seam for verifyOIDC; tests inject a mock in its place.
async function fetchGitHubJwks(force = false) {
  if (!force && jwksCache && Date.now() - jwksAt < 3_600_000) return jwksCache;
  const r = await fetch(JWKS_URL);
  if (!r.ok) throw new Error("jwks fetch failed");
  jwksCache = (await r.json()).keys;
  jwksAt = Date.now();
  return jwksCache;
}

// `verifyOIDC` is the entire trust boundary. `config` comes from loadConfig(env). The two seams
// (getJwks, nowMs) default to production behavior — GitHub's live JWKS and the wall clock — and
// are overridable ONLY for tests; no check is relaxed.
export async function verifyOIDC(jwt, config, { getJwks = fetchGitHubJwks, nowMs = Date.now } = {}) {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("malformed jwt");
  const [h, p, sig] = parts;
  const header = b64urlToJSON(h);
  const payload = b64urlToJSON(p);

  // Pin the algorithm: only RS256, the alg GitHub signs with. Defeats alg-confusion
  // (e.g. "none"/HS256) regardless of the verify step.
  if (header.alg !== "RS256") throw new Error("unexpected alg");

  // Find the signing key by kid; refetch JWKS once on a miss (handles key rotation).
  let jwk = (await getJwks()).find((k) => k.kid === header.kid);
  if (!jwk) jwk = (await getJwks(true)).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("unknown signing key");

  const pub = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", pub, b64urlToBytes(sig), new TextEncoder().encode(`${h}.${p}`),
  );
  if (!ok) throw new Error("bad signature");

  const now = Math.floor(nowMs() / 1000);
  if (payload.iss !== GH_ISSUER) throw new Error("bad iss");
  // `aud` may be a string or an array — require our audience to be present.
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(config.audience)) throw new Error("bad aud");
  if (typeof payload.exp !== "number" || payload.exp < now) throw new Error("expired");
  if (typeof payload.iat === "number" && payload.iat > now + 60) throw new Error("iat in future");
  if (typeof payload.nbf === "number" && payload.nbf > now) throw new Error("not yet valid");

  if (payload.repository_owner !== config.owner) throw new Error("owner not allowed");
  if (payload.repository !== config.repository) throw new Error("repository not allowed");
  const allowedRefs = [config.readWorkflowRef, ...(config.editWorkflowRef ? [config.editWorkflowRef] : [])];
  if (!allowedRefs.includes(payload.job_workflow_ref)) throw new Error("workflow not allowed");
  return payload;
}

// Scope from the ENVIRONMENT claim, not the workflow filename: edit only for the edit workflow
// run that entered the reviewer-gated Environment. Everything else — including that workflow's
// dry-run path (which does not enter the environment) — falls back to read-only.
export function deriveEdit(claims, config) {
  return !!(
    config.editWorkflowRef && config.editEnvironment &&
    claims.job_workflow_ref === config.editWorkflowRef &&
    claims.environment === config.editEnvironment
  );
}

// Cloudflare token policy — zone-pinned, least-privilege. THIS is the part you adapt to your
// needs; the example below is "DNS-as-code" (read = snapshot, edit = apply). Fails CLOSED: if any
// required config is missing it THROWS rather than minting an over-scoped token (no `zone.*`
// wildcard, no placeholder groups). Permission-group ids are global Cloudflare constants supplied
// as Worker vars (GET /user/tokens/permission_groups).
//
//   read: Zone Read + DNS Read on the pinned zones — PLUS, only if their permission-group vars
//         are set, Workers Routes Read (zone) and Workers Scripts Read (ACCOUNT scope, since
//         workers/scripts is an account endpoint). Omit those vars for a DNS-only (apply-only)
//         deployment and the read token stays minimal.
//   edit: Zone Read + DNS Read + DNS Edit on the pinned zones.
export function policyFor(edit, env) {
  const zoneIds = (env.CF_ZONE_IDS || "").split(",").map((z) => z.trim()).filter(Boolean);
  if (zoneIds.length === 0) throw new Error("CF_ZONE_IDS not configured");
  const accountId = env.CF_ACCOUNT_ID;
  if (!accountId) throw new Error("CF_ACCOUNT_ID not configured");
  const group = (v) => {
    const id = env[v];
    if (!id) throw new Error(`${v} not configured`);
    return { id };
  };
  const optGroup = (v) => (env[v] ? { id: env[v] } : null); // additive scope; omit the var to skip it
  const zoneResources = {};
  for (const z of zoneIds) zoneResources[`com.cloudflare.api.account.zone.${z}`] = "*";

  if (edit) {
    return [{
      effect: "allow",
      resources: zoneResources,
      permission_groups: [group("CF_PG_ZONE_READ"), group("CF_PG_DNS_READ"), group("CF_PG_DNS_EDIT")],
    }];
  }
  // read tier: Zone + DNS read always; Workers reads only when their vars are configured.
  const zonePerms = [group("CF_PG_ZONE_READ"), group("CF_PG_DNS_READ")];
  const routesRead = optGroup("CF_PG_WORKERS_ROUTES_READ");
  if (routesRead) zonePerms.push(routesRead);
  const policies = [{ effect: "allow", resources: zoneResources, permission_groups: zonePerms }];
  const scriptsRead = optGroup("CF_PG_WORKERS_SCRIPTS_READ");
  if (scriptsRead) {
    policies.push({
      effect: "allow",
      resources: { [`com.cloudflare.api.account.${accountId}`]: "*" },
      permission_groups: [scriptsRead],
    });
  }
  return policies;
}

// Cloudflare's token API requires second-precision ISO-8601 ("2005-12-30T01:02:03Z") and REJECTS
// the millisecond form that Date#toISOString() emits ("...:03.524Z"). Strip the millis.
export const isoSeconds = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

export default {
  async fetch(req, env) {
    if (req.method !== "POST") return new Response("POST only\n", { status: 405 });
    const jwt = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!jwt) return new Response("unauthorized\n", { status: 401 });

    let config;
    try {
      config = loadConfig(env);
    } catch (e) {
      console.error(`broker misconfigured: ${e.message}`);
      return new Response("broker misconfigured\n", { status: 500 });
    }

    let claims;
    try {
      claims = await verifyOIDC(jwt, config);
    } catch (e) {
      // Log the specific reason server-side; return a generic message (no oracle for attackers).
      console.warn(`oidc rejected: ${e.message}`);
      return new Response("unauthorized\n", { status: 401 });
    }

    const edit = deriveEdit(claims, config);

    // Build the least-privilege policy; a misconfigured broker fails closed (500), never minting.
    let policies;
    try {
      policies = policyFor(edit, env);
    } catch (e) {
      console.error(`broker misconfigured: ${e.message}`);
      return new Response("broker misconfigured\n", { status: 500 });
    }

    const now = Date.now();
    let mint, text;
    try {
      mint = await fetch("https://api.cloudflare.com/client/v4/user/tokens", {
        method: "POST",
        headers: { Authorization: `Bearer ${env.CF_BROKER_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({
          name: `oidc-${claims.repository}-${edit ? "edit" : "read"}-${Math.floor(now / 1000)}`,
          policies,
          not_before: isoSeconds(now),
          expires_on: isoSeconds(now + TOKEN_TTL_MS),
        }),
      });
      text = await mint.text();
    } catch (e) {
      // Network error reaching Cloudflare — fail closed, never leak.
      console.error(`mint fetch failed: ${e.message}`);
      return new Response("mint failed\n", { status: 502 });
    }
    let j;
    try {
      j = JSON.parse(text);
    } catch {
      // Cloudflare returned a non-JSON body — log the status + a snippet so misconfig is debuggable.
      console.error(`mint non-JSON (HTTP ${mint.status}): ${text.slice(0, 200)}`);
      return new Response("mint failed\n", { status: 502 });
    }
    if (!j.success) {
      console.warn(`mint failed (HTTP ${mint.status}): ${JSON.stringify(j.errors)}`);
      return new Response("mint failed\n", { status: 502 });
    }

    return new Response(JSON.stringify({ token: j.result.value, expires_on: j.result.expires_on, scope: edit ? "edit" : "read" }), {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
