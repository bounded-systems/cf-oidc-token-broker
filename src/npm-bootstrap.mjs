// npm-bootstrap-vendor — GitHub Actions OIDC → the npm bootstrap token.
//
// A SIBLING of index.mjs, deliberately not a route on it. It reuses `verifyOIDC` — the entire
// trust boundary, already audited — and nothing else.
//
// ⚠️ THIS WORKER VENDS A LONG-LIVED SECRET. index.mjs MINTS short-lived, least-privilege
// Cloudflare tokens: a leak there is bounded to ten minutes by construction. Here there is no
// minting API to call and no TTL to set — npm has no equivalent of Cloudflare's token endpoint —
// so what comes back is the stored credential itself. Serving that from index.mjs would have
// quietly falsified the invariant that repo documents, which is why this is its own entrypoint,
// its own Secret and its own deployment.
//
// ── WHY IT EXISTS AT ALL ─────────────────────────────────────────────────────
// npm cannot attach a trusted publisher to a package that does not exist — there is no settings
// page for an unpublished name — so the FIRST publish of a new package cannot authenticate via
// OIDC (npm/cli#8544). Verified rather than assumed, on bdelanghe/brand: the run packs the
// tarball, signs provenance to Sigstore, and only then the registry refuses the PUT with
//
//     npm error 404 Not Found - PUT https://registry.npmjs.org/@bdelanghe%2fbrand
//
// So every new package needs exactly one token-authenticated publish. This vends that token to a
// workflow that has proved its identity, so it never lives in GitHub.
//
// ── DELETE THIS WORKER WHEN ──────────────────────────────────────────────────
// npm/cli#8544 closes (OIDC can create a package), or npm retires direct publish from 2FA-bypass
// tokens around January 2027 — whichever comes first. It is scaffolding for a registry
// limitation, not a permanent capability.
import { verifyOIDC } from "./index.mjs";

// Trust policy. Deliberately NOT loadConfig(): that one pins a single GH_REPOSITORY, and this
// deployment serves several (each new package bootstraps once). The allow-list IS the trust
// boundary here, which is precisely why it is a separate Worker rather than a widened pin on the
// existing one.
export function loadBootstrapConfig(env) {
  const need = (k) => {
    const v = env[k];
    if (!v) throw new Error(`${k} not configured`);
    return v;
  };
  const repositories = need("GH_REPOSITORIES").split(",").map((r) => r.trim()).filter(Boolean);
  if (repositories.length === 0) throw new Error("GH_REPOSITORIES is empty");
  const workflowRefs = need("BOOTSTRAP_WORKFLOW_REFS").split(",").map((r) => r.trim()).filter(Boolean);
  if (workflowRefs.length === 0) throw new Error("BOOTSTRAP_WORKFLOW_REFS is empty");
  return {
    audience: need("GH_AUDIENCE"),
    owner: need("GH_OWNER"),
    repositories,
    workflowRefs,
    // Required, not optional. index.mjs treats the environment claim as an UPGRADE (no
    // environment => read tier). There is no read tier here: vending is the privileged act, so a
    // request without the reviewer-gated environment gets nothing at all.
    environment: need("BOOTSTRAP_ENVIRONMENT"),
  };
}

// verifyOIDC pins one repository and one workflow ref. This deployment allows several of each, so
// it is called once per candidate pair and the first acceptance wins. Every other check —
// signature, alg, iss, aud, exp/nbf/iat, owner — is enforced identically on each pass, so
// widening the repo set does NOT weaken anything else.
export async function verifyAgainstAllowList(jwt, config, opts) {
  let lastError = new Error("no allowed repository/workflow pair");
  for (const repository of config.repositories) {
    for (const workflowRef of config.workflowRefs) {
      try {
        return await verifyOIDC(
          jwt,
          { audience: config.audience, owner: config.owner, repository, readWorkflowRef: workflowRef },
          opts,
        );
      } catch (e) {
        lastError = e;
      }
    }
  }
  throw lastError;
}

// The environment claim is GitHub-signed and cannot be forged, so requiring it means a human
// approved this specific run in a reviewer-gated Environment before the token was ever vended.
export function environmentApproved(claims, config) {
  return claims.environment === config.environment;
}

export default {
  async fetch(req, env) {
    if (req.method !== "POST") return new Response("POST only\n", { status: 405 });
    const jwt = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!jwt) return new Response("unauthorized\n", { status: 401 });

    let config;
    try {
      config = loadBootstrapConfig(env);
    } catch (e) {
      console.error(`vendor misconfigured: ${e.message}`);
      return new Response("vendor misconfigured\n", { status: 500 });
    }

    let claims;
    try {
      claims = await verifyAgainstAllowList(jwt, config);
    } catch (e) {
      // Reason server-side only — no oracle for an attacker probing the allow-list.
      console.warn(`oidc rejected: ${e.message}`);
      return new Response("unauthorized\n", { status: 401 });
    }

    if (!environmentApproved(claims, config)) {
      console.warn(`environment claim '${claims.environment}' != '${config.environment}' for ${claims.repository}`);
      return new Response("unauthorized\n", { status: 401 });
    }

    // Fail closed: an unconfigured Secret must never fall through to an empty-token response that
    // a caller would send to npm as `Bearer `.
    const token = env.NPM_BOOTSTRAP_TOKEN;
    if (!token) {
      console.error("NPM_BOOTSTRAP_TOKEN not configured");
      return new Response("vendor misconfigured\n", { status: 500 });
    }

    console.log(`vended npm bootstrap token to ${claims.repository} (${claims.job_workflow_ref})`);
    return new Response(JSON.stringify({ token, repository: claims.repository }), {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
