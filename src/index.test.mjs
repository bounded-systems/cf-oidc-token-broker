// Unit tests for the trust boundary (loadConfig + verifyOIDC + deriveEdit + policyFor).
//
// We never touch the network or the real clock: verifyOIDC takes two injectable seams —
// `getJwks` (default: GitHub's live JWKS) and `nowMs` (default: Date.now) — so here we mint our
// own RS256 keypair, serve it as a mock JWKS, and freeze time. Production `fetch` calls verifyOIDC
// with no options, so it keeps using the real defaults untouched.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  loadConfig,
  verifyOIDC,
  deriveEdit,
  policyFor,
  isoSeconds,
  GH_ISSUER,
} from "./index.mjs";

const enc = new TextEncoder();
const KID = "test-key-1";
const NOW_MS = 1_700_000_000_000; // frozen wall clock
const NOW_S = Math.floor(NOW_MS / 1000);

// Example trust config (what loadConfig would return from Worker vars).
const CONFIG = {
  audience: "my-cf-broker",
  owner: "acme",
  repository: "acme/infra",
  readWorkflowRef: "acme/infra/.github/workflows/snapshot.yml@refs/heads/main",
  editWorkflowRef: "acme/infra/.github/workflows/apply.yml@refs/heads/main",
  editEnvironment: "production-apply",
};

// ---- crypto + JWT minting helpers ------------------------------------------

function b64url(bytes) {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const b64urlJSON = (obj) => b64url(enc.encode(JSON.stringify(obj)));

const { privateKey, publicKey } = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const jwk = await crypto.subtle.exportKey("jwk", publicKey);
const PUBLIC_JWK = { ...jwk, kid: KID, alg: "RS256", use: "sig" };
const mockJwks = async () => [PUBLIC_JWK];

// A second key whose token (same kid) fails the crypto verify.
const other = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);

function baseClaims(over = {}) {
  return {
    iss: GH_ISSUER,
    aud: CONFIG.audience,
    exp: NOW_S + 600,
    iat: NOW_S,
    nbf: NOW_S - 10,
    repository: CONFIG.repository,
    repository_owner: CONFIG.owner,
    job_workflow_ref: CONFIG.readWorkflowRef,
    ...over,
  };
}

async function signJwt(claims, { header = {}, key = privateKey } = {}) {
  const h = b64urlJSON({ alg: "RS256", typ: "JWT", kid: KID, ...header });
  const p = b64urlJSON(claims);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

const verify = (jwt) => verifyOIDC(jwt, CONFIG, { getJwks: mockJwks, nowMs: () => NOW_MS });
const rejects = (jwt, re) => assert.rejects(() => verify(jwt), re);

// ---- config ----------------------------------------------------------------

test("loadConfig: reads the required pins; edit tier optional", () => {
  const cfg = loadConfig({
    GH_AUDIENCE: "a", GH_OWNER: "o", GH_REPOSITORY: "o/r",
    READ_WORKFLOW_REF: "o/r/.github/workflows/read.yml@refs/heads/main",
  });
  assert.equal(cfg.audience, "a");
  assert.equal(cfg.editWorkflowRef, null); // read-only broker when edit vars are unset
  assert.equal(cfg.editEnvironment, null);
});

test("loadConfig: throws on any missing required var (fails closed)", () => {
  assert.throws(() => loadConfig({ GH_OWNER: "o", GH_REPOSITORY: "o/r", READ_WORKFLOW_REF: "x" }), /GH_AUDIENCE/);
  assert.throws(() => loadConfig({ GH_AUDIENCE: "a", GH_OWNER: "o", GH_REPOSITORY: "o/r" }), /READ_WORKFLOW_REF/);
});

// ---- valid path ------------------------------------------------------------

test("valid JWT verifies and returns the claims", async () => {
  const out = await verify(await signJwt(baseClaims()));
  assert.equal(out.repository, CONFIG.repository);
  assert.equal(out.repository_owner, CONFIG.owner);
});

test("valid JWT with aud as an array containing our audience verifies", async () => {
  const out = await verify(await signJwt(baseClaims({ aud: ["other", CONFIG.audience] })));
  assert.deepEqual(out.aud, ["other", CONFIG.audience]);
});

// ---- rejections ------------------------------------------------------------

test("rejects alg=none", async () => {
  const h = b64urlJSON({ alg: "none", typ: "JWT", kid: KID });
  const p = b64urlJSON(baseClaims());
  await rejects(`${h}.${p}.`, /unexpected alg/);
});

test("rejects alg=HS256 (algorithm confusion)", async () => {
  const h = b64urlJSON({ alg: "HS256", typ: "JWT", kid: KID });
  const p = b64urlJSON(baseClaims());
  await rejects(`${h}.${p}.AAAA`, /unexpected alg/);
});

test("rejects wrong aud", async () => {
  await rejects(await signJwt(baseClaims({ aud: "someone-else" })), /bad aud/);
});

test("rejects a tampered signature", async () => {
  const claims = baseClaims();
  const h = b64urlJSON({ alg: "RS256", typ: "JWT", kid: KID });
  const p = b64urlJSON(claims);
  const badSig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", other.privateKey, enc.encode(`${h}.${p}`));
  await rejects(`${h}.${p}.${b64url(badSig)}`, /bad signature/);
});

test("rejects a flipped-byte signature", async () => {
  const jwt = await signJwt(baseClaims());
  const [h, p, sig] = jwt.split(".");
  const flipped = sig.slice(0, -2) + (sig.endsWith("AA") ? "BB" : "AA");
  await rejects(`${h}.${p}.${flipped}`, /bad signature/);
});

test("rejects wrong repository", async () => {
  await rejects(await signJwt(baseClaims({ repository: "acme/other" })), /repository not allowed/);
});

test("rejects wrong repository_owner", async () => {
  await rejects(await signJwt(baseClaims({ repository_owner: "evil", repository: "evil/infra" })), /owner not allowed/);
});

test("rejects wrong issuer", async () => {
  await rejects(await signJwt(baseClaims({ iss: "https://evil.example/" })), /bad iss/);
});

test("rejects an expired token (exp in the past)", async () => {
  await rejects(await signJwt(baseClaims({ exp: NOW_S - 1 })), /expired/);
});

test("rejects a not-yet-valid token (nbf in the future)", async () => {
  await rejects(await signJwt(baseClaims({ nbf: NOW_S + 120 })), /not yet valid/);
});

test("rejects iat too far in the future", async () => {
  await rejects(await signJwt(baseClaims({ iat: NOW_S + 120 })), /iat in future/);
});

test("rejects a disallowed workflow ref", async () => {
  await rejects(
    await signJwt(baseClaims({ job_workflow_ref: `${CONFIG.repository}/.github/workflows/evil.yml@refs/heads/main` })),
    /workflow not allowed/,
  );
});

test("rejects an unknown kid (not in JWKS)", async () => {
  await rejects(await signJwt(baseClaims(), { header: { kid: "no-such-kid" } }), /unknown signing key/);
});

test("rejects a malformed JWT (not three segments)", async () => {
  await rejects("only.two", /malformed jwt/);
});

// ---- scope derivation ------------------------------------------------------

test("scope: read workflow → read (no edit)", async () => {
  const claims = await verify(await signJwt(baseClaims({ job_workflow_ref: CONFIG.readWorkflowRef })));
  assert.equal(deriveEdit(claims, CONFIG), false);
});

test("scope: edit workflow WITHOUT environment → read (dry-run path)", async () => {
  const claims = await verify(await signJwt(baseClaims({ job_workflow_ref: CONFIG.editWorkflowRef })));
  assert.equal(deriveEdit(claims, CONFIG), false);
});

test("scope: edit workflow WITH the gated environment → edit", async () => {
  const claims = await verify(
    await signJwt(baseClaims({ job_workflow_ref: CONFIG.editWorkflowRef, environment: CONFIG.editEnvironment })),
  );
  assert.equal(deriveEdit(claims, CONFIG), true);
});

test("scope: edit workflow with a WRONG environment → read (not the approved env)", async () => {
  const claims = await verify(
    await signJwt(baseClaims({ job_workflow_ref: CONFIG.editWorkflowRef, environment: "staging" })),
  );
  assert.equal(deriveEdit(claims, CONFIG), false);
});

test("scope: a read-only broker (no edit config) never grants edit", () => {
  const readonly = { ...CONFIG, editWorkflowRef: null, editEnvironment: null };
  assert.equal(deriveEdit({ job_workflow_ref: CONFIG.editWorkflowRef, environment: CONFIG.editEnvironment }, readonly), false);
});

// ---- token policy: zone-pinned, fail-closed --------------------------------

const POLICY_ENV = {
  CF_ACCOUNT_ID: "acct-1",
  CF_ZONE_IDS: "zone-abc",
  CF_PG_ZONE_READ: "pg-zone-read",
  CF_PG_DNS_READ: "pg-dns-read",
  CF_PG_DNS_EDIT: "pg-dns-edit",
  CF_PG_WORKERS_ROUTES_READ: "pg-wr-read",
  CF_PG_WORKERS_SCRIPTS_READ: "pg-ws-read",
};
const ids = (pgs) => pgs.map((g) => g.id);

test("policy: read scope → zone reads on the zone + Workers Scripts read on the account", () => {
  const policies = policyFor(false, POLICY_ENV);
  assert.equal(policies.length, 2);
  assert.deepEqual(policies[0].resources, { "com.cloudflare.api.account.zone.zone-abc": "*" });
  assert.deepEqual(ids(policies[0].permission_groups), ["pg-zone-read", "pg-dns-read", "pg-wr-read"]);
  assert.deepEqual(policies[1].resources, { "com.cloudflare.api.account.acct-1": "*" });
  assert.deepEqual(ids(policies[1].permission_groups), ["pg-ws-read"]);
});

test("policy: edit scope → Zone Read + DNS Read + DNS Edit on the zone, one policy", () => {
  const policies = policyFor(true, POLICY_ENV);
  assert.equal(policies.length, 1);
  assert.deepEqual(ids(policies[0].permission_groups), ["pg-zone-read", "pg-dns-read", "pg-dns-edit"]);
});

test("policy: multiple zones → each zone-scoped policy pins every zone (comma-separated, trimmed)", () => {
  const [zonePolicy] = policyFor(false, { ...POLICY_ENV, CF_ZONE_IDS: "zone-abc, zone-def" });
  assert.deepEqual(zonePolicy.resources, {
    "com.cloudflare.api.account.zone.zone-abc": "*",
    "com.cloudflare.api.account.zone.zone-def": "*",
  });
});

test("policy: missing/empty CF_ZONE_IDS throws — fails closed, never mints a zone.* token", () => {
  assert.throws(() => policyFor(false, { ...POLICY_ENV, CF_ZONE_IDS: undefined }), /CF_ZONE_IDS/);
  assert.throws(() => policyFor(false, { ...POLICY_ENV, CF_ZONE_IDS: " , " }), /CF_ZONE_IDS/);
});

test("policy: missing CF_ACCOUNT_ID or any permission-group id throws — fails closed", () => {
  assert.throws(() => policyFor(false, { ...POLICY_ENV, CF_ACCOUNT_ID: undefined }), /CF_ACCOUNT_ID/);
  assert.throws(() => policyFor(false, { ...POLICY_ENV, CF_PG_ZONE_READ: undefined }), /CF_PG_ZONE_READ/);
  assert.throws(() => policyFor(true, { ...POLICY_ENV, CF_PG_DNS_EDIT: undefined }), /CF_PG_DNS_EDIT/);
});

// ---- token validity timestamps ---------------------------------------------

test("isoSeconds: second-precision ISO-8601, no millis (Cloudflare rejects the .mmm form)", () => {
  assert.equal(isoSeconds(1782684432524), "2026-06-28T22:07:12Z");
  assert.match(isoSeconds(1782684432000), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.doesNotMatch(isoSeconds(1782684432999), /\.\d+Z$/);
});
