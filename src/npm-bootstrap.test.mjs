// Unit tests for the npm bootstrap vendor's own trust surface.
//
// verifyOIDC itself is covered by index.test.mjs and is NOT re-tested here — this file exercises
// only what the sibling adds: the repository/workflow allow-list, the unconditional environment
// requirement, and fail-closed config. Same technique as index.test.mjs: a locally minted RS256
// keypair served as a mock JWKS, with a frozen clock. No network, no real time.

import { test } from "node:test";
import assert from "node:assert/strict";
import { GH_ISSUER } from "./index.mjs";
import {
  loadBootstrapConfig,
  verifyAgainstAllowList,
  environmentApproved,
} from "./npm-bootstrap.mjs";

const enc = new TextEncoder();
const KID = "test-key-1";
const NOW_MS = 1_700_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);

const CONFIG = {
  audience: "npm-bootstrap-vendor",
  owner: "bdelanghe",
  repositories: ["bdelanghe/brand", "bdelanghe/brand-tools"],
  workflowRefs: [
    "bdelanghe/brand/.github/workflows/bootstrap-publish.yml@refs/heads/main",
    "bdelanghe/brand-tools/.github/workflows/bootstrap-publish.yml@refs/heads/main",
  ],
  environment: "npm-bootstrap",
};

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const b64urlJSON = (o) => b64url(enc.encode(JSON.stringify(o)));

const { privateKey, publicKey } = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["sign", "verify"],
);
const jwk = await crypto.subtle.exportKey("jwk", publicKey);
const mockJwks = async () => [{ ...jwk, kid: KID, alg: "RS256", use: "sig" }];

async function signJwt(over = {}) {
  const claims = {
    iss: GH_ISSUER,
    aud: CONFIG.audience,
    exp: NOW_S + 600,
    iat: NOW_S,
    nbf: NOW_S - 10,
    repository: CONFIG.repositories[0],
    repository_owner: CONFIG.owner,
    job_workflow_ref: CONFIG.workflowRefs[0],
    environment: CONFIG.environment,
    ...over,
  };
  const h = b64urlJSON({ alg: "RS256", typ: "JWT", kid: KID });
  const p = b64urlJSON(claims);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

const verify = (jwt) => verifyAgainstAllowList(jwt, CONFIG, { getJwks: mockJwks, nowMs: () => NOW_MS });

// ---- config ----------------------------------------------------------------

const ENV = {
  GH_AUDIENCE: "npm-bootstrap-vendor",
  GH_OWNER: "bdelanghe",
  GH_REPOSITORIES: "bdelanghe/brand, bdelanghe/brand-tools",
  BOOTSTRAP_WORKFLOW_REFS: CONFIG.workflowRefs.join(","),
  BOOTSTRAP_ENVIRONMENT: "npm-bootstrap",
};

test("loadBootstrapConfig: splits and trims the allow-lists", () => {
  const c = loadBootstrapConfig(ENV);
  assert.deepEqual(c.repositories, ["bdelanghe/brand", "bdelanghe/brand-tools"]);
  assert.equal(c.environment, "npm-bootstrap");
});

test("loadBootstrapConfig: fails closed on any missing var", () => {
  for (const k of Object.keys(ENV)) {
    const partial = { ...ENV };
    delete partial[k];
    assert.throws(() => loadBootstrapConfig(partial), new RegExp(k), `${k} must be required`);
  }
});

// An empty list must not degrade into "allow nothing quietly" — it is a misconfiguration, and a
// misconfigured vendor of a long-lived secret should refuse loudly rather than 401 forever.
test("loadBootstrapConfig: an all-whitespace list is a misconfiguration, not an empty allow-list", () => {
  assert.throws(() => loadBootstrapConfig({ ...ENV, GH_REPOSITORIES: " , , " }), /GH_REPOSITORIES is empty/);
  assert.throws(() => loadBootstrapConfig({ ...ENV, BOOTSTRAP_WORKFLOW_REFS: " , " }), /BOOTSTRAP_WORKFLOW_REFS is empty/);
});

// ---- the allow-list --------------------------------------------------------

test("accepts each allowed repository with its own workflow ref", async () => {
  for (const [i, repository] of CONFIG.repositories.entries()) {
    const claims = await verify(await signJwt({ repository, job_workflow_ref: CONFIG.workflowRefs[i] }));
    assert.equal(claims.repository, repository);
  }
});

test("rejects a repository outside the allow-list", async () => {
  const jwt = await signJwt({ repository: "bdelanghe/site" });
  await assert.rejects(() => verify(jwt));
});

test("rejects a workflow ref outside the allow-list", async () => {
  const jwt = await signJwt({ job_workflow_ref: "bdelanghe/brand/.github/workflows/publish.yml@refs/heads/main" });
  await assert.rejects(() => verify(jwt));
});

// Widening the repo set must not widen anything else. verifyOIDC runs in full on every candidate
// pair, so a token failing a NON-repo check has to fail no matter how many pairs are tried.
test("widening the repo list does not relax the other checks", async () => {
  for (const [over, re] of [
    [{ repository_owner: "someone-else" }, /owner/],
    [{ aud: "other-audience" }, /aud/],
    [{ exp: NOW_S - 1 }, /expired/],
    [{ iss: "https://evil.example" }, /iss/],
  ]) {
    const jwt = await signJwt(over);
    await assert.rejects(() => verify(jwt), re);
  }
});

// ---- the environment gate --------------------------------------------------
//
// index.mjs treats the environment claim as an UPGRADE — absent it, you get the read tier. There
// is no read tier here, so absence must mean refusal.

test("the environment claim is required, not an upgrade", () => {
  assert.equal(environmentApproved({ environment: CONFIG.environment }, CONFIG), true);
  assert.equal(environmentApproved({ environment: "some-other-env" }, CONFIG), false);
  assert.equal(environmentApproved({}, CONFIG), false, "a job that entered no environment gets nothing");
  assert.equal(environmentApproved({ environment: "" }, CONFIG), false);
});

// Defence in depth. loadBootstrapConfig already requires BOOTSTRAP_ENVIRONMENT, so a config with
// no environment should be unreachable — but "unreachable" is a property held by a DIFFERENT
// function, and a check that silently passes when its own config is empty is one refactor away
// from vending to anyone. The gate must refuse on its own terms.
test("a config with no environment vends nothing, even though config loading forbids it", () => {
  for (const broken of [{}, { environment: "" }, { environment: null }]) {
    assert.equal(
      environmentApproved({ environment: CONFIG.environment }, broken), false,
      "an empty configured environment must not match every claim",
    );
  }
});
