import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import {
  computeWorkChallengeResponse,
  deriveSharedSecret
} from "../src/crypto/primitives.js";
import {
  ADMIN_KEY,
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  basicAuthHeader,
  createIdentityViaDirectory,
  solveAuthenticatedPost,
  solveWorkRequest,
  startTestServer
} from "./helpers.js";

describe("Work API, MDM, User Properties & Remote Secret", () => {
  let ctx: TestServerContext;
  const authDemo = basicAuthHeader(DEMO_USER, DEMO_PASS);
  const bobUser = "bob";
  const bobPass = "bob-secret";
  const authBob = basicAuthHeader(bobUser, bobPass);

  before(async () => {
    ctx = await startTestServer();
  });

  after(async () => {
    await ctx.stopAndCleanup();
  });

  it("matches official libthreema wdir challenge test vector", () => {
    // Verified vector from threema-desktop-src libthreema work_directory.rs
    const sharedZero = deriveSharedSecret(new Uint8Array(32), new Uint8Array(32));
    const resp = computeWorkChallengeResponse(sharedZero, Buffer.from("meow", "utf8"));
    assert.equal(
      Buffer.from(resp).toString("hex"),
      "56266bebac77186b46982853067a9a405f28163e5d436e9353388f4f6f59e394"
    );
  });

  it("serves /work/fetch2, /work/identities (no time), wildcard /work/directory, logos, user-properties, and remote-secret", async () => {
    await fetch(`${ctx.httpOrigin}/admin/accounts`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({
        username: bobUser,
        password: bobPass,
        firstName: "Bob",
        lastName: "Tester",
        department: "Engineering",
        category: "eng"
      })
    });

    const alice = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);
    const bob = await createIdentityViaDirectory(ctx.httpOrigin, authBob);
    const charlie = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    await solveAuthenticatedPost(`${ctx.httpOrigin}/directory/identity/update_work_info`, authDemo, alice.identity, alice.keys.secretKey, {
      licenseUsername: DEMO_USER,
      licensePassword: DEMO_PASS,
      publicNickname: "Alice",
      firstName: "Alice",
      lastName: "Admin",
      jobTitle: "CTO",
      department: "Ops",
      category: "exec"
    });
    await solveAuthenticatedPost(`${ctx.httpOrigin}/directory/identity/update_work_info`, authDemo, charlie.identity, charlie.keys.secretKey, {
      licenseUsername: DEMO_USER,
      licensePassword: DEMO_PASS,
      publicNickname: "charlie"
    });

    // Self-hosted logo upload & fetch2 auto-URL
    const logoPng = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3, 4]);
    const putLogo = await fetch(`${ctx.httpOrigin}/admin/mdm/logo/light`, {
      method: "PUT",
      headers: { "x-admin-key": ADMIN_KEY, "content-type": "image/png" },
      body: logoPng
    });
    assert.equal(putLogo.status, 204);

    const getLogo = await fetch(`${ctx.httpOrigin}/work/logo/light`);
    assert.equal(getLogo.status, 200);
    assert.equal(getLogo.headers.get("content-type"), "image/png");
    assert.deepEqual(Buffer.from(await getLogo.arrayBuffer()), logoPng);
    const etag = getLogo.headers.get("etag")!;
    const cachedLogo = await fetch(`${ctx.httpOrigin}/work/logo/light`, {
      headers: { "if-none-match": etag }
    });
    assert.equal(cachedLogo.status, 304);

    // /work/fetch2
    const f2 = await fetch(`${ctx.httpOrigin}/work/fetch2`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: DEMO_USER, password: DEMO_PASS, contacts: [] })
    });
    assert.equal(f2.status, 200);
    const f2Json = (await f2.json()) as any;
    assert.equal(f2Json.org.name, "OnPrem Organization");
    assert.ok(f2Json.logo.light.endsWith("/work/logo/light"));
    assert.equal(f2Json.contacts.length, 3);

    const byId = new Map<string, any>(f2Json.contacts.map((c: any) => [c.id, c]));
    assert.equal(byId.get(alice.identity).first, "Alice");
    assert.equal(byId.get(bob.identity).department, "Engineering");
    const charlieC = byId.get(charlie.identity);
    assert.equal(charlieC.first, "charlie");
    assert.equal("last" in charlieC, false);
    assert.equal("jobTitle" in charlieC, false);
    assert.equal("department" in charlieC, false);
    assert.equal("availability" in charlieC, false);

    // /work/identities omits top-level `time`
    const idsRes = await fetch(`${ctx.httpOrigin}/work/identities`, {
      method: "POST",
      headers: {
        origin: "threemadesktop://app",
        "content-type": "text/plain;charset=UTF-8"
      },
      body: JSON.stringify({
        username: DEMO_USER,
        password: DEMO_PASS,
        contacts: [alice.identity, bob.identity, charlie.identity]
      })
    });
    assert.equal(idsRes.status, 200);
    const idsJson = (await idsRes.json()) as any;
    assert.equal("time" in idsJson, false);
    assert.equal(idsJson.contacts.length, 3);

    // /work/directory wildcard "*" + category filter
    const dirWild = await fetch(`${ctx.httpOrigin}/work/directory`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        username: DEMO_USER,
        password: DEMO_PASS,
        identity: alice.identity,
        query: "*",
        categories: ["eng"],
        page: 0
      })
    });
    assert.equal(dirWild.status, 200);
    const dirWildJson = (await dirWild.json()) as any;
    assert.equal(dirWildJson.contacts.length, 1);
    assert.equal(dirWildJson.contacts[0].id, bob.identity);
    assert.equal(dirWildJson.contacts[0].org.name, "OnPrem Organization");

    // POST /work/api-client/v1/user-properties: WorkProperties { availability_status = { category: 2 (BUSY) } } => bytes CgIIAg==
    const setPropsRes = await solveWorkRequest(
      "POST",
      `${ctx.httpOrigin}/work/api-client/v1/user-properties`,
      {
        identity: charlie.identity,
        username: DEMO_USER,
        password: DEMO_PASS,
        properties: "CgIIAg=="
      },
      charlie.keys.secretKey
    );
    assert.equal(setPropsRes.status, 204);

    // Verify availability reflects in /work/fetch2
    const f2AfterProps = await fetch(`${ctx.httpOrigin}/work/fetch2`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: DEMO_USER, password: DEMO_PASS, contacts: [charlie.identity] })
    });
    const charlieAfter = ((await f2AfterProps.json()) as any).contacts[0];
    assert.equal(charlieAfter.availability, "CAI=");

    // PUT / POST / DELETE /work/api-client/v1/remote-secret
    const remoteSecretB64 = crypto.randomBytes(32).toString("base64");
    const putRsRes = await solveWorkRequest(
      "PUT",
      `${ctx.httpOrigin}/work/api-client/v1/remote-secret`,
      {
        identity: alice.identity,
        username: DEMO_USER,
        password: DEMO_PASS,
        secret: remoteSecretB64
      },
      alice.keys.secretKey
    );
    assert.equal(putRsRes.status, 200);
    const { secretAuthenticationToken } = (await putRsRes.json()) as {
      secretAuthenticationToken: string;
    };
    assert.equal(Buffer.from(secretAuthenticationToken, "base64").byteLength, 32);

    const fetchRs1 = await fetch(`${ctx.httpOrigin}/work/api-client/v1/remote-secret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secretAuthenticationToken })
    });
    assert.equal(fetchRs1.status, 200);
    const rsJson = (await fetchRs1.json()) as any;
    assert.equal(rsJson.secret, remoteSecretB64);
    assert.ok(rsJson.checkIntervalS > 0);

    // Admin blocks remote secret -> fetch returns 403
    const listRs = await fetch(`${ctx.httpOrigin}/admin/remote-secrets`, {
      headers: { "x-admin-key": ADMIN_KEY }
    });
    const hash = ((await listRs.json()) as any).remoteSecrets[0].authTokenHash;
    const blockRes = await fetch(`${ctx.httpOrigin}/admin/remote-secrets/${hash}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({ blocked: true })
    });
    assert.equal(blockRes.status, 200);

    const fetchRsBlocked = await fetch(`${ctx.httpOrigin}/work/api-client/v1/remote-secret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secretAuthenticationToken })
    });
    assert.equal(fetchRsBlocked.status, 403);

    // DELETE remote secret
    const delRsRes = await solveWorkRequest(
      "DELETE",
      `${ctx.httpOrigin}/work/api-client/v1/remote-secret`,
      {
        identity: alice.identity,
        username: DEMO_USER,
        password: DEMO_PASS,
        secretAuthenticationToken
      },
      alice.keys.secretKey
    );
    assert.equal(delRsRes.status, 204);

    const fetchRsGone = await fetch(`${ctx.httpOrigin}/work/api-client/v1/remote-secret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secretAuthenticationToken })
    });
    assert.equal(fetchRsGone.status, 404);
  });
});
