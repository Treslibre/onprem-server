import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import {
  computeDirectoryChallengeResponse,
  deriveSharedSecret,
  hmacEmail
} from "../src/crypto/primitives.js";
import {
  ADMIN_KEY,
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  basicAuthHeader,
  createIdentityViaDirectory,
  solveAuthenticatedPost,
  startTestServer
} from "./helpers.js";

describe("Directory API & Identity Revocation", () => {
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

  it("handles creation, lookups with wire ActivityState, HMAC matching, revocation, and reports", async () => {
    const accRes = await fetch(`${ctx.httpOrigin}/admin/accounts`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({
        username: bobUser,
        password: bobPass,
        firstName: "Bob",
        lastName: "Tester",
        department: "Engineering"
      })
    });
    assert.equal(accRes.status, 201);

    // check_license without Basic Auth (Desktop compatible)
    const licOk = await fetch(`${ctx.httpOrigin}/directory/check_license`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ licenseUsername: DEMO_USER, licensePassword: DEMO_PASS })
    });
    assert.deepEqual(await licOk.json(), { success: true });

    const licBad = await fetch(`${ctx.httpOrigin}/directory/check_license`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ licenseUsername: DEMO_USER, licensePassword: "wrong" })
    });
    assert.equal(((await licBad.json()) as any).success, false);

    const alice = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);
    const bob = await createIdentityViaDirectory(ctx.httpOrigin, authBob);
    const charlie = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    // Single lookup & bulk lookup: protocol wire state 0 === ACTIVE
    const single = await fetch(`${ctx.httpOrigin}/directory/identity/${alice.identity}`, {
      headers: { authorization: authDemo }
    });
    assert.equal(single.status, 200);
    const singleJson = (await single.json()) as any;
    assert.equal(singleJson.identity, alice.identity);
    assert.equal(singleJson.publicKey, Buffer.from(alice.keys.publicKey).toString("base64"));
    assert.equal(singleJson.state, 0);

    const bulk = await fetch(`${ctx.httpOrigin}/directory/identity/fetch_bulk`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authDemo },
      body: JSON.stringify({ identities: [alice.identity, bob.identity] })
    });
    const bulkJson = (await bulk.json()) as any;
    assert.equal(bulkJson.identities.length, 2);
    assert.equal(bulkJson.identities[0].state, 0);

    // Feature mask + /identity/check: wire ActivityState [0 (ACTIVE), 2 (INVALID)]
    const fmRes = await solveAuthenticatedPost<{ success: boolean }>(
      `${ctx.httpOrigin}/directory/identity/set_featuremask`,
      authDemo,
      alice.identity,
      alice.keys.secretKey,
      { featureMask: 63 }
    );
    assert.equal(fmRes.success, true);

    const checkRes = await fetch(`${ctx.httpOrigin}/directory/identity/check`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authDemo },
      body: JSON.stringify({ identities: [alice.identity, "NOTFOUND"] })
    });
    const checkJson = (await checkRes.json()) as any;
    assert.deepEqual(checkJson.states, [0, 2]);
    assert.deepEqual(checkJson.featureMasks, [63, null]);

    // Link email + CORS preflight & text/plain JSON body handling for threemadesktop://app
    const linkStart = await fetch(`${ctx.httpOrigin}/directory/identity/link_email`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authDemo },
      body: JSON.stringify({ identity: alice.identity, email: "Alice@Example.com", lang: "en" })
    });
    const linkCh = (await linkStart.json()) as {
      linked: boolean;
      token: string;
      tokenRespKeyPub: string;
    };
    assert.equal(linkCh.linked, false);
    const linkResp = computeDirectoryChallengeResponse(
      deriveSharedSecret(
        new Uint8Array(Buffer.from(linkCh.tokenRespKeyPub, "base64")),
        alice.keys.secretKey
      ),
      new Uint8Array(Buffer.from(linkCh.token, "base64"))
    );
    const linkFinish = await fetch(`${ctx.httpOrigin}/directory/identity/link_email`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authDemo },
      body: JSON.stringify({
        identity: alice.identity,
        email: "Alice@Example.com",
        lang: "en",
        token: linkCh.token,
        response: Buffer.from(linkResp).toString("base64")
      })
    });
    assert.equal(((await linkFinish.json()) as any).success, true);

    const preflightPriv = await fetch(`${ctx.httpOrigin}/directory/identity/fetch_priv`, {
      method: "OPTIONS",
      headers: {
        origin: "threemadesktop://app",
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization, user-agent"
      }
    });
    assert.equal(preflightPriv.status, 204);
    assert.equal(preflightPriv.headers.get("access-control-allow-origin"), "threemadesktop://app");
    const allowHeaders = (preflightPriv.headers.get("access-control-allow-headers") ?? "").toLowerCase();
    assert.ok(allowHeaders.includes("authorization"));
    assert.ok(allowHeaders.includes("user-agent"));

    const privStep1 = await fetch(`${ctx.httpOrigin}/directory/identity/fetch_priv`, {
      method: "POST",
      headers: {
        origin: "threemadesktop://app",
        "content-type": "text/plain;charset=UTF-8",
        authorization: authDemo
      },
      body: JSON.stringify({ identity: alice.identity })
    });
    assert.equal(privStep1.status, 200);
    const privCh = (await privStep1.json()) as { token: string; tokenRespKeyPub: string };
    const privResp = computeDirectoryChallengeResponse(
      deriveSharedSecret(
        new Uint8Array(Buffer.from(privCh.tokenRespKeyPub, "base64")),
        alice.keys.secretKey
      ),
      new Uint8Array(Buffer.from(privCh.token, "base64"))
    );
    const privStep2 = await fetch(`${ctx.httpOrigin}/directory/identity/fetch_priv`, {
      method: "POST",
      headers: {
        origin: "threemadesktop://app",
        "content-type": "text/plain;charset=UTF-8",
        authorization: authDemo
      },
      body: JSON.stringify({
        identity: alice.identity,
        token: privCh.token,
        response: Buffer.from(privResp).toString("base64")
      })
    });
    assert.equal(privStep2.status, 200);
    assert.equal(privStep2.headers.get("access-control-allow-origin"), "threemadesktop://app");
    const privJson = (await privStep2.json()) as { identity: string; serverGroup: string; email?: string };
    assert.equal(privJson.email, "Alice@Example.com");

    // match_token + match
    const mt = await solveAuthenticatedPost<{ success: boolean; matchToken: string }>(
      `${ctx.httpOrigin}/directory/identity/match_token`,
      authBob,
      bob.identity,
      bob.keys.secretKey,
      {}
    );
    assert.equal(mt.success, true);

    const emailHash = hmacEmail("alice@example.com");
    const matchRes = await fetch(`${ctx.httpOrigin}/directory/identity/match`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authBob },
      body: JSON.stringify({
        matchToken: mt.matchToken,
        emailHashes: [emailHash],
        mobileNoHashes: []
      })
    });
    const matchJson = (await matchRes.json()) as any;
    assert.equal(matchJson.identities.length, 1);
    assert.equal(matchJson.identities[0].identity, alice.identity);

    // SFU & TURN credentials + junk report
    const turn = await solveAuthenticatedPost<any>(
      `${ctx.httpOrigin}/directory/identity/turn_cred`,
      authDemo,
      alice.identity,
      alice.keys.secretKey,
      { type: "call" }
    );
    assert.equal(turn.success, true);

    const sfu = await solveAuthenticatedPost<any>(
      `${ctx.httpOrigin}/directory/identity/sfu_cred`,
      authDemo,
      alice.identity,
      alice.keys.secretKey,
      {}
    );
    assert.equal(sfu.success, true);
    assert.ok(sfu.sfuToken);

    const junk = await solveAuthenticatedPost<any>(
      `${ctx.httpOrigin}/directory/identity/report_junk`,
      authDemo,
      alice.identity,
      alice.keys.secretKey,
      { targetIdentity: charlie.identity, reason: "spam" }
    );
    assert.equal(junk.success, true);

    // Revocation key + ws/revoke (for Bob) and challenge-authenticated /identity/revoke (for Charlie)
    const revKey = Buffer.from(crypto.randomBytes(4)).toString("base64");
    const setRev = await solveAuthenticatedPost<{ success: boolean }>(
      `${ctx.httpOrigin}/directory/identity/set_revocation_key`,
      authBob,
      bob.identity,
      bob.keys.secretKey,
      { revocationKey: revKey }
    );
    assert.equal(setRev.success, true);
    const chkRev = await solveAuthenticatedPost<{ revocationKeySet: boolean; lastChanged: string }>(
      `${ctx.httpOrigin}/directory/identity/check_revocation_key`,
      authBob,
      bob.identity,
      bob.keys.secretKey,
      {}
    );
    assert.equal(chkRev.revocationKeySet, true);
    assert.match(chkRev.lastChanged, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+0000$/);

    // Wrong revocation key fails
    const badWsRevoke = await fetch(`${ctx.httpOrigin}/directory/identity/ws/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identity: bob.identity, revocationKey: "wrongkey" })
    });
    assert.equal(((await badWsRevoke.json()) as any).success, false);

    // Correct revocation key succeeds without Basic Auth
    const okWsRevoke = await fetch(`${ctx.httpOrigin}/directory/identity/ws/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identity: bob.identity, revocationKey: revKey })
    });
    assert.equal(((await okWsRevoke.json()) as any).success, true);

    // Challenge-authenticated /identity/revoke on Charlie
    const okChRevoke = await solveAuthenticatedPost<{ success: boolean }>(
      `${ctx.httpOrigin}/directory/identity/revoke`,
      authDemo,
      charlie.identity,
      charlie.keys.secretKey,
      {}
    );
    assert.equal(okChRevoke.success, true);

    // Revoked identities: 404 on GET /identity/:id, omitted in fetch_bulk, 2 in /identity/check, 404 on blob_cred
    const bobGet = await fetch(`${ctx.httpOrigin}/directory/identity/${bob.identity}`, {
      headers: { authorization: authDemo }
    });
    assert.equal(bobGet.status, 404);
    assert.deepEqual(await bobGet.json(), { state: 2 });

    const bulkAfterRevoke = await fetch(`${ctx.httpOrigin}/directory/identity/fetch_bulk`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authDemo },
      body: JSON.stringify({ identities: [alice.identity, bob.identity, charlie.identity] })
    });
    const bulkAfterJson = (await bulkAfterRevoke.json()) as any;
    assert.equal(bulkAfterJson.identities.length, 1);
    assert.equal(bulkAfterJson.identities[0].identity, alice.identity);

    const checkAfter = await fetch(`${ctx.httpOrigin}/directory/identity/check`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authDemo },
      body: JSON.stringify({ identities: [alice.identity, bob.identity, charlie.identity] })
    });
    assert.deepEqual(((await checkAfter.json()) as any).states, [0, 2, 2]);

    const blobCredRevoked = await fetch(`${ctx.httpOrigin}/directory/identity/blob_cred`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identity: bob.identity })
    });
    assert.equal(blobCredRevoked.status, 404);
  });
});
