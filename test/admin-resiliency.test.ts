import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import {
  ADMIN_KEY,
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  basicAuthHeader,
  buildMessageBoxPayload,
  connectD2mDevice,
  createIdentityViaDirectory,
  solveAuthenticatedPost,
  startTestServer
} from "./helpers.js";

describe("Admin UI/API, Housekeeping Sweeper, Rate Limiting & Error Handling", () => {
  let ctx: TestServerContext;
  const authDemo = basicAuthHeader(DEMO_USER, DEMO_PASS);

  before(async () => {
    ctx = await startTestServer();
  });

  after(async () => {
    await ctx.stopAndCleanup();
  });

  it("serves /admin/ui unauthenticated, secures /admin/* with constant-time key, and supports full CRUD", async () => {
    const uiRes = await fetch(`${ctx.httpOrigin}/admin/ui`);
    assert.equal(uiRes.status, 200);
    assert.ok((uiRes.headers.get("content-type") ?? "").includes("text/html"));
    const html = await uiRes.text();
    assert.ok(html.includes("Threema OnPrem Admin"));

    assert.equal((await fetch(`${ctx.httpOrigin}/admin/status`)).status, 401);
    assert.equal(
      (await fetch(`${ctx.httpOrigin}/admin/status`, { headers: { "x-admin-key": "wrong" } })).status,
      401
    );

    const statusRes = await fetch(`${ctx.httpOrigin}/admin/status`, {
      headers: { "x-admin-key": ADMIN_KEY }
    });
    assert.equal(statusRes.status, 200);
    const statusJson = (await statusRes.json()) as any;
    assert.ok(statusJson.keys.oppfPublicKeyBase64);
    assert.ok(statusJson.live.csp && statusJson.live.d2m && statusJson.live.rendezvous);

    // Account CRUD + password reset
    const accPost = await fetch(`${ctx.httpOrigin}/admin/accounts`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({ username: "carol", password: "pw1", firstName: "Carol" })
    });
    assert.equal(accPost.status, 201);
    const { account } = (await accPost.json()) as any;

    const accPatch = await fetch(`${ctx.httpOrigin}/admin/accounts/${account.id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({ password: "pw2", enabled: false })
    });
    assert.equal(accPatch.status, 200);

    const disabledLic = await fetch(`${ctx.httpOrigin}/directory/check_license`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ licenseUsername: "carol", licensePassword: "pw2" })
    });
    assert.equal(((await disabledLic.json()) as any).success, false);

    await fetch(`${ctx.httpOrigin}/admin/accounts/${account.id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({ enabled: true })
    });
    const reenabledLic = await fetch(`${ctx.httpOrigin}/directory/check_license`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ licenseUsername: "carol", licensePassword: "pw2" })
    });
    assert.equal(((await reenabledLic.json()) as any).success, true);

    assert.equal(
      (
        await fetch(`${ctx.httpOrigin}/admin/accounts/${account.id}`, {
          method: "DELETE",
          headers: { "x-admin-key": ADMIN_KEY }
        })
      ).status,
      204
    );

    // Identity delete
    const tempUser = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);
    assert.equal(
      (
        await fetch(`${ctx.httpOrigin}/admin/identities/${tempUser.identity}`, {
          method: "DELETE",
          headers: { "x-admin-key": ADMIN_KEY }
        })
      ).status,
      204
    );

    // Spam report list + dismiss
    const repReporter = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);
    await solveAuthenticatedPost(
      `${ctx.httpOrigin}/directory/identity/report_junk`,
      authDemo,
      repReporter.identity,
      repReporter.keys.secretKey,
      { targetIdentity: "ZZZZZZZZ", reason: "test" }
    );
    const reps = ((await (await fetch(`${ctx.httpOrigin}/admin/reports`, { headers: { "x-admin-key": ADMIN_KEY } })).json()) as any).reports;
    assert.ok(reps.length >= 1);
    assert.equal(
      (
        await fetch(`${ctx.httpOrigin}/admin/reports/${reps[0].id}`, {
          method: "DELETE",
          headers: { "x-admin-key": ADMIN_KEY }
        })
      ).status,
      204
    );

    // D2M devices list + admin drop
    const d2m = await connectD2mDevice(ctx.wsOrigin, 0x9988776655443322n);
    const devs = ((await (await fetch(`${ctx.httpOrigin}/admin/devices`, { headers: { "x-admin-key": ADMIN_KEY } })).json()) as any).groups;
    assert.ok(devs.length >= 1);
    const dgid = Buffer.from(d2m.dgid).toString("hex");
    assert.equal(
      (
        await fetch(`${ctx.httpOrigin}/admin/devices/${dgid}/${0x9988776655443322n.toString()}`, {
          method: "DELETE",
          headers: { "x-admin-key": ADMIN_KEY }
        })
      ).status,
      204
    );
    const closed = await d2m.q.waitClose();
    assert.equal(closed.code, 4113);

    // Malformed JSON returns clean 400 JSON error
    const badJsonRes = await fetch(`${ctx.httpOrigin}/directory/check_license`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not valid json"
    });
    assert.equal(badJsonRes.status, 400);
    assert.deepEqual(await badJsonRes.json(), { error: "Invalid JSON body" });
  });

  it("prunes expired tokens, messages, volatile slots, acked reflections, disk blobs, and Safe backups via /admin/cleanup", async () => {
    const oldDate = new Date(Date.now() - 200 * 86_400_000);
    const twoHoursAgo = new Date(Date.now() - 2 * 3_600_000);

    // Seed expired challenge & authToken
    await ctx.server.prisma.challenge.create({
      data: {
        token: "expired-ch-" + crypto.randomBytes(6).toString("hex"),
        purpose: "test",
        serverEphemeralPriv: new Uint8Array(32),
        expiresAt: new Date(Date.now() - 10_000)
      }
    });
    await ctx.server.prisma.authToken.create({
      data: {
        token: "expired-tok-" + crypto.randomBytes(6).toString("hex"),
        kind: "blob",
        expiresAt: new Date(Date.now() - 10_000)
      }
    });

    // Seed old delivered message & old short-lived message
    const mPayload = buildMessageBoxPayload("AAAAAAAA", "BBBBBBBB", crypto.randomBytes(8), Buffer.from("x"), 0x20);
    await ctx.server.prisma.queuedMessage.create({
      data: {
        fromIdentity: "AAAAAAAA",
        toIdentity: "BBBBBBBB",
        messageId: new Uint8Array(crypto.randomBytes(8)),
        rawPayload: new Uint8Array(mPayload),
        delivered: true,
        createdAt: twoHoursAgo
      }
    });
    await ctx.server.prisma.queuedMessage.create({
      data: {
        fromIdentity: "AAAAAAAA",
        toIdentity: "BBBBBBBB",
        messageId: new Uint8Array(crypto.randomBytes(8)),
        rawPayload: new Uint8Array(mPayload),
        delivered: false,
        createdAt: new Date(Date.now() - 120_000)
      }
    });

    // Seed expired disk blob + persistent disk blob (persistent must survive!)
    const expBlobId = crypto.randomBytes(16).toString("hex");
    const keepBlobId = crypto.randomBytes(16).toString("hex");
    for (const id of [expBlobId, keepBlobId]) {
      const p = path.join(ctx.blobDir, id.slice(0, 2), id);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, Buffer.from("blob-data"));
    }
    await ctx.server.prisma.blobItem.create({
      data: {
        id: expBlobId,
        scope: "usual",
        persist: false,
        storagePath: path.join(expBlobId.slice(0, 2), expBlobId),
        size: 9,
        data: new Uint8Array(0),
        createdAt: oldDate
      }
    });
    await ctx.server.prisma.blobItem.create({
      data: {
        id: keepBlobId,
        scope: "local",
        persist: true,
        storagePath: path.join(keepBlobId.slice(0, 2), keepBlobId),
        size: 9,
        data: new Uint8Array(0),
        createdAt: oldDate
      }
    });

    // Seed expired Safe backup
    const oldBackupId = crypto.randomBytes(32).toString("hex");
    await ctx.server.prisma.safeBackup.create({
      data: { backupId: oldBackupId, data: new Uint8Array(16), updatedAt: oldDate }
    });

    // Seed D2M group with stale volatile slot and fully-acked reflection
    const gHex = crypto.randomBytes(32).toString("hex");
    await ctx.server.prisma.deviceGroup.create({
      data: {
        dgid: gHex,
        encryptedSharedDeviceData: new Uint8Array(0),
        nextReflectId: 2
      }
    });
    await ctx.server.prisma.deviceSlot.createMany({
      data: [
        {
          dgid: gHex,
          deviceId: "1",
          expirationPolicy: 1,
          encryptedDeviceInfo: new Uint8Array(0),
          minReflectId: 1
        },
        {
          dgid: gHex,
          deviceId: "2",
          expirationPolicy: 0, // VOLATILE (stale -> dropped -> reflectId 1 pruned)
          encryptedDeviceInfo: new Uint8Array(0),
          minReflectId: 1,
          lastDisconnectAt: BigInt(Date.now() - 2 * 3_600_000)
        },
        {
          dgid: gHex,
          deviceId: "3",
          expirationPolicy: 1, // PERSISTENT unacked on reflectId 2 -> reflectId 2 kept!
          encryptedDeviceInfo: new Uint8Array(0),
          minReflectId: 2
        }
      ]
    });
    await ctx.server.prisma.reflectedEvent.createMany({
      data: [
        {
          dgid: gHex,
          reflectId: 1,
          senderDeviceId: "1",
          flags: 0,
          timestamp: BigInt(Date.now()),
          envelope: new Uint8Array(8)
        },
        {
          dgid: gHex,
          reflectId: 2,
          senderDeviceId: "1",
          flags: 0,
          timestamp: BigInt(Date.now()),
          envelope: new Uint8Array(8)
        }
      ]
    });
    await ctx.server.prisma.deviceReflectionAck.create({
      data: { dgid: gHex, deviceId: "2", reflectId: 1 }
    });

    const cleanRes = await fetch(`${ctx.httpOrigin}/admin/cleanup`, {
      method: "POST",
      headers: { "x-admin-key": ADMIN_KEY }
    });
    assert.equal(cleanRes.status, 200);
    const { stats } = (await cleanRes.json()) as any;
    assert.ok(stats.expiredChallenges >= 1);
    assert.ok(stats.expiredAuthTokens >= 1);
    assert.ok(stats.prunedMessages >= 2);
    assert.ok(stats.droppedVolatileSlots >= 1);
    assert.equal(stats.prunedReflectedEvents, 1); // reflectId 1 pruned, reflectId 2 preserved for slot 3
    assert.ok(stats.prunedBlobs >= 1);
    assert.ok(stats.prunedSafeBackups >= 1);

    assert.equal(fs.existsSync(path.join(ctx.blobDir, expBlobId.slice(0, 2), expBlobId)), false);
    assert.equal(fs.existsSync(path.join(ctx.blobDir, keepBlobId.slice(0, 2), keepBlobId)), true);

    // Once slot 3 acks reflectId 2, next cleanup prunes reflectId 2 as well
    await ctx.server.prisma.deviceReflectionAck.create({
      data: { dgid: gHex, deviceId: "3", reflectId: 2 }
    });
    const cleanRes2 = await fetch(`${ctx.httpOrigin}/admin/cleanup`, {
      method: "POST",
      headers: { "x-admin-key": ADMIN_KEY }
    });
    assert.equal(((await cleanRes2.json()) as any).stats.prunedReflectedEvents, 1);
  });

  it("enforces sliding-window rate limits with 429 and Retry-After", async () => {
    const rlCtx = await startTestServer({
      rateLimitEnabled: true,
      rateLimitWindowMs: 10_000,
      rateLimitMaxRequests: 3
    });
    try {
      for (let i = 0; i < 3; i++) {
        const ok = await fetch(`${rlCtx.httpOrigin}/directory/check_license`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ licenseUsername: DEMO_USER, licensePassword: DEMO_PASS })
        });
        assert.equal(ok.status, 200);
      }
      const throttled = await fetch(`${rlCtx.httpOrigin}/directory/check_license`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ licenseUsername: DEMO_USER, licensePassword: DEMO_PASS })
      });
      assert.equal(throttled.status, 429);
      assert.ok(Number(throttled.headers.get("retry-after")) >= 1);
    } finally {
      await rlCtx.stopAndCleanup();
    }
  });
});
