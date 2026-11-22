import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import { concatBytes } from "../src/crypto/primitives.js";
import { CspPayloadType, convertCspMessagePayload } from "../src/csp/protocol.js";
import {
  ADMIN_KEY,
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  basicAuthHeader,
  buildMessageBoxPayload,
  connectCspClient,
  createIdentityViaDirectory,
  startTestServer
} from "./helpers.js";

describe("CSP Protocol, Queuing, Device Cookies, Push Tokens & Revocation", () => {
  let ctx: TestServerContext;
  const authDemo = basicAuthHeader(DEMO_USER, DEMO_PASS);

  before(async () => {
    ctx = await startTestServer();
  });

  after(async () => {
    await ctx.stopAndCleanup();
  });

  it("handles handshake (v0, v1, v3), echo, offline queue, future timestamp clamp, v0 downgrade, and ack", async () => {
    const serverCspPub = ctx.server.keyManager.getCspKeyPair().publicKey;
    const alice = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);
    const bob = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    const aliceConn = await connectCspClient(
      "127.0.0.1",
      ctx.cspPort,
      serverCspPub,
      alice.identity,
      alice.keys,
      { messagePayloadVersion: 3 } // Android 6.6.0 sends 3
    );
    assert.equal((await aliceConn.readFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);

    // Echo request/response
    const echoData = new Uint8Array(crypto.randomBytes(12));
    aliceConn.sendFrame(CspPayloadType.ECHO_REQUEST, echoData);
    const echoReply = await aliceConn.readFrame();
    assert.equal(echoReply.payloadType, CspPayloadType.ECHO_RESPONSE);
    assert.deepEqual(echoReply.payload, echoData);

    // Send offline message with metadata box (v1/v3) & far-future timestamp -> clamped by server & stripped for v0 receiver
    const msgId1 = new Uint8Array(crypto.randomBytes(8));
    const metaBytes = Buffer.from("encrypted-meta-container-bytes");
    const futureTs = Math.floor(Date.now() / 1000) + 36000;
    const beforeSendSec = Math.floor(Date.now() / 1000);
    const box1 = buildMessageBoxPayload(
      alice.identity,
      bob.identity,
      msgId1,
      Buffer.from("hello-offline-bob"),
      0,
      new Uint8Array(metaBytes),
      futureTs
    );
    aliceConn.sendFrame(CspPayloadType.OUTGOING_MESSAGE, box1);

    const outAck1 = await aliceConn.readFrame();
    assert.equal(outAck1.payloadType, CspPayloadType.OUTGOING_MESSAGE_ACK);
    assert.equal(Buffer.from(outAck1.payload.subarray(0, 8)).toString("ascii"), bob.identity);
    assert.deepEqual(outAck1.payload.subarray(8, 16), msgId1);

    // Connect Bob with legacy messagePayloadVersion = 0 and a persistent deviceCookie
    const bobCookie = new Uint8Array(crypto.randomBytes(16));
    const bobConn = await connectCspClient(
      "127.0.0.1",
      ctx.cspPort,
      serverCspPub,
      bob.identity,
      bob.keys,
      { messagePayloadVersion: 0, deviceCookie: bobCookie }
    );
    const bobIn1 = await bobConn.readFrame();
    assert.equal(bobIn1.payloadType, CspPayloadType.INCOMING_MESSAGE);
    const inBuf = Buffer.from(bobIn1.payload);
    assert.equal(inBuf.readUInt16LE(30), 0); // metadata stripped for v0 client
    assert.equal(inBuf.byteLength, box1.byteLength - metaBytes.byteLength);
    const deliveredTs = inBuf.readUInt32LE(24);
    assert.ok(deliveredTs >= beforeSendSec && deliveredTs <= beforeSendSec + 10);
    assert.deepEqual(
      bobIn1.payload,
      convertCspMessagePayload(
        (() => {
          const b = Buffer.from(box1);
          b.writeUInt32LE(deliveredTs, 24);
          return new Uint8Array(b);
        })(),
        0
      )
    );
    assert.equal((await bobConn.readFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);

    bobConn.sendFrame(
      CspPayloadType.INCOMING_MESSAGE_ACK,
      concatBytes(Buffer.from(alice.identity, "ascii"), msgId1)
    );

    // Live push from Bob -> Alice
    const msgId2 = new Uint8Array(crypto.randomBytes(8));
    const box2 = buildMessageBoxPayload(
      bob.identity,
      alice.identity,
      msgId2,
      Buffer.from("hello-live-alice")
    );
    bobConn.sendFrame(CspPayloadType.OUTGOING_MESSAGE, box2);
    assert.equal((await bobConn.readFrame()).payloadType, CspPayloadType.OUTGOING_MESSAGE_ACK);
    const aliceIn2 = await aliceConn.readFrame();
    assert.equal(aliceIn2.payloadType, CspPayloadType.INCOMING_MESSAGE);
    assert.deepEqual(aliceIn2.payload, box2);

    // Short-lived queued message (0x20) created >60s ago is skipped upon login
    const expiredShortId = new Uint8Array(crypto.randomBytes(8));
    const expiredBox = buildMessageBoxPayload(
      alice.identity,
      bob.identity,
      expiredShortId,
      Buffer.from("typing-expired"),
      0x20
    );
    await ctx.server.prisma.queuedMessage.create({
      data: {
        fromIdentity: alice.identity,
        toIdentity: bob.identity,
        messageId: Buffer.from(expiredShortId),
        rawPayload: Buffer.from(expiredBox),
        delivered: false,
        createdAt: new Date(Date.now() - 90_000)
      }
    });

    aliceConn.close();
    bobConn.close();

    // Reconnect Bob with same deviceCookie -> receives neither acked msgId1 nor expired 0x20 message
    const bobConn2 = await connectCspClient(
      "127.0.0.1",
      ctx.cspPort,
      serverCspPub,
      bob.identity,
      bob.keys,
      { messagePayloadVersion: 1, deviceCookie: bobCookie }
    );
    assert.equal((await bobConn2.readFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);
    bobConn2.close();
  });

  it("handles device cookie change detection, push tokens, server alerts, and revoked ID close errors", async () => {
    const serverCspPub = ctx.server.keyManager.getCspKeyPair().publicKey;
    const user = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    const cookie1 = new Uint8Array(crypto.randomBytes(16));
    const cookie2 = new Uint8Array(crypto.randomBytes(16));

    // First single-device login establishes deviceCookie
    const c1 = await connectCspClient("127.0.0.1", ctx.cspPort, serverCspPub, user.identity, user.keys, {
      deviceCookie: cookie1
    });
    assert.equal((await c1.readFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);

    // Register normal + high-prio push tokens
    c1.sendFrame(
      CspPayloadType.SET_PUSH_NOTIFICATION_TOKEN,
      concatBytes(new Uint8Array([0x11]), Buffer.from("fcm-token-abc", "utf8"))
    );
    c1.sendFrame(
      CspPayloadType.SET_HIGH_PRIO_PUSH_NOTIFICATION_TOKEN,
      concatBytes(new Uint8Array([0x05]), Buffer.from("apns-voip-xyz", "utf8"))
    );

    // Server sends ALERT (0xe1) via Admin API
    const alertRes = await fetch(`${ctx.httpOrigin}/admin/alert`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({ identity: user.identity, message: "Maintenance at 23:00" })
    });
    assert.equal(alertRes.status, 200);
    assert.equal(((await alertRes.json()) as any).deliveredCount, 1);

    const alertFrame = await c1.readFrame();
    assert.equal(alertFrame.payloadType, CspPayloadType.ALERT);
    assert.equal(Buffer.from(alertFrame.payload).toString("utf8"), "Maintenance at 23:00");

    const tokensAfterSet = await ctx.server.prisma.pushToken.findMany({
      where: { identityId: user.identity }
    });
    assert.equal(tokensAfterSet.length, 2);
    c1.close();

    // Second login with a DIFFERENT device cookie -> receives DEVICE_COOKIE_CHANGED_INDICATION (0xd2)
    const c2 = await connectCspClient("127.0.0.1", ctx.cspPort, serverCspPub, user.identity, user.keys, {
      deviceCookie: cookie2
    });
    assert.equal((await c2.readFrame()).payloadType, CspPayloadType.DEVICE_COOKIE_CHANGED_INDICATION);
    assert.equal((await c2.readFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);

    // Clear indication (0xd3), then reconnect with cookie2 -> no more 0xd2 warning
    c2.sendFrame(CspPayloadType.CLEAR_DEVICE_COOKIE_CHANGED_INDICATION, new Uint8Array(0));
    const echo = new Uint8Array([1, 2, 3, 4]);
    c2.sendFrame(CspPayloadType.ECHO_REQUEST, echo);
    assert.equal((await c2.readFrame()).payloadType, CspPayloadType.ECHO_RESPONSE);
    c2.close();

    const c3 = await connectCspClient("127.0.0.1", ctx.cspPort, serverCspPub, user.identity, user.keys, {
      deviceCookie: cookie2
    });
    assert.equal((await c3.readFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);

    // Admin revokes user -> live session receives CLOSE_ERROR (canReconnect=0) immediately
    const revRes = await fetch(`${ctx.httpOrigin}/admin/identities/${user.identity}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({ state: 0 })
    });
    assert.equal(revRes.status, 200);

    const kickFrame = await c3.readFrame();
    assert.equal(kickFrame.payloadType, CspPayloadType.CLOSE_ERROR);
    assert.equal(kickFrame.payload[0], 0); // canReconnect = 0
    c3.close();

    // Subsequent login attempt by revoked identity also gets CLOSE_ERROR (canReconnect=0)
    const cRevoked = await connectCspClient(
      "127.0.0.1",
      ctx.cspPort,
      serverCspPub,
      user.identity,
      user.keys,
      { deviceCookie: cookie2 }
    );
    const errFrame = await cRevoked.readFrame();
    assert.equal(errFrame.payloadType, CspPayloadType.CLOSE_ERROR);
    assert.equal(errFrame.payload[0], 0);
    cRevoked.close();
  });
});
