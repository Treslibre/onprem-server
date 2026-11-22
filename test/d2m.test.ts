import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import { WebSocket } from "ws";
import {
  blake2bMac256,
  concatBytes,
  deriveCurve25519PublicKey
} from "../src/crypto/primitives.js";
import { CspPayloadType } from "../src/csp/protocol.js";
import {
  D2mCloseCode,
  D2mPayloadType,
  decodeDeviceIdOnly,
  decodeDevicesInfo,
  decodeTransactionNotification,
  encodeBeginTransaction,
  encodeClientUrlInfo,
  encodeDeviceIdOnly
} from "../src/d2m/proto.js";
import {
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  basicAuthHeader,
  buildMessageBoxPayload,
  connectCspClient,
  connectD2mDevice,
  connectD2mWithGroup,
  connectMdDeviceWithCsp,
  createIdentityViaDirectory,
  startTestServer
} from "./helpers.js";

describe("D2M Mediator, Concurrent CSP Proxy & Rendezvous", () => {
  let ctx: TestServerContext;
  const authDemo = basicAuthHeader(DEMO_USER, DEMO_PASS);

  before(async () => {
    ctx = await startTestServer();
  });

  after(async () => {
    await ctx.stopAndCleanup();
  });

  it("handles D2M handshake, reflection, transactions (including TTL expiry 4011), and device drop", async () => {
    const dev1Id = 0x1122334455667788n;
    const dev2Id = 0x8877665544332211n;

    const { q: q1, dgpk, urlInfoHex } = await connectD2mDevice(ctx.wsOrigin, dev1Id);
    assert.equal((await q1.next()).payloadType, D2mPayloadType.REFLECTION_QUEUE_DRY);
    assert.equal((await q1.next()).payloadType, D2mPayloadType.ROLE_PROMOTED_TO_LEADER);

    const q2 = await connectD2mWithGroup(ctx.wsOrigin, urlInfoHex, dgpk, dev2Id);
    assert.equal((await q2.next()).payloadType, D2mPayloadType.REFLECTION_QUEUE_DRY);

    // GetDevicesInfo
    q1.send(D2mPayloadType.GET_DEVICES_INFO, new Uint8Array(0));
    const devInfoMsg = await q1.next();
    assert.equal(devInfoMsg.payloadType, D2mPayloadType.DEVICES_INFO);
    const devMap = decodeDevicesInfo(devInfoMsg.payload);
    assert.equal(devMap.size, 2);
    assert.ok(devMap.has(dev1Id));
    assert.ok(devMap.has(dev2Id));

    // Reflect from dev1 -> dev2
    const envBytes = Buffer.from("encrypted-sync-envelope");
    const reflectFrame = Buffer.alloc(8 + envBytes.byteLength);
    reflectFrame.writeUInt8(8, 0);
    reflectFrame.writeUInt8(0, 1);
    reflectFrame.writeUInt16LE(0, 2);
    reflectFrame.writeUInt32LE(42, 4);
    envBytes.copy(reflectFrame, 8);
    q1.send(D2mPayloadType.REFLECT, new Uint8Array(reflectFrame));

    const rAck = await q1.next();
    assert.equal(rAck.payloadType, D2mPayloadType.REFLECT_ACK);
    assert.equal(Buffer.from(rAck.payload).readUInt32LE(4), 42);

    const rBroadcast = await q2.next();
    assert.equal(rBroadcast.payloadType, D2mPayloadType.REFLECTED);
    const serverReflectId = Buffer.from(rBroadcast.payload).readUInt32LE(4);
    assert.deepEqual(rBroadcast.payload.subarray(16), new Uint8Array(envBytes));

    // Transactions: dev1 acquires, dev2 rejected, dev1 commits, dev2 gets TransactionEnded
    const txScope = Buffer.from("scope-contacts");
    q1.send(D2mPayloadType.BEGIN_TRANSACTION, encodeBeginTransaction(txScope, 30));
    assert.equal((await q1.next()).payloadType, D2mPayloadType.BEGIN_TRANSACTION_ACK);

    q2.send(D2mPayloadType.BEGIN_TRANSACTION, encodeBeginTransaction(txScope, 30));
    const txRej = await q2.next();
    assert.equal(txRej.payloadType, D2mPayloadType.TRANSACTION_REJECTED);
    assert.equal(decodeTransactionNotification(txRej.payload).deviceId, dev1Id);

    q1.send(D2mPayloadType.COMMIT_TRANSACTION, new Uint8Array(0));
    assert.equal((await q1.next()).payloadType, D2mPayloadType.COMMIT_TRANSACTION_ACK);
    const txEnd = await q2.next();
    assert.equal(txEnd.payloadType, D2mPayloadType.TRANSACTION_ENDED);
    assert.equal(decodeTransactionNotification(txEnd.payload).deviceId, dev1Id);

    // ReflectedAck from dev2
    const redAck = Buffer.alloc(8);
    redAck.writeUInt32LE(serverReflectId, 4);
    q2.send(D2mPayloadType.REFLECTED_ACK, new Uint8Array(redAck));

    // SetSharedDeviceData
    const sharedEnc = Buffer.from("shared-device-data-blob");
    const setShared = Buffer.alloc(2 + sharedEnc.byteLength);
    setShared[0] = 0x0a;
    setShared[1] = sharedEnc.byteLength;
    sharedEnc.copy(setShared, 2);
    q1.send(D2mPayloadType.SET_SHARED_DEVICE_DATA, new Uint8Array(setShared));

    // Drop dev2
    q1.send(D2mPayloadType.DROP_DEVICE, encodeDeviceIdOnly(dev2Id));
    const dropAck = await q1.next();
    assert.equal(dropAck.payloadType, D2mPayloadType.DROP_DEVICE_ACK);
    assert.equal(decodeDeviceIdOnly(dropAck.payload), dev2Id);
    const closed2 = await q2.waitClose();
    assert.equal(closed2.code, D2mCloseCode.DEVICE_DROPPED);

    // Transaction TTL=1s expiration closes holding client with 4011 TRANSACTION_TTL_REACHED
    q1.send(D2mPayloadType.BEGIN_TRANSACTION, encodeBeginTransaction(txScope, 1));
    assert.equal((await q1.next()).payloadType, D2mPayloadType.BEGIN_TRANSACTION_ACK);
    const ttlClosed = await q1.waitClose(3000);
    assert.equal(ttlClosed.code, D2mCloseCode.TRANSACTION_TTL_REACHED);
  });

  it("supports concurrent D2M+CSP handshakes, multi-device routing, flags, minReflectId, and leader failover", async () => {
    const serverCspPub = ctx.server.keyManager.getCspKeyPair().publicKey;
    const alice = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);
    const bob = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    const dgk = new Uint8Array(crypto.randomBytes(32));
    const dgpk = blake2bMac256(dgk, new Uint8Array(0), { personal: "3ma-mdev", salt: "p" });
    const dgid = deriveCurve25519PublicKey(dgpk);
    const urlInfoHex = Buffer.from(
      encodeClientUrlInfo({ deviceGroupId: dgid, serverGroup: "0" })
    ).toString("hex");

    const dev1Id = 0x1111222233334444n;
    const dev2Id = 0x5555666677778888n;

    const md1 = await connectMdDeviceWithCsp(
      ctx.wsOrigin,
      serverCspPub,
      urlInfoHex,
      dgpk,
      dev1Id,
      dev1Id,
      alice.identity,
      alice.keys
    );
    await md1.waitForD2m(D2mPayloadType.ROLE_PROMOTED_TO_LEADER);

    const bobConn = await connectCspClient(
      "127.0.0.1",
      ctx.cspPort,
      serverCspPub,
      bob.identity,
      bob.keys
    );
    assert.equal((await bobConn.readFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);

    // Bob -> Alice while md1 has NOT unblocked incoming yet
    const msgAId = new Uint8Array(crypto.randomBytes(8));
    const boxRealA = buildMessageBoxPayload(
      bob.identity,
      alice.identity,
      msgAId,
      Buffer.from("queued-before-unblock")
    );
    bobConn.sendFrame(CspPayloadType.OUTGOING_MESSAGE, boxRealA);
    assert.equal((await bobConn.readFrame()).payloadType, CspPayloadType.OUTGOING_MESSAGE_ACK);

    // Reflect before dev2 joins -> dev2's minReflectId skips it
    const preJoinEnv = Buffer.from("reflection-before-dev2-joined");
    const preReflectFrame = Buffer.alloc(8 + preJoinEnv.byteLength);
    preReflectFrame.writeUInt8(8, 0);
    preReflectFrame.writeUInt32LE(7, 4);
    preJoinEnv.copy(preReflectFrame, 8);
    md1.sendD2m(D2mPayloadType.REFLECT, new Uint8Array(preReflectFrame));
    assert.equal((await md1.waitForD2m(D2mPayloadType.REFLECT_ACK)).payloadType, D2mPayloadType.REFLECT_ACK);

    const md2 = await connectMdDeviceWithCsp(
      ctx.wsOrigin,
      serverCspPub,
      urlInfoHex,
      dgpk,
      dev2Id,
      dev2Id,
      alice.identity,
      alice.keys
    );

    md1.sendCsp(CspPayloadType.UNBLOCK_INCOMING_MESSAGES, new Uint8Array(0));
    const inA = await md1.readCspFrame();
    assert.equal(inA.payloadType, CspPayloadType.INCOMING_MESSAGE);
    assert.deepEqual(inA.payload, boxRealA);
    assert.equal((await md1.readCspFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);
    md1.sendCsp(
      CspPayloadType.INCOMING_MESSAGE_ACK,
      concatBytes(Buffer.from(bob.identity, "ascii"), msgAId)
    );

    // Live message to leader dev1
    const msgBId = new Uint8Array(crypto.randomBytes(8));
    const boxB = buildMessageBoxPayload(bob.identity, alice.identity, msgBId, Buffer.from("live-to-leader"));
    bobConn.sendFrame(CspPayloadType.OUTGOING_MESSAGE, boxB);
    assert.equal((await bobConn.readFrame()).payloadType, CspPayloadType.OUTGOING_MESSAGE_ACK);
    const inB = await md1.readCspFrame();
    assert.equal(inB.payloadType, CspPayloadType.INCOMING_MESSAGE);
    assert.deepEqual(inB.payload, boxB);
    md1.sendCsp(
      CspPayloadType.INCOMING_MESSAGE_ACK,
      concatBytes(Buffer.from(bob.identity, "ascii"), msgBId)
    );
    md1.sendCsp(CspPayloadType.ECHO_REQUEST, new Uint8Array([9, 8, 7, 6]));
    assert.equal((await md1.readCspFrame()).payloadType, CspPayloadType.ECHO_RESPONSE);

    // Follower dev2 can send concurrently
    const msgCId = new Uint8Array(crypto.randomBytes(8));
    const boxC = buildMessageBoxPayload(alice.identity, bob.identity, msgCId, Buffer.from("from-follower-dev2"));
    md2.sendCsp(CspPayloadType.OUTGOING_MESSAGE, boxC);
    assert.equal((await md2.readCspFrame()).payloadType, CspPayloadType.OUTGOING_MESSAGE_ACK);
    const bobInC = await bobConn.readFrame();
    assert.equal(bobInC.payloadType, CspPayloadType.INCOMING_MESSAGE);
    assert.deepEqual(bobInC.payload, boxC);
    bobConn.close();

    // Leader failover when dev1 disconnects -> dev2 promoted
    md1.close();
    await md2.waitForD2m(D2mPayloadType.ROLE_PROMOTED_TO_LEADER);
    md2.sendCsp(CspPayloadType.UNBLOCK_INCOMING_MESSAGES, new Uint8Array(0));
    assert.equal((await md2.readCspFrame()).payloadType, CspPayloadType.QUEUE_SEND_COMPLETE);
    md2.close();
  });

  it("relays binary WebSocket frames and early-buffered messages via Rendezvous", async () => {
    const channelHex = crypto.randomBytes(16).toString("hex");
    const wsA = new WebSocket(`${ctx.wsOrigin}/rendezvous/${channelHex}`);
    await new Promise<void>((resolve) => wsA.once("open", resolve));

    // Send early frame before peerB connects -> must buffer and flush upon pairing
    const earlyFrame = Buffer.from([10, 20, 30, 40]);
    wsA.send(earlyFrame);

    const wsB = new WebSocket(`${ctx.wsOrigin}/rendezvous/${channelHex}`);
    const firstOnB = await new Promise<Buffer>((resolve) => {
      wsB.once("message", (d) => resolve(Buffer.from(d as Buffer)));
    });
    assert.deepEqual(firstOnB, earlyFrame);

    const closedOnB = new Promise<number>((resolve) => {
      wsB.once("close", (code) => resolve(code));
    });
    wsA.close(1000);
    assert.equal(await closedOnB, 4004);
  });
});
