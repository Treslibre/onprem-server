import assert from "node:assert/strict";
import crypto from "node:crypto";
import dgram from "node:dgram";
import net from "node:net";
import { after, before, describe, it } from "node:test";
import {
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  basicAuthHeader,
  createIdentityViaDirectory,
  solveAuthenticatedPost,
  startTestServer
} from "./helpers.js";

describe("Built-in STUN / TURN Server", () => {
  let ctx: TestServerContext;
  const authDemo = basicAuthHeader(DEMO_USER, DEMO_PASS);

  before(async () => {
    ctx = await startTestServer({
      turnEnabled: true,
      turnPort: 0,
      turnHost: "127.0.0.1",
      turnExternalIp: "127.0.0.1",
      turnMinPort: 0,
      turnMaxPort: 0
    });
  });

  after(async () => {
    await ctx.stopAndCleanup();
  });

  it("relays UDP & TCP TURN allocations with HMAC-SHA1 credentials from /directory/identity/turn_cred", async () => {
    assert.ok(ctx.turnPort > 0);
    const alice = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);
    const bob = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    const aliceTurn = await solveAuthenticatedPost<{
      success: boolean;
      turnUrls: string[];
      turnUsername: string;
      turnPassword: string;
      expiration: number;
    }>(`${ctx.httpOrigin}/directory/identity/turn_cred`, authDemo, alice.identity, alice.keys.secretKey, {
      type: "call"
    });
    const bobTurn = await solveAuthenticatedPost<{
      success: boolean;
      turnUrls: string[];
      turnUsername: string;
      turnPassword: string;
      expiration: number;
    }>(`${ctx.httpOrigin}/directory/identity/turn_cred`, authDemo, bob.identity, bob.keys.secretKey, {
      type: "call"
    });
    assert.equal(aliceTurn.success, true);
    assert.equal(bobTurn.success, true);
    assert.equal(aliceTurn.expiration, 3600);
    assert.ok(aliceTurn.turnUrls.includes(`turn:127.0.0.1:${ctx.turnPort}?transport=udp`));
    assert.ok(aliceTurn.turnUrls.includes(`turn:127.0.0.1:${ctx.turnPort}?transport=tcp`));

    const STUN_COOKIE = 0x2112a442;
    const stunAttr = (type: number, val: Uint8Array): Buffer => {
      const pad = (4 - (val.byteLength % 4)) % 4;
      const b = Buffer.alloc(4 + val.byteLength + pad);
      b.writeUInt16BE(type, 0);
      b.writeUInt16BE(val.byteLength, 2);
      Buffer.from(val).copy(b, 4);
      return b;
    };
    const encodeXorPeer = (ip: string, port: number): Buffer => {
      const v = Buffer.alloc(8);
      v.writeUInt8(0x01, 1);
      v.writeUInt16BE((port ^ (STUN_COOKIE >>> 16)) & 0xffff, 2);
      const octets = ip.split(".").map((n) => parseInt(n, 10));
      const c = Buffer.alloc(4);
      c.writeUInt32BE(STUN_COOKIE, 0);
      for (let i = 0; i < 4; i++) v[4 + i] = octets[i] ^ c[i];
      return stunAttr(0x0012, v);
    };
    const buildClientStun = (
      msgType: number,
      txId: Buffer,
      attrs: Buffer[],
      longTermKey?: Buffer
    ): Buffer => {
      const attrsLen = attrs.reduce((s, a) => s + a.byteLength, 0);
      const totalLen = attrsLen + (longTermKey ? 24 : 0);
      const hdr = Buffer.alloc(20);
      hdr.writeUInt16BE(msgType, 0);
      hdr.writeUInt16BE(totalLen, 2);
      hdr.writeUInt32BE(STUN_COOKIE, 4);
      txId.copy(hdr, 8, 0, 12);
      if (!longTermKey) return Buffer.concat([hdr, ...attrs]);
      const preMi = Buffer.concat([hdr, ...attrs]);
      const mi = crypto.createHmac("sha1", longTermKey).update(preMi).digest();
      return Buffer.concat([preMi, stunAttr(0x0008, mi)]);
    };
    const parseXor = (v: Buffer): { ip: string; port: number } => {
      const port = (v.readUInt16BE(2) ^ (STUN_COOKIE >>> 16)) & 0xffff;
      const c = Buffer.alloc(4);
      c.writeUInt32BE(STUN_COOKIE, 0);
      const ip = `${v[4] ^ c[0]}.${v[5] ^ c[1]}.${v[6] ^ c[2]}.${v[7] ^ c[3]}`;
      return { ip, port };
    };
    const parseServerStun = (raw: Buffer) => {
      const msgType = raw.readUInt16BE(0);
      const msgLen = raw.readUInt16BE(2);
      const out: {
        msgType: number;
        errorCode?: number;
        realm?: string;
        nonce?: string;
        lifetime?: number;
        xorMapped?: { ip: string; port: number };
        xorRelayed?: { ip: string; port: number };
        xorPeer?: { ip: string; port: number };
        data?: Buffer;
      } = { msgType };
      let off = 20;
      const end = 20 + msgLen;
      while (off + 4 <= end) {
        const t = raw.readUInt16BE(off);
        const l = raw.readUInt16BE(off + 2);
        const pad = (l + 3) & ~3;
        const val = raw.subarray(off + 4, off + 4 + l);
        if (t === 0x0009 && val.byteLength >= 4) out.errorCode = val[2] * 100 + val[3];
        if (t === 0x0014) out.realm = val.toString("utf8");
        if (t === 0x0015) out.nonce = val.toString("utf8");
        if (t === 0x000d && val.byteLength >= 4) out.lifetime = val.readUInt32BE(0);
        if (t === 0x0020) out.xorMapped = parseXor(val);
        if (t === 0x0016) out.xorRelayed = parseXor(val);
        if (t === 0x0012) out.xorPeer = parseXor(val);
        if (t === 0x0013) out.data = Buffer.from(val);
        off += 4 + pad;
      }
      return out;
    };

    const udpA = dgram.createSocket("udp4");
    await new Promise<void>((resolve) => udpA.bind(0, "127.0.0.1", resolve));
    const udpQueue: Buffer[] = [];
    const udpWaiters: Array<(b: Buffer) => void> = [];
    udpA.on("message", (msg) => {
      const copy = Buffer.from(msg);
      const w = udpWaiters.shift();
      if (w) w(copy);
      else udpQueue.push(copy);
    });
    const nextUdp = (ms = 4000): Promise<Buffer> =>
      udpQueue.length > 0
        ? Promise.resolve(udpQueue.shift()!)
        : new Promise((resolve, reject) => {
            const t = setTimeout(() => reject(new Error("UDP TURN response timeout")), ms);
            udpWaiters.push((b) => {
              clearTimeout(t);
              resolve(b);
            });
          });

    const tcpB = net.createConnection({ host: "127.0.0.1", port: ctx.turnPort });
    await new Promise<void>((resolve, reject) => {
      tcpB.once("connect", resolve);
      tcpB.once("error", reject);
    });
    let tcpRx = Buffer.alloc(0);
    const tcpFrames: Array<{ kind: "stun"; buf: Buffer } | { kind: "channel"; ch: number; data: Buffer }> = [];
    const tcpWaiters: Array<(f: { kind: "stun"; buf: Buffer } | { kind: "channel"; ch: number; data: Buffer }) => void> = [];
    tcpB.on("data", (chunk) => {
      tcpRx = Buffer.concat([tcpRx, chunk]);
      while (tcpRx.byteLength >= 4) {
        const first2 = tcpRx.readUInt16BE(0);
        let frame: { kind: "stun"; buf: Buffer } | { kind: "channel"; ch: number; data: Buffer } | undefined;
        if ((first2 & 0xc000) === 0x0000) {
          if (tcpRx.byteLength < 20) break;
          const total = 20 + tcpRx.readUInt16BE(2);
          if (tcpRx.byteLength < total) break;
          frame = { kind: "stun", buf: Buffer.from(tcpRx.subarray(0, total)) };
          tcpRx = tcpRx.subarray(total);
        } else {
          const dataLen = tcpRx.readUInt16BE(2);
          const padded = 4 + ((dataLen + 3) & ~3);
          if (tcpRx.byteLength < padded) break;
          frame = { kind: "channel", ch: first2, data: Buffer.from(tcpRx.subarray(4, 4 + dataLen)) };
          tcpRx = tcpRx.subarray(padded);
        }
        const w = tcpWaiters.shift();
        if (w) w(frame);
        else tcpFrames.push(frame);
      }
    });
    const nextTcp = (ms = 4000) =>
      tcpFrames.length > 0
        ? Promise.resolve(tcpFrames.shift()!)
        : new Promise<{ kind: "stun"; buf: Buffer } | { kind: "channel"; ch: number; data: Buffer }>(
            (resolve, reject) => {
              const t = setTimeout(() => reject(new Error("TCP TURN response timeout")), ms);
              tcpWaiters.push((f) => {
                clearTimeout(t);
                resolve(f);
              });
            }
          );

    try {
      const bindPkt = buildClientStun(0x0001, crypto.randomBytes(12), []);
      udpA.send(bindPkt, ctx.turnPort, "127.0.0.1");
      const bindRes = parseServerStun(await nextUdp());
      assert.equal(bindRes.msgType, 0x0101);
      assert.equal(bindRes.xorMapped?.ip, "127.0.0.1");
      assert.equal(bindRes.xorMapped?.port, udpA.address().port);

      const reqUdpTransport = Buffer.from([17, 0, 0, 0]);
      udpA.send(
        buildClientStun(0x0003, crypto.randomBytes(12), [stunAttr(0x0019, reqUdpTransport)]),
        ctx.turnPort,
        "127.0.0.1"
      );
      const aliceChallenge = parseServerStun(await nextUdp());
      assert.equal(aliceChallenge.msgType, 0x0113);
      assert.equal(aliceChallenge.errorCode, 401);

      const aliceKey = crypto
        .createHash("md5")
        .update(`${aliceTurn.turnUsername}:${aliceChallenge.realm}:${aliceTurn.turnPassword}`, "utf8")
        .digest();
      udpA.send(
        buildClientStun(
          0x0003,
          crypto.randomBytes(12),
          [
            stunAttr(0x0019, reqUdpTransport),
            stunAttr(0x0006, Buffer.from(aliceTurn.turnUsername, "utf8")),
            stunAttr(0x0014, Buffer.from(aliceChallenge.realm!, "utf8")),
            stunAttr(0x0015, Buffer.from(aliceChallenge.nonce!, "utf8"))
          ],
          aliceKey
        ),
        ctx.turnPort,
        "127.0.0.1"
      );
      const aliceRelay = parseServerStun(await nextUdp()).xorRelayed!;
      assert.ok(aliceRelay.port > 0);

      tcpB.write(buildClientStun(0x0003, crypto.randomBytes(12), [stunAttr(0x0019, reqUdpTransport)]));
      const bobChFrame = await nextTcp();
      assert.equal(bobChFrame.kind, "stun");
      const bobChallenge = parseServerStun(bobChFrame.buf);
      assert.equal(bobChallenge.errorCode, 401);

      const bobKey = crypto
        .createHash("md5")
        .update(`${bobTurn.turnUsername}:${bobChallenge.realm}:${bobTurn.turnPassword}`, "utf8")
        .digest();
      tcpB.write(
        buildClientStun(
          0x0003,
          crypto.randomBytes(12),
          [
            stunAttr(0x0019, reqUdpTransport),
            stunAttr(0x0006, Buffer.from(bobTurn.turnUsername, "utf8")),
            stunAttr(0x0014, Buffer.from(bobChallenge.realm!, "utf8")),
            stunAttr(0x0015, Buffer.from(bobChallenge.nonce!, "utf8"))
          ],
          bobKey
        )
      );
      const bobAllocFrame = await nextTcp();
      assert.equal(bobAllocFrame.kind, "stun");
      const bobRelay = parseServerStun(bobAllocFrame.buf).xorRelayed!;
      assert.ok(bobRelay.port > 0);

      udpA.send(
        buildClientStun(
          0x0008,
          crypto.randomBytes(12),
          [
            encodeXorPeer(bobRelay.ip, bobRelay.port),
            stunAttr(0x0006, Buffer.from(aliceTurn.turnUsername, "utf8")),
            stunAttr(0x0014, Buffer.from(aliceChallenge.realm!, "utf8")),
            stunAttr(0x0015, Buffer.from(aliceChallenge.nonce!, "utf8"))
          ],
          aliceKey
        ),
        ctx.turnPort,
        "127.0.0.1"
      );
      assert.equal(parseServerStun(await nextUdp()).msgType, 0x0108);

      const chAttr = Buffer.alloc(4);
      chAttr.writeUInt16BE(0x4000, 0);
      tcpB.write(
        buildClientStun(
          0x0009,
          crypto.randomBytes(12),
          [
            stunAttr(0x000c, chAttr),
            encodeXorPeer(aliceRelay.ip, aliceRelay.port),
            stunAttr(0x0006, Buffer.from(bobTurn.turnUsername, "utf8")),
            stunAttr(0x0014, Buffer.from(bobChallenge.realm!, "utf8")),
            stunAttr(0x0015, Buffer.from(bobChallenge.nonce!, "utf8"))
          ],
          bobKey
        )
      );
      const bindAckFrame = await nextTcp();
      assert.equal(bindAckFrame.kind, "stun");
      assert.equal(parseServerStun(bindAckFrame.buf).msgType, 0x0109);

      const udpToTcpPayload = Buffer.from("hello-udp-to-tcp");
      udpA.send(
        buildClientStun(0x0016, crypto.randomBytes(12), [
          encodeXorPeer(bobRelay.ip, bobRelay.port),
          stunAttr(0x0013, udpToTcpPayload)
        ]),
        ctx.turnPort,
        "127.0.0.1"
      );
      const deliveredToBob = await nextTcp();
      assert.equal(deliveredToBob.kind, "channel");
      assert.equal(deliveredToBob.ch, 0x4000);
      assert.deepEqual(deliveredToBob.data, udpToTcpPayload);

      const tcpToUdpPayload = Buffer.from("reply-tcp-to-udp-!");
      const chPad = (4 - (tcpToUdpPayload.byteLength % 4)) % 4;
      const chPkt = Buffer.alloc(4 + tcpToUdpPayload.byteLength + chPad);
      chPkt.writeUInt16BE(0x4000, 0);
      chPkt.writeUInt16BE(tcpToUdpPayload.byteLength, 2);
      tcpToUdpPayload.copy(chPkt, 4);
      tcpB.write(chPkt);

      const deliveredToAlice = parseServerStun(await nextUdp());
      assert.equal(deliveredToAlice.msgType, 0x0017);
      assert.equal(deliveredToAlice.xorPeer?.port, bobRelay.port);
      assert.deepEqual(deliveredToAlice.data, tcpToUdpPayload);

      const life0 = Buffer.alloc(4);
      life0.writeUInt32BE(0, 0);
      udpA.send(
        buildClientStun(
          0x0004,
          crypto.randomBytes(12),
          [
            stunAttr(0x000d, life0),
            stunAttr(0x0006, Buffer.from(aliceTurn.turnUsername, "utf8")),
            stunAttr(0x0014, Buffer.from(aliceChallenge.realm!, "utf8")),
            stunAttr(0x0015, Buffer.from(aliceChallenge.nonce!, "utf8"))
          ],
          aliceKey
        ),
        ctx.turnPort,
        "127.0.0.1"
      );
      const refreshRes = parseServerStun(await nextUdp());
      assert.equal(refreshRes.msgType, 0x0104);
      assert.equal(refreshRes.lifetime, 0);
    } finally {
      await new Promise<void>((resolve) => udpA.close(() => resolve()));
      tcpB.destroy();
    }
  });
});
