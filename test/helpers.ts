import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import type { IncomingHttpHeaders } from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { WebSocket } from "ws";
import type { ServerConfig } from "../src/config.js";
import { createServer, type OnPremServerHandle } from "../src/index.js";
import {
  NonceCounter,
  boxDecryptShared,
  boxEncryptShared,
  computeCspVouchMac,
  computeDirectoryChallengeResponse,
  computeWorkChallengeResponse,
  concatBytes,
  deriveCurve25519PublicKey,
  deriveSharedSecret,
  generateCurve25519KeyPair
} from "../src/crypto/primitives.js";
import {
  CLEVER_EXTENSION_MAGIC,
  CspExtensionType,
  CspPayloadType,
  decodeCspContainer,
  encodeCspContainer
} from "../src/csp/protocol.js";
import {
  D2mCloseCode,
  D2mPayloadType,
  decodeD2mContainer,
  decodeServerHello,
  decodeServerInfo,
  encodeClientHello,
  encodeClientUrlInfo,
  encodeD2mContainer
} from "../src/d2m/proto.js";
import { blake2bMac256 } from "../src/crypto/primitives.js";

export const PROJECT_ROOT = path.resolve(import.meta.dirname, "..");
export const DEMO_USER = "demo";
export const DEMO_PASS = "demo-password";
export const ADMIN_KEY = "test-admin-key";

export interface TestServerContext {
  tmpDir: string;
  dbFile: string;
  blobDir: string;
  server: OnPremServerHandle;
  httpOrigin: string;
  wsOrigin: string;
  cspPort: number;
  turnPort: number;
  stopAndCleanup: () => Promise<void>;
}

export async function startTestServer(
  overrides: Partial<ServerConfig> = {}
): Promise<TestServerContext> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "threema-onprem-test-"));
  const dbFile = path.join(tmpDir, "test.db");
  const blobDir = path.join(tmpDir, "blobs");

  const basePgUrl =
    process.env.TEST_DATABASE_URL ||
    process.env.DATABASE_URL ||
    "postgresql://postgres:Emr38253825!@localhost:5432/threema_onprem?schema=public";
  const schemaName = `test_${crypto.randomBytes(8).toString("hex")}`;
  const parsedUrl = new URL(basePgUrl);
  parsedUrl.searchParams.set("schema", schemaName);
  const databaseUrl = parsedUrl.toString();

  const prismaCli = path.join(PROJECT_ROOT, "node_modules", "prisma", "build", "index.js");
  execFileSync(process.execPath, [prismaCli, "db", "push", "--skip-generate"], {
    cwd: PROJECT_ROOT,
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: "pipe"
  });

  const server = createServer({
    databaseUrl,
    blobStorageDir: blobDir,
    host: "127.0.0.1",
    httpPort: 0,
    cspPort: 0,
    cspHost: "127.0.0.1",
    turnEnabled: false,
    tlsEnabled: false,
    defaultWorkUsername: DEMO_USER,
    defaultWorkPassword: DEMO_PASS,
    adminApiKey: ADMIN_KEY,
    rateLimitEnabled: false,
    housekeepingIntervalMinutes: 0,
    logLevel: "silent",
    ...overrides
  });

  const addrs = await server.start();

  const stopAndCleanup = async () => {
    try {
      await server.prisma.$executeRawUnsafe(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`);
    } catch {
      // Ignore schema drop errors during teardown
    }
    await server.stop();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    } catch {
      // Ignore transient Windows handle teardown locks in os.tmpdir()
    }
  };

  return {
    tmpDir,
    dbFile,
    blobDir,
    server,
    httpOrigin: addrs.httpOrigin,
    wsOrigin: addrs.wsOrigin,
    cspPort: addrs.cspPort,
    turnPort: addrs.turnPort,
    stopAndCleanup
  };
}

export function basicAuthHeader(user: string, pass: string): string {
  return `Basic ${Buffer.from(`${user}:${pass}`, "utf8").toString("base64")}`;
}

export async function createIdentityViaDirectory(
  httpOrigin: string,
  authHeader: string
): Promise<{ identity: string; keys: { publicKey: Uint8Array; secretKey: Uint8Array } }> {
  const keys = generateCurve25519KeyPair();
  const pubB64 = Buffer.from(keys.publicKey).toString("base64");

  const r1 = await fetch(`${httpOrigin}/directory/identity/create`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: authHeader },
    body: JSON.stringify({ publicKey: pubB64 })
  });
  assert.equal(r1.status, 200);
  const c1 = (await r1.json()) as { token: string; tokenRespKeyPub: string };

  const shared = deriveSharedSecret(
    new Uint8Array(Buffer.from(c1.tokenRespKeyPub, "base64")),
    keys.secretKey
  );
  const resp = computeDirectoryChallengeResponse(
    shared,
    new Uint8Array(Buffer.from(c1.token, "base64"))
  );

  const r2 = await fetch(`${httpOrigin}/directory/identity/create`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: authHeader },
    body: JSON.stringify({
      publicKey: pubB64,
      token: c1.token,
      response: Buffer.from(resp).toString("base64")
    })
  });
  assert.equal(r2.status, 200);
  const c2 = (await r2.json()) as { success: boolean; identity: string; serverGroup: string };
  assert.equal(c2.success, true);
  assert.equal(c2.identity.length, 8);
  return { identity: c2.identity, keys };
}

export async function solveAuthenticatedPost<T>(
  url: string,
  authHeader: string,
  identity: string,
  secretKey: Uint8Array,
  payload: Record<string, unknown>
): Promise<T> {
  const r1 = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: authHeader },
    body: JSON.stringify({ identity, ...payload })
  });
  assert.equal(r1.status, 200);
  const ch = (await r1.json()) as { token: string; tokenRespKeyPub: string };
  assert.ok(ch.token && ch.tokenRespKeyPub);

  const shared = deriveSharedSecret(
    new Uint8Array(Buffer.from(ch.tokenRespKeyPub, "base64")),
    secretKey
  );
  const resp = computeDirectoryChallengeResponse(
    shared,
    new Uint8Array(Buffer.from(ch.token, "base64"))
  );

  const r2 = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: authHeader },
    body: JSON.stringify({
      identity,
      ...payload,
      token: ch.token,
      response: Buffer.from(resp).toString("base64")
    })
  });
  assert.equal(r2.status, 200);
  return (await r2.json()) as T;
}

export async function solveWorkRequest(
  method: "POST" | "PUT" | "DELETE",
  url: string,
  payload: Record<string, unknown>,
  secretKey: Uint8Array
): Promise<Response> {
  const r1 = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  assert.equal(r1.status, 200);
  const ch = (await r1.json()) as { challengePublicKey: string; challenge: string };
  assert.ok(ch.challengePublicKey && ch.challenge);

  const shared = deriveSharedSecret(
    new Uint8Array(Buffer.from(ch.challengePublicKey, "base64")),
    secretKey
  );
  const resp = computeWorkChallengeResponse(
    shared,
    new Uint8Array(Buffer.from(ch.challenge, "base64"))
  );

  return fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ...payload,
      challenge: ch.challenge,
      response: Buffer.from(resp).toString("base64")
    })
  });
}

export class TcpByteReader {
  private buf = Buffer.alloc(0);
  private waiters: Array<{
    n: number;
    resolve: (chunk: Buffer) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];
  private closedErr?: Error;

  constructor(private readonly socket: net.Socket) {
    socket.on("data", (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.flush();
    });
    socket.on("error", (err) => {
      this.failAll(err);
    });
    socket.on("close", () => {
      this.failAll(new Error("TCP socket closed"));
    });
  }

  private flush(): void {
    while (this.waiters.length > 0 && this.buf.byteLength >= this.waiters[0].n) {
      const w = this.waiters.shift()!;
      clearTimeout(w.timer);
      const out = Buffer.from(this.buf.subarray(0, w.n));
      this.buf = this.buf.subarray(w.n);
      w.resolve(out);
    }
  }

  private failAll(err: Error): void {
    this.closedErr = err;
    while (this.waiters.length > 0) {
      const w = this.waiters.shift()!;
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  readExact(n: number, timeoutMs = 5000): Promise<Buffer> {
    if (this.buf.byteLength >= n) {
      const out = Buffer.from(this.buf.subarray(0, n));
      this.buf = this.buf.subarray(n);
      return Promise.resolve(out);
    }
    if (this.closedErr) return Promise.reject(this.closedErr);
    return new Promise((resolve, reject) => {
      const waiter: {
        n: number;
        resolve: (chunk: Buffer) => void;
        reject: (err: Error) => void;
        timer: NodeJS.Timeout;
      } = {
        n,
        resolve,
        reject,
        timer: setTimeout(() => {
          const idx = this.waiters.indexOf(waiter);
          if (idx !== -1) this.waiters.splice(idx, 1);
          reject(new Error(`Timed out waiting for ${n} bytes from TCP socket`));
        }, timeoutMs)
      };
      waiter.timer.unref();
      this.waiters.push(waiter);
    });
  }
}

export interface CspClientSession {
  socket: net.Socket;
  reader: TcpByteReader;
  clientNonce: NonceCounter;
  serverNonce: NonceCounter;
  kShared: Uint8Array;
  sendFrame: (payloadType: number, payload: Uint8Array) => void;
  readFrame: () => Promise<{ payloadType: number; payload: Uint8Array }>;
  close: () => void;
}

export interface CspConnectOptions {
  cspDeviceId?: bigint;
  messagePayloadVersion?: number;
  deviceCookie?: Uint8Array;
}

export async function connectCspClient(
  host: string,
  port: number,
  serverPermPub: Uint8Array,
  identity: string,
  clientKeys: { publicKey: Uint8Array; secretKey: Uint8Array },
  opts: CspConnectOptions = {}
): Promise<CspClientSession> {
  const socket = net.createConnection({ host, port });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  const reader = new TcpByteReader(socket);

  const clientTemp = generateCurve25519KeyPair();
  const clientCookie = new Uint8Array(crypto.randomBytes(16));
  const clientNonce = new NonceCounter(clientCookie);

  // 1. Send ClientHello (48B)
  socket.write(Buffer.from(concatBytes(clientTemp.publicKey, clientCookie)));

  // 2. Read ServerHello (80B)
  const serverHello = await reader.readExact(80);
  const serverCookie = new Uint8Array(serverHello.subarray(0, 16));
  const serverHelloBox = new Uint8Array(serverHello.subarray(16, 80));
  const serverNonce = new NonceCounter(serverCookie);

  const kPermTemp = deriveSharedSecret(serverPermPub, clientTemp.secretKey);
  const serverHelloPlain = boxDecryptShared(
    serverHelloBox,
    serverNonce.nextNonce(),
    kPermTemp
  );
  const serverTempPub = serverHelloPlain.subarray(0, 32);
  const echoedClientCookie = serverHelloPlain.subarray(32, 48);
  assert.deepEqual(echoedClientCookie, clientCookie);

  const kShared = deriveSharedSecret(serverTempPub, clientTemp.secretKey);

  // 3. Build ClientLogin (csn1 for loginData, csn2 for extensions)
  const csn1 = clientNonce.nextNonce();
  const csn2 = clientNonce.nextNonce();

  const extParts: Uint8Array[] = [];
  const pushExt = (type: number, data: Uint8Array) => {
    const hdr = Buffer.alloc(3);
    hdr.writeUInt8(type, 0);
    hdr.writeUInt16LE(data.byteLength, 1);
    extParts.push(new Uint8Array(hdr), data);
  };
  pushExt(CspExtensionType.CLIENT_INFO, Buffer.from("TestClient/1.0", "utf8"));
  if (opts.cspDeviceId !== undefined) {
    const devBuf = Buffer.alloc(8);
    devBuf.writeBigUInt64LE(opts.cspDeviceId, 0);
    pushExt(CspExtensionType.CSP_DEVICE_ID, new Uint8Array(devBuf));
  }
  pushExt(
    CspExtensionType.MESSAGE_PAYLOAD_VERSION,
    new Uint8Array([opts.messagePayloadVersion ?? 3])
  );
  pushExt(
    CspExtensionType.DEVICE_COOKIE,
    opts.deviceCookie ?? new Uint8Array(crypto.randomBytes(16))
  );

  const extBox = boxEncryptShared(concatBytes(...extParts), csn2, kShared);

  const loginPlain = Buffer.alloc(128, 0);
  Buffer.from(identity, "ascii").copy(loginPlain, 0);
  CLEVER_EXTENSION_MAGIC.copy(loginPlain, 8);
  loginPlain.writeUInt16LE(extBox.byteLength, 38);
  Buffer.from(serverCookie).copy(loginPlain, 40);

  const ss1 = deriveSharedSecret(serverPermPub, clientKeys.secretKey);
  const ss2 = deriveSharedSecret(serverTempPub, clientKeys.secretKey);
  const vouch = computeCspVouchMac(ss1, ss2, serverCookie, clientTemp.publicKey);
  Buffer.from(vouch).copy(loginPlain, 80);

  const loginBox = boxEncryptShared(new Uint8Array(loginPlain), csn1, kShared);
  socket.write(Buffer.from(concatBytes(loginBox, extBox)));

  // 4. Read ServerLoginAck (32B)
  const ackBox = new Uint8Array(await reader.readExact(32));
  const ackPlain = boxDecryptShared(ackBox, serverNonce.nextNonce(), kShared);
  assert.equal(ackPlain.byteLength, 16);

  const sendFrame = (payloadType: number, payload: Uint8Array) => {
    const container = encodeCspContainer(payloadType, payload);
    const box = boxEncryptShared(container, clientNonce.nextNonce(), kShared);
    const frame = Buffer.alloc(2 + box.byteLength);
    frame.writeUInt16LE(box.byteLength, 0);
    Buffer.from(box).copy(frame, 2);
    socket.write(frame);
  };

  const readFrame = async () => {
    const lenBuf = await reader.readExact(2);
    const len = lenBuf.readUInt16LE(0);
    const box = new Uint8Array(await reader.readExact(len));
    const plain = boxDecryptShared(box, serverNonce.nextNonce(), kShared);
    return decodeCspContainer(plain);
  };

  return {
    socket,
    reader,
    clientNonce,
    serverNonce,
    kShared,
    sendFrame,
    readFrame,
    close: () => socket.destroy()
  };
}

export function buildMessageBoxPayload(
  fromId: string,
  toId: string,
  messageId: Uint8Array,
  ciphertext: Uint8Array,
  flags = 0,
  metaBytes?: Uint8Array,
  createdAtSec?: number
): Uint8Array {
  const metaLen = metaBytes ? metaBytes.byteLength : 0;
  const out = Buffer.alloc(64 + metaLen + 24 + ciphertext.byteLength);
  Buffer.from(fromId, "ascii").copy(out, 0);
  Buffer.from(toId, "ascii").copy(out, 8);
  Buffer.from(messageId).copy(out, 16);
  out.writeUInt32LE((createdAtSec ?? Math.floor(Date.now() / 1000)) >>> 0, 24);
  out.writeUInt8(flags, 28);
  out.writeUInt8(0, 29);
  out.writeUInt16LE(metaLen, 30);
  Buffer.from("Alice", "utf8").copy(out, 32);
  if (metaBytes && metaLen > 0) {
    Buffer.from(metaBytes).copy(out, 64);
  }
  crypto.randomBytes(24).copy(out, 64 + metaLen);
  Buffer.from(ciphertext).copy(out, 64 + metaLen + 24);
  return new Uint8Array(out);
}

export class WsQueue {
  private messages: Array<{ payloadType: number; payload: Uint8Array }> = [];
  private waiters: Array<{
    resolve: (msg: { payloadType: number; payload: Uint8Array }) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];
  public closed?: { code: number; reason: string };
  private closedError?: Error;

  constructor(public readonly ws: WebSocket) {
    ws.on("message", (data) => {
      const buf = Buffer.isBuffer(data) ? new Uint8Array(data) : new Uint8Array(data as ArrayBuffer);
      const decoded = decodeD2mContainer(buf);
      if (this.waiters.length > 0) {
        const w = this.waiters.shift()!;
        clearTimeout(w.timer);
        w.resolve(decoded);
      } else {
        this.messages.push(decoded);
      }
    });
    ws.on("error", (err) => {
      this.failWaiters(err instanceof Error ? err : new Error(String(err)));
    });
    ws.on("close", (code, reason) => {
      const reasonStr = reason.toString("utf8");
      this.closed = { code, reason: reasonStr };
      this.failWaiters(new Error(`WebSocket closed (${code}: ${reasonStr || "no reason"})`));
    });
  }

  private failWaiters(err: Error): void {
    if (!this.closedError) {
      this.closedError = err;
    }
    while (this.waiters.length > 0) {
      const w = this.waiters.shift()!;
      clearTimeout(w.timer);
      w.reject(this.closedError);
    }
  }

  next(timeoutMs = 5000): Promise<{ payloadType: number; payload: Uint8Array }> {
    if (this.messages.length > 0) {
      return Promise.resolve(this.messages.shift()!);
    }
    if (this.closedError) {
      return Promise.reject(this.closedError);
    }
    return new Promise((resolve, reject) => {
      const waiter: {
        resolve: (msg: { payloadType: number; payload: Uint8Array }) => void;
        reject: (err: Error) => void;
        timer: NodeJS.Timeout;
      } = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const idx = this.waiters.indexOf(waiter);
          if (idx !== -1) this.waiters.splice(idx, 1);
          reject(new Error(`Timed out waiting for D2M message after ${timeoutMs}ms`));
        }, timeoutMs)
      };
      waiter.timer.unref();
      this.waiters.push(waiter);
    });
  }

  send(payloadType: number, payload: Uint8Array): void {
    this.ws.send(Buffer.from(encodeD2mContainer(payloadType, payload)));
  }

  waitClose(timeoutMs = 5000): Promise<{ code: number; reason: string }> {
    if (this.closed) return Promise.resolve(this.closed);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("Timed out waiting for WS close")), timeoutMs);
      t.unref();
      this.ws.once("close", (code, reason) => {
        clearTimeout(t);
        resolve({ code, reason: reason.toString("utf8") });
      });
    });
  }
}

export async function connectD2mDevice(
  wsOrigin: string,
  deviceId: bigint,
  expirationPolicy = 1
): Promise<{
  q: WsQueue;
  dgpk: Uint8Array;
  dgid: Uint8Array;
  urlInfoHex: string;
}> {
  const dgk = new Uint8Array(crypto.randomBytes(32));
  const dgpk = blake2bMac256(dgk, new Uint8Array(0), { personal: "3ma-mdev", salt: "p" });
  const dgid = deriveCurve25519PublicKey(dgpk);
  const urlInfoHex = Buffer.from(
    encodeClientUrlInfo({ deviceGroupId: dgid, serverGroup: "0" })
  ).toString("hex");
  const q = await connectD2mWithGroup(wsOrigin, urlInfoHex, dgpk, deviceId, expirationPolicy);
  return { q, dgpk, dgid, urlInfoHex };
}

export async function connectD2mWithGroup(
  wsOrigin: string,
  urlInfoHex: string,
  dgpk: Uint8Array,
  deviceId: bigint,
  expirationPolicy = 1,
  expectedDeviceSlotState = 0
): Promise<WsQueue> {
  const ws = new WebSocket(`${wsOrigin}/mediator/${urlInfoHex}`);
  const q = new WsQueue(ws);
  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });

  const m1 = await q.next();
  assert.equal(m1.payloadType, D2mPayloadType.SERVER_HELLO);
  const serverHello = decodeServerHello(m1.payload);
  assert.equal(serverHello.version, 0);

  const nonce = new Uint8Array(crypto.randomBytes(24));
  const shared = deriveSharedSecret(serverHello.esk, dgpk);
  const respBox = boxEncryptShared(serverHello.challenge, nonce, shared);

  q.send(
    D2mPayloadType.CLIENT_HELLO,
    encodeClientHello({
      version: 0,
      response: concatBytes(nonce, respBox),
      deviceId,
      deviceSlotsExhaustedPolicy: 0,
      deviceSlotExpirationPolicy: expirationPolicy,
      encryptedDeviceInfo: Buffer.from("dev-info"),
      expectedDeviceSlotState
    })
  );

  const m2 = await q.next();
  assert.equal(m2.payloadType, D2mPayloadType.SERVER_INFO);
  const serverInfo = decodeServerInfo(m2.payload);
  assert.equal(serverInfo.maxDeviceSlots, 8);
  return q;
}

export async function connectMdDeviceWithCsp(
  wsOrigin: string,
  serverCspPub: Uint8Array,
  urlInfoHex: string,
  dgpk: Uint8Array,
  deviceId: bigint,
  cspDeviceId: bigint,
  identity: string,
  identityKeys: { publicKey: Uint8Array; secretKey: Uint8Array }
) {
  const ws = new WebSocket(`${wsOrigin}/mediator/${urlInfoHex}`);
  const d2mMessages: Array<{ payloadType: number; payload: Uint8Array }> = [];
  const d2mWaiters: Array<{
    expectedType?: number;
    resolve: (msg: { payloadType: number; payload: Uint8Array }) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];
  let cspBuf = Buffer.alloc(0);
  const cspWaiters: Array<{
    n: number;
    resolve: (chunk: Buffer) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];
  let closedErr: Error | undefined;

  const failAll = (err: Error) => {
    if (!closedErr) closedErr = err;
    while (d2mWaiters.length > 0) {
      const w = d2mWaiters.shift()!;
      clearTimeout(w.timer);
      w.reject(closedErr);
    }
    while (cspWaiters.length > 0) {
      const w = cspWaiters.shift()!;
      clearTimeout(w.timer);
      w.reject(closedErr);
    }
  };

  ws.on("message", (data) => {
    const raw = Buffer.isBuffer(data) ? new Uint8Array(data) : new Uint8Array(data as ArrayBuffer);
    const decoded = decodeD2mContainer(raw);
    if (decoded.payloadType === D2mPayloadType.PROXY) {
      cspBuf = Buffer.concat([cspBuf, Buffer.from(decoded.payload)]);
      while (cspWaiters.length > 0 && cspBuf.byteLength >= cspWaiters[0].n) {
        const w = cspWaiters.shift()!;
        clearTimeout(w.timer);
        const out = Buffer.from(cspBuf.subarray(0, w.n));
        cspBuf = cspBuf.subarray(w.n);
        w.resolve(out);
      }
      return;
    }
    const idx = d2mWaiters.findIndex(
      (w) => w.expectedType === undefined || w.expectedType === decoded.payloadType
    );
    if (idx !== -1) {
      const w = d2mWaiters.splice(idx, 1)[0];
      clearTimeout(w.timer);
      w.resolve(decoded);
    } else {
      d2mMessages.push(decoded);
    }
  });
  ws.on("error", (err) => failAll(err instanceof Error ? err : new Error(String(err))));
  ws.on("close", (code, reason) =>
    failAll(new Error(`MD WS closed (${code}: ${reason.toString("utf8") || "no reason"})`))
  );

  const waitForD2m = (expectedType?: number, timeoutMs = 5000) => {
    const idx = d2mMessages.findIndex(
      (m) => expectedType === undefined || m.payloadType === expectedType
    );
    if (idx !== -1) {
      return Promise.resolve(d2mMessages.splice(idx, 1)[0]);
    }
    if (closedErr) return Promise.reject(closedErr);
    return new Promise<{ payloadType: number; payload: Uint8Array }>((resolve, reject) => {
      const w: {
        expectedType?: number;
        resolve: (msg: { payloadType: number; payload: Uint8Array }) => void;
        reject: (err: Error) => void;
        timer: NodeJS.Timeout;
      } = {
        expectedType,
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = d2mWaiters.indexOf(w);
          if (i !== -1) d2mWaiters.splice(i, 1);
          reject(new Error(`Timed out waiting for D2M payloadType=${expectedType}`));
        }, timeoutMs)
      };
      w.timer.unref();
      d2mWaiters.push(w);
    });
  };

  const readCspExact = (n: number, timeoutMs = 5000): Promise<Buffer> => {
    if (cspBuf.byteLength >= n && cspWaiters.length === 0) {
      const out = Buffer.from(cspBuf.subarray(0, n));
      cspBuf = cspBuf.subarray(n);
      return Promise.resolve(out);
    }
    if (closedErr) return Promise.reject(closedErr);
    return new Promise((resolve, reject) => {
      const w: {
        n: number;
        resolve: (chunk: Buffer) => void;
        reject: (err: Error) => void;
        timer: NodeJS.Timeout;
      } = {
        n,
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = cspWaiters.indexOf(w);
          if (i !== -1) cspWaiters.splice(i, 1);
          reject(new Error(`Timed out waiting for ${n} proxied CSP bytes`));
        }, timeoutMs)
      };
      w.timer.unref();
      cspWaiters.push(w);
    });
  };

  const sendD2m = (payloadType: number, payload: Uint8Array) => {
    ws.send(Buffer.from(encodeD2mContainer(payloadType, payload)));
  };

  await new Promise<void>((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });

  // Immediately start CSP handshake via D2M PROXY BEFORE sending D2M CLIENT_HELLO
  const cspTemp = generateCurve25519KeyPair();
  const cspCookie = new Uint8Array(crypto.randomBytes(16));
  const clientNonce = new NonceCounter(cspCookie);
  sendD2m(D2mPayloadType.PROXY, concatBytes(cspTemp.publicKey, cspCookie));

  const [d2mServerHelloMsg, cspServerHello] = await Promise.all([
    waitForD2m(D2mPayloadType.SERVER_HELLO),
    readCspExact(80)
  ]);

  const serverCookie = new Uint8Array(cspServerHello.subarray(0, 16));
  const serverHelloBox = new Uint8Array(cspServerHello.subarray(16, 80));
  const serverNonce = new NonceCounter(serverCookie);
  const kPermTemp = deriveSharedSecret(serverCspPub, cspTemp.secretKey);
  const serverHelloPlain = boxDecryptShared(
    serverHelloBox,
    serverNonce.nextNonce(),
    kPermTemp
  );
  const serverTempPub = serverHelloPlain.subarray(0, 32);
  assert.deepEqual(serverHelloPlain.subarray(32, 48), cspCookie);
  const kShared = deriveSharedSecret(serverTempPub, cspTemp.secretKey);

  const csn1 = clientNonce.nextNonce();
  const csn2 = clientNonce.nextNonce();
  const extParts: Uint8Array[] = [];
  const pushExt = (type: number, data: Uint8Array) => {
    const hdr = Buffer.alloc(3);
    hdr.writeUInt8(type, 0);
    hdr.writeUInt16LE(data.byteLength, 1);
    extParts.push(new Uint8Array(hdr), data);
  };
  pushExt(CspExtensionType.CLIENT_INFO, Buffer.from("DesktopMdTest/2.0", "utf8"));
  const devBuf = Buffer.alloc(8);
  devBuf.writeBigUInt64LE(cspDeviceId, 0);
  pushExt(CspExtensionType.CSP_DEVICE_ID, new Uint8Array(devBuf));
  pushExt(CspExtensionType.MESSAGE_PAYLOAD_VERSION, new Uint8Array([3]));
  pushExt(CspExtensionType.DEVICE_COOKIE, new Uint8Array(crypto.randomBytes(16)));
  const extBox = boxEncryptShared(concatBytes(...extParts), csn2, kShared);

  const loginPlain = Buffer.alloc(128, 0);
  Buffer.from(identity, "ascii").copy(loginPlain, 0);
  CLEVER_EXTENSION_MAGIC.copy(loginPlain, 8);
  loginPlain.writeUInt16LE(extBox.byteLength, 38);
  Buffer.from(serverCookie).copy(loginPlain, 40);
  const ss1 = deriveSharedSecret(serverCspPub, identityKeys.secretKey);
  const ss2 = deriveSharedSecret(serverTempPub, identityKeys.secretKey);
  Buffer.from(computeCspVouchMac(ss1, ss2, serverCookie, cspTemp.publicKey)).copy(loginPlain, 80);
  const loginBox = boxEncryptShared(new Uint8Array(loginPlain), csn1, kShared);

  sendD2m(D2mPayloadType.PROXY, concatBytes(loginBox, extBox));

  const d2mHello = decodeServerHello(d2mServerHelloMsg.payload);
  const d2mNonce = new Uint8Array(crypto.randomBytes(24));
  const d2mShared = deriveSharedSecret(d2mHello.esk, dgpk);
  sendD2m(
    D2mPayloadType.CLIENT_HELLO,
    encodeClientHello({
      version: 0,
      response: concatBytes(d2mNonce, boxEncryptShared(d2mHello.challenge, d2mNonce, d2mShared)),
      deviceId,
      deviceSlotsExhaustedPolicy: 0,
      deviceSlotExpirationPolicy: 1,
      encryptedDeviceInfo: Buffer.from("md-dev"),
      expectedDeviceSlotState: 0
    })
  );

  const [serverInfoMsg, , cspAckRaw] = await Promise.all([
    waitForD2m(D2mPayloadType.SERVER_INFO),
    waitForD2m(D2mPayloadType.REFLECTION_QUEUE_DRY),
    readCspExact(32)
  ]);
  assert.equal(decodeServerInfo(serverInfoMsg.payload).maxDeviceSlots, 8);
  const cspAckPlain = boxDecryptShared(
    new Uint8Array(cspAckRaw),
    serverNonce.nextNonce(),
    kShared
  );
  assert.equal(cspAckPlain.byteLength, 16);

  const sendCsp = (payloadType: number, payload: Uint8Array) => {
    const container = encodeCspContainer(payloadType, payload);
    const box = boxEncryptShared(container, clientNonce.nextNonce(), kShared);
    const frame = Buffer.alloc(2 + box.byteLength);
    frame.writeUInt16LE(box.byteLength, 0);
    Buffer.from(box).copy(frame, 2);
    sendD2m(D2mPayloadType.PROXY, new Uint8Array(frame));
  };

  const readCspFrame = async () => {
    const lenBuf = await readCspExact(2);
    const boxLen = lenBuf.readUInt16LE(0);
    const box = new Uint8Array(await readCspExact(boxLen));
    const plain = boxDecryptShared(box, serverNonce.nextNonce(), kShared);
    return decodeCspContainer(plain);
  };

  return {
    ws,
    sendD2m,
    waitForD2m,
    sendCsp,
    readCspFrame,
    close: () => {
      if (ws.readyState === WebSocket.OPEN) ws.close(D2mCloseCode.NORMAL);
    }
  };
}

export function httpsRequest(
  caCertPem: string,
  method: "GET" | "HEAD",
  urlStr: string,
  headers: Record<string, string> = {}
): Promise<{ statusCode: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      urlStr,
      {
        method,
        ca: caCertPem,
        rejectUnauthorized: true,
        servername: "localhost",
        checkServerIdentity: (_host, cert) => tls.checkServerIdentity(new URL(urlStr).hostname, cert),
        headers
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8")
          });
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}
