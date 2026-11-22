import crypto from "node:crypto";
import dgram from "node:dgram";
import dns from "node:dns";
import net from "node:net";
import { createLogger } from "../logger.js";

const log = createLogger("TURN");

const STUN_MAGIC_COOKIE = 0x2112a442;
const FINGERPRINT_XOR = 0x5354554e;

const STUN_METHOD = {
  BINDING: 0x0001,
  ALLOCATE: 0x0003,
  REFRESH: 0x0004,
  SEND: 0x0006,
  DATA: 0x0007,
  CREATE_PERMISSION: 0x0008,
  CHANNEL_BIND: 0x0009
} as const;

const STUN_CLASS = {
  REQUEST: 0x0000,
  INDICATION: 0x0010,
  SUCCESS: 0x0100,
  ERROR: 0x0110
} as const;

const STUN_ATTR = {
  USERNAME: 0x0006,
  MESSAGE_INTEGRITY: 0x0008,
  ERROR_CODE: 0x0009,
  CHANNEL_NUMBER: 0x000c,
  LIFETIME: 0x000d,
  XOR_PEER_ADDRESS: 0x0012,
  DATA: 0x0013,
  REALM: 0x0014,
  NONCE: 0x0015,
  XOR_RELAYED_ADDRESS: 0x0016,
  REQUESTED_TRANSPORT: 0x0019,
  XOR_MAPPED_ADDRESS: 0x0020,
  SOFTWARE: 0x8022,
  FINGERPRINT: 0x8028
} as const;

const PERMISSION_TTL_MS = 5 * 60 * 1000;
const CHANNEL_BIND_TTL_MS = 10 * 60 * 1000;
const NONCE_TTL_SEC = 3600;
const DEFAULT_ALLOCATION_LIFETIME_SEC = 600;
const MAX_ALLOCATION_LIFETIME_SEC = 3600;
const MIN_ALLOCATION_LIFETIME_SEC = 60;

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.byteLength; i++) {
    c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function normalizeIp(ip?: string): string {
  if (!ip) return "127.0.0.1";
  if (ip === "::1" || ip === "::") return "127.0.0.1";
  if (ip.startsWith("::ffff:")) {
    const mapped = ip.slice("::ffff:".length);
    if (net.isIPv4(mapped)) return mapped;
  }
  return net.isIPv4(ip) ? ip : "127.0.0.1";
}

function ipv4ToBytes(ip: string): Buffer {
  const parts = ip.split(".").map((p) => parseInt(p, 10) & 0xff);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) {
    return Buffer.from([127, 0, 0, 1]);
  }
  return Buffer.from(parts);
}

function stunMsgType(method: number, cls: number): number {
  return (method & 0x0f80) | (method & 0x0070) | (method & 0x000f) | (cls & 0x0110);
}

function parseStunMsgType(type: number): { method: number; cls: number } {
  const cls = ((type & 0x0100) !== 0 ? 0x0100 : 0) | ((type & 0x0010) !== 0 ? 0x0010 : 0);
  const method = type & ~0x0110;
  return { method, cls };
}

function encodeAttr(type: number, value: Uint8Array): Buffer {
  const padLen = (4 - (value.byteLength % 4)) % 4;
  const out = Buffer.alloc(4 + value.byteLength + padLen);
  out.writeUInt16BE(type, 0);
  out.writeUInt16BE(value.byteLength, 2);
  Buffer.from(value).copy(out, 4);
  return out;
}

function encodeXorAddress(attrType: number, ip: string, port: number): Buffer {
  const val = Buffer.alloc(8);
  val.writeUInt8(0, 0);
  val.writeUInt8(0x01, 1); // IPv4
  val.writeUInt16BE((port ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff, 2);
  const ipBuf = ipv4ToBytes(ip);
  const cookieBuf = Buffer.alloc(4);
  cookieBuf.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
  for (let i = 0; i < 4; i++) {
    val[4 + i] = ipBuf[i] ^ cookieBuf[i];
  }
  return encodeAttr(attrType, val);
}

function decodeXorAddress(val: Buffer): { ip: string; port: number } | null {
  if (val.byteLength < 8 || val.readUInt8(1) !== 0x01) return null;
  const port = (val.readUInt16BE(2) ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff;
  const cookieBuf = Buffer.alloc(4);
  cookieBuf.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
  const ip = `${val[4] ^ cookieBuf[0]}.${val[5] ^ cookieBuf[1]}.${val[6] ^ cookieBuf[2]}.${val[7] ^ cookieBuf[3]}`;
  return { ip, port };
}

function encodeErrorCode(code: number, reason: string): Buffer {
  const reasonBuf = Buffer.from(reason, "utf8");
  const val = Buffer.alloc(4 + reasonBuf.byteLength);
  val.writeUInt16BE(0, 0);
  val.writeUInt8(Math.floor(code / 100), 2);
  val.writeUInt8(code % 100, 3);
  reasonBuf.copy(val, 4);
  return encodeAttr(STUN_ATTR.ERROR_CODE, val);
}

function encodeUint32Attr(type: number, value: number): Buffer {
  const val = Buffer.alloc(4);
  val.writeUInt32BE(value >>> 0, 0);
  return encodeAttr(type, val);
}

function computeLongTermKey(username: string, realm: string, password: string): Buffer {
  return crypto.createHash("md5").update(`${username}:${realm}:${password}`, "utf8").digest();
}

export function generateTurnPasswordForUsername(username: string, secret: string): string {
  return crypto.createHmac("sha1", secret).update(username, "utf8").digest("base64");
}

/**
 * Generates standard coturn/RFC time-limited REST TURN credentials (`timestamp:identity` + HMAC-SHA1).
 */
export function generateTurnCredentials(
  identity: string,
  secret: string,
  expirationSeconds = 3600
): { turnUsername: string; turnPassword: string; expiration: number } {
  const expiryTs = Math.floor(Date.now() / 1000) + expirationSeconds;
  const turnUsername = `${expiryTs}:${identity}`;
  const turnPassword = generateTurnPasswordForUsername(turnUsername, secret);
  return {
    turnUsername,
    turnPassword,
    expiration: expirationSeconds
  };
}

function buildStunMessage(
  msgType: number,
  transactionId: Buffer,
  attrs: Buffer[],
  integrityKey?: Buffer
): Buffer {
  const attrBytesLen = attrs.reduce((sum, a) => sum + a.byteLength, 0);
  const bodyLenWithMi = attrBytesLen + (integrityKey ? 24 : 0);

  const preMiHeader = Buffer.alloc(20);
  preMiHeader.writeUInt16BE(msgType, 0);
  preMiHeader.writeUInt16BE(bodyLenWithMi, 2);
  preMiHeader.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  transactionId.copy(preMiHeader, 8, 0, 12);

  const bodyParts = [...attrs];
  if (integrityKey) {
    const hmacInput = Buffer.concat([preMiHeader, ...bodyParts]);
    const hmac = crypto.createHmac("sha1", integrityKey).update(hmacInput).digest();
    bodyParts.push(encodeAttr(STUN_ATTR.MESSAGE_INTEGRITY, hmac));
  }

  const finalBodyLen = bodyLenWithMi + 8; // FINGERPRINT attribute = 8 bytes
  const finalHeader = Buffer.alloc(20);
  finalHeader.writeUInt16BE(msgType, 0);
  finalHeader.writeUInt16BE(finalBodyLen, 2);
  finalHeader.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  transactionId.copy(finalHeader, 8, 0, 12);

  const preFp = Buffer.concat([finalHeader, ...bodyParts]);
  const fpVal = Buffer.alloc(4);
  fpVal.writeUInt32BE((crc32(preFp) ^ FINGERPRINT_XOR) >>> 0, 0);
  return Buffer.concat([preFp, encodeAttr(STUN_ATTR.FINGERPRINT, fpVal)]);
}

interface ParsedStunMessage {
  msgType: number;
  method: number;
  cls: number;
  transactionId: Buffer;
  username?: string;
  realm?: string;
  nonce?: string;
  lifetime?: number;
  requestedTransport?: number;
  channelNumber?: number;
  data?: Buffer;
  peerAddresses: Array<{ ip: string; port: number }>;
  miOffset?: number;
  miValue?: Buffer;
}

function parseStunPacket(raw: Buffer): ParsedStunMessage | null {
  if (raw.byteLength < 20) return null;
  const msgType = raw.readUInt16BE(0);
  if ((msgType & 0xc000) !== 0x0000) return null;
  if (raw.readUInt32BE(4) !== STUN_MAGIC_COOKIE) return null;
  const msgLen = raw.readUInt16BE(2);
  if (msgLen % 4 !== 0 || 20 + msgLen > raw.byteLength) return null;

  const { method, cls } = parseStunMsgType(msgType);
  const parsed: ParsedStunMessage = {
    msgType,
    method,
    cls,
    transactionId: Buffer.from(raw.subarray(8, 20)),
    peerAddresses: []
  };

  let offset = 20;
  const end = 20 + msgLen;
  while (offset + 4 <= end) {
    const attrType = raw.readUInt16BE(offset);
    const attrLen = raw.readUInt16BE(offset + 2);
    const padded = (attrLen + 3) & ~3;
    if (offset + 4 + padded > end) return null;

    const val = raw.subarray(offset + 4, offset + 4 + attrLen);
    if (parsed.miOffset !== undefined) {
      // RFC 5389 §15.4: attributes after MESSAGE-INTEGRITY other than FINGERPRINT are ignored
      offset += 4 + padded;
      continue;
    }

    switch (attrType) {
      case STUN_ATTR.USERNAME:
        parsed.username = val.toString("utf8");
        break;
      case STUN_ATTR.REALM:
        parsed.realm = val.toString("utf8");
        break;
      case STUN_ATTR.NONCE:
        parsed.nonce = val.toString("utf8");
        break;
      case STUN_ATTR.LIFETIME:
        if (val.byteLength >= 4) parsed.lifetime = val.readUInt32BE(0);
        break;
      case STUN_ATTR.REQUESTED_TRANSPORT:
        if (val.byteLength >= 4) parsed.requestedTransport = val.readUInt8(0);
        break;
      case STUN_ATTR.CHANNEL_NUMBER:
        if (val.byteLength >= 4) parsed.channelNumber = val.readUInt16BE(0);
        break;
      case STUN_ATTR.XOR_PEER_ADDRESS: {
        const addr = decodeXorAddress(val);
        if (addr) parsed.peerAddresses.push(addr);
        break;
      }
      case STUN_ATTR.DATA:
        parsed.data = Buffer.from(val);
        break;
      case STUN_ATTR.MESSAGE_INTEGRITY:
        if (attrLen === 20) {
          parsed.miOffset = offset;
          parsed.miValue = Buffer.from(val);
        }
        break;
      default:
        break;
    }

    offset += 4 + padded;
  }

  return parsed;
}

interface ClientEndpoint {
  transport: "udp" | "tcp";
  ip: string;
  port: number;
  tupleKey: string;
  send: (buf: Buffer) => void;
}

interface TurnAllocation {
  tupleKey: string;
  client: ClientEndpoint;
  username: string;
  integrityKey: Buffer;
  relaySocket: dgram.Socket;
  relayPort: number;
  lifetimeTimer: NodeJS.Timeout;
  permissions: Map<string, number>; // peerIp -> expiresAtMs
  channelToPeer: Map<number, { ip: string; port: number; expiresAt: number }>;
  peerToChannel: Map<string, number>; // `${ip}:${port}` -> channel
  lastAllocateTxIdHex: string;
  lastAllocateResponse: Buffer;
}

export interface TurnServerOptions {
  host: string;
  port: number;
  turnHost: string;
  externalIp: string;
  realm: string;
  getSecret: () => string;
  minPort: number;
  maxPort: number;
  logEnabled?: boolean;
}

/**
 * Built-in RFC 5389 STUN + RFC 5766 TURN server over UDP and TCP with long-term HMAC-SHA1 credentials.
 */
export class TurnServer {
  private udpSocket?: dgram.Socket;
  private tcpServer?: net.Server;
  private readonly tcpSockets = new Set<net.Socket>();
  private readonly allocationsByTuple = new Map<string, TurnAllocation>();
  private readonly allocationsByRelayPort = new Map<number, TurnAllocation>();
  private readonly nonceSecret = crypto.randomBytes(32);
  private boundPort = 0;
  private resolvedExternalIp = "127.0.0.1";
  private dnsRefreshTimer?: NodeJS.Timeout;
  private stopped = false;

  public constructor(private readonly opts: TurnServerOptions) {}

  public getStats(): {
    enabled: true;
    port: number;
    externalIp: string;
    activeAllocations: number;
    activeTcpSockets: number;
  } {
    return {
      enabled: true,
      port: this.boundPort,
      externalIp: this.resolvedExternalIp,
      activeAllocations: this.allocationsByTuple.size,
      activeTcpSockets: this.tcpSockets.size
    };
  }

  public async start(): Promise<{ port: number; externalIp: string }> {
    this.stopped = false;
    this.resolvedExternalIp = await this.resolveExternalIp();

    if (!this.opts.externalIp.trim() && !net.isIPv4(this.opts.turnHost)) {
      this.dnsRefreshTimer = setInterval(() => {
        this.resolveExternalIp()
          .then((ip) => {
            if (ip !== this.resolvedExternalIp) {
              this.log(`refreshed externalIp=${ip} (was ${this.resolvedExternalIp})`);
              this.resolvedExternalIp = ip;
            }
          })
          .catch(() => undefined);
      }, 5 * 60 * 1000);
      this.dnsRefreshTimer.unref();
    }

    const bindHost = this.opts.host === "::" ? "0.0.0.0" : this.opts.host;
    const maxAttempts = this.opts.port === 0 ? 5 : 1;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const udp = await this.bindUdp(bindHost, this.opts.port);
      const udpPort = udp.address().port;
      try {
        const tcp = await this.bindTcp(this.opts.host, udpPort);
        this.udpSocket = udp;
        this.tcpServer = tcp;
        this.boundPort = udpPort;
        return { port: this.boundPort, externalIp: this.resolvedExternalIp };
      } catch (err) {
        await new Promise<void>((resolve) => udp.close(() => resolve()));
        const errno = (err as NodeJS.ErrnoException).code;
        if (attempt < maxAttempts && (errno === "EADDRINUSE" || errno === "EACCES")) {
          continue;
        }
        throw err;
      }
    }

    throw new Error("Failed to bind TURN UDP/TCP sockets on matching port");
  }

  public async stop(): Promise<void> {
    this.stopped = true;
    if (this.dnsRefreshTimer) {
      clearInterval(this.dnsRefreshTimer);
      this.dnsRefreshTimer = undefined;
    }
    for (const alloc of Array.from(this.allocationsByTuple.values())) {
      this.destroyAllocation(alloc, "server-stop");
    }
    for (const sock of Array.from(this.tcpSockets)) {
      sock.destroy();
    }
    this.tcpSockets.clear();

    if (this.udpSocket) {
      const udp = this.udpSocket;
      this.udpSocket = undefined;
      await new Promise<void>((resolve) => {
        try {
          udp.close(() => resolve());
        } catch {
          resolve();
        }
      });
    }
    if (this.tcpServer) {
      const tcp = this.tcpServer;
      this.tcpServer = undefined;
      await new Promise<void>((resolve) => {
        try {
          tcp.close(() => resolve());
        } catch {
          resolve();
        }
      });
    }
  }

  private log(msg: string): void {
    if (this.opts.logEnabled !== false) {
      log.info(msg);
    }
  }

  private async resolveExternalIp(): Promise<string> {
    if (this.opts.externalIp.trim()) {
      return normalizeIp(this.opts.externalIp.trim());
    }
    if (net.isIPv4(this.opts.turnHost)) {
      return this.opts.turnHost;
    }
    try {
      const res = await dns.promises.lookup(this.opts.turnHost, { family: 4 });
      return normalizeIp(res.address);
    } catch {
      this.log(`DNS lookup failed for ${this.opts.turnHost}, falling back to 127.0.0.1`);
      return "127.0.0.1";
    }
  }

  private bindUdp(bindHost: string, port: number): Promise<dgram.Socket> {
    return new Promise((resolve, reject) => {
      const udp = dgram.createSocket({ type: "udp4", reuseAddr: true });
      const onErr = (err: Error) => {
        udp.off("listening", onListen);
        try {
          udp.close();
        } catch {
          // ignore
        }
        reject(err);
      };
      const onListen = () => {
        udp.off("error", onErr);
        udp.on("error", () => undefined);
        udp.on("message", (msg, rinfo) => {
          const ip = normalizeIp(rinfo.address);
          const client: ClientEndpoint = {
            transport: "udp",
            ip,
            port: rinfo.port,
            tupleKey: `udp:${ip}:${rinfo.port}`,
            send: (buf) => {
              if (!this.stopped && this.udpSocket === udp) {
                udp.send(buf, rinfo.port, rinfo.address, () => undefined);
              }
            }
          };
          this.handleDatagram(msg, client);
        });
        resolve(udp);
      };
      udp.once("error", onErr);
      udp.once("listening", onListen);
      udp.bind(port, bindHost);
    });
  }

  private bindTcp(bindHost: string, port: number): Promise<net.Server> {
    return new Promise((resolve, reject) => {
      const tcp = net.createServer((socket) => this.handleTcpSocket(socket));
      const onErr = (err: Error) => {
        tcp.off("listening", onListen);
        reject(err);
      };
      const onListen = () => {
        tcp.off("error", onErr);
        tcp.on("error", () => undefined);
        resolve(tcp);
      };
      tcp.once("error", onErr);
      tcp.once("listening", onListen);
      if (bindHost === "0.0.0.0") {
        tcp.listen({ port, host: "::", ipv6Only: false });
      } else {
        tcp.listen({ port, host: bindHost });
      }
    });
  }

  private handleTcpSocket(socket: net.Socket): void {
    this.tcpSockets.add(socket);
    const ip = normalizeIp(socket.remoteAddress);
    const port = socket.remotePort ?? 0;
    const tupleKey = `tcp:${ip}:${port}`;

    const client: ClientEndpoint = {
      transport: "tcp",
      ip,
      port,
      tupleKey,
      send: (buf) => {
        if (!socket.destroyed) {
          socket.write(buf);
        }
      }
    };

    let rxBuf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      rxBuf = Buffer.concat([rxBuf, chunk]);
      while (rxBuf.byteLength >= 4) {
        const firstTwo = rxBuf.readUInt16BE(0);
        if ((firstTwo & 0xc000) === 0x0000) {
          if (rxBuf.byteLength < 20) break;
          const msgLen = rxBuf.readUInt16BE(2);
          const total = 20 + msgLen;
          if (total > 65535 + 20) {
            socket.destroy();
            return;
          }
          if (rxBuf.byteLength < total) break;
          const pkt = Buffer.from(rxBuf.subarray(0, total));
          rxBuf = rxBuf.subarray(total);
          this.handleStunBytes(pkt, client);
        } else if ((firstTwo & 0xc000) === 0x4000) {
          const dataLen = rxBuf.readUInt16BE(2);
          const paddedTotal = 4 + ((dataLen + 3) & ~3);
          if (rxBuf.byteLength < paddedTotal) break;
          const payload = Buffer.from(rxBuf.subarray(4, 4 + dataLen));
          rxBuf = rxBuf.subarray(paddedTotal);
          this.handleChannelData(firstTwo, payload, client);
        } else {
          socket.destroy();
          return;
        }
      }
    });

    const cleanup = () => {
      this.tcpSockets.delete(socket);
      const alloc = this.allocationsByTuple.get(tupleKey);
      if (alloc) {
        this.destroyAllocation(alloc, "tcp-closed");
      }
    };
    socket.on("close", cleanup);
    socket.on("error", () => socket.destroy());
  }

  private handleDatagram(msg: Buffer, client: ClientEndpoint): void {
    if (msg.byteLength < 4) return;
    const topTwo = msg.readUInt16BE(0) & 0xc000;
    if (topTwo === 0x4000) {
      const channel = msg.readUInt16BE(0);
      const len = msg.readUInt16BE(2);
      if (4 + len > msg.byteLength) return;
      this.handleChannelData(channel, Buffer.from(msg.subarray(4, 4 + len)), client);
      return;
    }
    if (topTwo === 0x0000) {
      this.handleStunBytes(msg, client);
    }
  }

  private handleStunBytes(raw: Buffer, client: ClientEndpoint): void {
    const msg = parseStunPacket(raw);
    if (!msg) return;

    if (msg.method === STUN_METHOD.BINDING && msg.cls === STUN_CLASS.REQUEST) {
      const reply = buildStunMessage(
        stunMsgType(STUN_METHOD.BINDING, STUN_CLASS.SUCCESS),
        msg.transactionId,
        [encodeXorAddress(STUN_ATTR.XOR_MAPPED_ADDRESS, client.ip, client.port)]
      );
      client.send(reply);
      return;
    }

    if (msg.method === STUN_METHOD.SEND && msg.cls === STUN_CLASS.INDICATION) {
      this.handleSendIndication(msg, client);
      return;
    }

    if (msg.cls !== STUN_CLASS.REQUEST) return;

    if (msg.method === STUN_METHOD.ALLOCATE) {
      const existing = this.allocationsByTuple.get(client.tupleKey);
      if (existing && existing.lastAllocateTxIdHex === msg.transactionId.toString("hex")) {
        client.send(existing.lastAllocateResponse);
        return;
      }
    }

    const auth = this.authenticateRequest(raw, msg);
    if (!auth.ok) {
      client.send(
        buildStunMessage(stunMsgType(msg.method, STUN_CLASS.ERROR), msg.transactionId, [
          encodeErrorCode(auth.code, auth.reason),
          encodeAttr(STUN_ATTR.REALM, Buffer.from(this.opts.realm, "utf8")),
          encodeAttr(STUN_ATTR.NONCE, Buffer.from(this.createNonce(), "utf8"))
        ])
      );
      return;
    }

    switch (msg.method) {
      case STUN_METHOD.ALLOCATE:
        void this.handleAllocate(msg, client, auth.username, auth.integrityKey);
        break;
      case STUN_METHOD.REFRESH:
        this.handleRefresh(msg, client, auth.integrityKey);
        break;
      case STUN_METHOD.CREATE_PERMISSION:
        this.handleCreatePermission(msg, client, auth.integrityKey);
        break;
      case STUN_METHOD.CHANNEL_BIND:
        this.handleChannelBind(msg, client, auth.integrityKey);
        break;
      default:
        client.send(
          buildStunMessage(
            stunMsgType(msg.method, STUN_CLASS.ERROR),
            msg.transactionId,
            [encodeErrorCode(400, "Bad Request")],
            auth.integrityKey
          )
        );
        break;
    }
  }

  private createNonce(): string {
    const tsHex = Math.floor(Date.now() / 1000).toString(16);
    const mac = crypto
      .createHmac("sha256", this.nonceSecret)
      .update(tsHex)
      .digest("hex")
      .slice(0, 16);
    return `${tsHex}.${mac}`;
  }

  private isValidNonce(nonce: string): boolean {
    const parts = nonce.split(".");
    if (parts.length !== 2) return false;
    const [tsHex, providedMac] = parts;
    const tsSec = parseInt(tsHex, 16);
    if (!Number.isFinite(tsSec)) return false;
    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec - tsSec > NONCE_TTL_SEC || tsSec - nowSec > 60) return false;
    const expectedMac = crypto
      .createHmac("sha256", this.nonceSecret)
      .update(tsHex)
      .digest("hex")
      .slice(0, 16);
    const a = Buffer.from(providedMac, "utf8");
    const b = Buffer.from(expectedMac, "utf8");
    return a.byteLength === b.byteLength && crypto.timingSafeEqual(a, b);
  }

  private authenticateRequest(
    raw: Buffer,
    msg: ParsedStunMessage
  ):
    | { ok: true; username: string; integrityKey: Buffer }
    | { ok: false; code: number; reason: string } {
    if (
      !msg.username ||
      !msg.realm ||
      !msg.nonce ||
      msg.miOffset === undefined ||
      !msg.miValue
    ) {
      return { ok: false, code: 401, reason: "Unauthorized" };
    }
    if (msg.realm !== this.opts.realm) {
      return { ok: false, code: 401, reason: "Unauthorized" };
    }
    if (!this.isValidNonce(msg.nonce)) {
      return { ok: false, code: 438, reason: "Stale Nonce" };
    }

    const expiryMatch = /^(\d+):/.exec(msg.username);
    if (expiryMatch) {
      const expirySec = parseInt(expiryMatch[1], 10);
      if (expirySec < Math.floor(Date.now() / 1000)) {
        return { ok: false, code: 401, reason: "Unauthorized" };
      }
    }

    const expectedPassword = generateTurnPasswordForUsername(msg.username, this.opts.getSecret());
    const integrityKey = computeLongTermKey(msg.username, this.opts.realm, expectedPassword);

    const miInput = Buffer.from(raw.subarray(0, msg.miOffset));
    miInput.writeUInt16BE(msg.miOffset - 20 + 24, 2);
    const computedHmac = crypto.createHmac("sha1", integrityKey).update(miInput).digest();
    if (
      msg.miValue.byteLength !== computedHmac.byteLength ||
      !crypto.timingSafeEqual(msg.miValue, computedHmac)
    ) {
      return { ok: false, code: 401, reason: "Unauthorized" };
    }

    return { ok: true, username: msg.username, integrityKey };
  }

  private async bindRelaySocket(): Promise<{ socket: dgram.Socket; port: number }> {
    const tryBind = (port: number): Promise<{ socket: dgram.Socket; port: number }> =>
      new Promise((resolve, reject) => {
        const sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
        const onErr = (err: Error) => {
          sock.off("listening", onListen);
          try {
            sock.close();
          } catch {
            // ignore
          }
          reject(err);
        };
        const onListen = () => {
          sock.off("error", onErr);
          sock.on("error", () => undefined);
          resolve({ socket: sock, port: sock.address().port });
        };
        sock.once("error", onErr);
        sock.once("listening", onListen);
        sock.bind(port, "0.0.0.0");
      });

    if (this.opts.minPort > 0 && this.opts.maxPort >= this.opts.minPort) {
      const span = this.opts.maxPort - this.opts.minPort + 1;
      const startOffset = crypto.randomInt(0, span);
      const maxTries = Math.min(100, span);
      for (let i = 0; i < maxTries; i++) {
        const candidate = this.opts.minPort + ((startOffset + i) % span);
        try {
          return await tryBind(candidate);
        } catch {
          // try next port in range
        }
      }
    }

    return tryBind(0);
  }

  private async handleAllocate(
    msg: ParsedStunMessage,
    client: ClientEndpoint,
    username: string,
    integrityKey: Buffer
  ): Promise<void> {
    if (this.allocationsByTuple.has(client.tupleKey)) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.ALLOCATE, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(437, "Allocation Mismatch")],
          integrityKey
        )
      );
      return;
    }

    if (msg.requestedTransport !== 17) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.ALLOCATE, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(442, "Unsupported Transport Protocol")],
          integrityKey
        )
      );
      return;
    }

    const lifetimeSec = Math.max(
      MIN_ALLOCATION_LIFETIME_SEC,
      Math.min(MAX_ALLOCATION_LIFETIME_SEC, msg.lifetime ?? DEFAULT_ALLOCATION_LIFETIME_SEC)
    );

    let bound: { socket: dgram.Socket; port: number };
    try {
      bound = await this.bindRelaySocket();
    } catch {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.ALLOCATE, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(500, "Server Error")],
          integrityKey
        )
      );
      return;
    }

    if (this.stopped || (client.transport === "tcp" && this.allocationsByTuple.has(client.tupleKey))) {
      bound.socket.close();
      return;
    }

    const reply = buildStunMessage(
      stunMsgType(STUN_METHOD.ALLOCATE, STUN_CLASS.SUCCESS),
      msg.transactionId,
      [
        encodeXorAddress(STUN_ATTR.XOR_RELAYED_ADDRESS, this.resolvedExternalIp, bound.port),
        encodeUint32Attr(STUN_ATTR.LIFETIME, lifetimeSec),
        encodeXorAddress(STUN_ATTR.XOR_MAPPED_ADDRESS, client.ip, client.port)
      ],
      integrityKey
    );

    const alloc: TurnAllocation = {
      tupleKey: client.tupleKey,
      client,
      username,
      integrityKey,
      relaySocket: bound.socket,
      relayPort: bound.port,
      lifetimeTimer: setTimeout(() => {
        this.destroyAllocation(alloc, "expired");
      }, lifetimeSec * 1000),
      permissions: new Map(),
      channelToPeer: new Map(),
      peerToChannel: new Map(),
      lastAllocateTxIdHex: msg.transactionId.toString("hex"),
      lastAllocateResponse: reply
    };
    alloc.lifetimeTimer.unref();

    bound.socket.on("message", (data, rinfo) => {
      this.deliverToClient(alloc, normalizeIp(rinfo.address), rinfo.port, data);
    });

    this.allocationsByTuple.set(client.tupleKey, alloc);
    this.allocationsByRelayPort.set(bound.port, alloc);
    this.log(
      `allocate tuple=${client.tupleKey} user=${username} relay=${this.resolvedExternalIp}:${bound.port} lifetime=${lifetimeSec}s`
    );
    client.send(reply);
  }

  private handleRefresh(msg: ParsedStunMessage, client: ClientEndpoint, integrityKey: Buffer): void {
    const alloc = this.allocationsByTuple.get(client.tupleKey);
    if (!alloc) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.REFRESH, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(437, "Allocation Mismatch")],
          integrityKey
        )
      );
      return;
    }

    const requested = msg.lifetime ?? DEFAULT_ALLOCATION_LIFETIME_SEC;
    if (requested === 0) {
      this.destroyAllocation(alloc, "refresh-0");
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.REFRESH, STUN_CLASS.SUCCESS),
          msg.transactionId,
          [encodeUint32Attr(STUN_ATTR.LIFETIME, 0)],
          integrityKey
        )
      );
      return;
    }

    const lifetimeSec = Math.max(
      MIN_ALLOCATION_LIFETIME_SEC,
      Math.min(MAX_ALLOCATION_LIFETIME_SEC, requested)
    );
    clearTimeout(alloc.lifetimeTimer);
    alloc.lifetimeTimer = setTimeout(() => {
      this.destroyAllocation(alloc, "expired");
    }, lifetimeSec * 1000);
    alloc.lifetimeTimer.unref();

    client.send(
      buildStunMessage(
        stunMsgType(STUN_METHOD.REFRESH, STUN_CLASS.SUCCESS),
        msg.transactionId,
        [encodeUint32Attr(STUN_ATTR.LIFETIME, lifetimeSec)],
        integrityKey
      )
    );
  }

  private handleCreatePermission(
    msg: ParsedStunMessage,
    client: ClientEndpoint,
    integrityKey: Buffer
  ): void {
    const alloc = this.allocationsByTuple.get(client.tupleKey);
    if (!alloc) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.CREATE_PERMISSION, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(437, "Allocation Mismatch")],
          integrityKey
        )
      );
      return;
    }

    if (msg.peerAddresses.length === 0) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.CREATE_PERMISSION, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(400, "Bad Request")],
          integrityKey
        )
      );
      return;
    }

    const expiresAt = Date.now() + PERMISSION_TTL_MS;
    for (const peer of msg.peerAddresses) {
      alloc.permissions.set(peer.ip, expiresAt);
    }

    client.send(
      buildStunMessage(
        stunMsgType(STUN_METHOD.CREATE_PERMISSION, STUN_CLASS.SUCCESS),
        msg.transactionId,
        [],
        integrityKey
      )
    );
  }

  private handleChannelBind(
    msg: ParsedStunMessage,
    client: ClientEndpoint,
    integrityKey: Buffer
  ): void {
    const alloc = this.allocationsByTuple.get(client.tupleKey);
    if (!alloc) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.CHANNEL_BIND, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(437, "Allocation Mismatch")],
          integrityKey
        )
      );
      return;
    }

    const ch = msg.channelNumber;
    const peer = msg.peerAddresses[0];
    if (ch === undefined || ch < 0x4000 || ch > 0x7fff || !peer) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.CHANNEL_BIND, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(400, "Bad Request")],
          integrityKey
        )
      );
      return;
    }

    const peerKey = `${peer.ip}:${peer.port}`;
    const existingByCh = alloc.channelToPeer.get(ch);
    const existingChForPeer = alloc.peerToChannel.get(peerKey);
    if (
      (existingByCh && (existingByCh.ip !== peer.ip || existingByCh.port !== peer.port)) ||
      (existingChForPeer !== undefined && existingChForPeer !== ch)
    ) {
      client.send(
        buildStunMessage(
          stunMsgType(STUN_METHOD.CHANNEL_BIND, STUN_CLASS.ERROR),
          msg.transactionId,
          [encodeErrorCode(400, "Bad Request")],
          integrityKey
        )
      );
      return;
    }

    const expiresAt = Date.now() + CHANNEL_BIND_TTL_MS;
    alloc.channelToPeer.set(ch, { ip: peer.ip, port: peer.port, expiresAt });
    alloc.peerToChannel.set(peerKey, ch);
    alloc.permissions.set(peer.ip, Math.max(alloc.permissions.get(peer.ip) ?? 0, expiresAt));

    client.send(
      buildStunMessage(
        stunMsgType(STUN_METHOD.CHANNEL_BIND, STUN_CLASS.SUCCESS),
        msg.transactionId,
        [],
        integrityKey
      )
    );
  }

  private handleSendIndication(msg: ParsedStunMessage, client: ClientEndpoint): void {
    const alloc = this.allocationsByTuple.get(client.tupleKey);
    if (!alloc || !msg.data || msg.peerAddresses.length === 0) return;

    const peer = msg.peerAddresses[0];
    const permUntil = alloc.permissions.get(peer.ip);
    if (!permUntil || permUntil <= Date.now()) return;

    this.sendToPeer(alloc, peer.ip, peer.port, msg.data);
  }

  private handleChannelData(channel: number, data: Buffer, client: ClientEndpoint): void {
    const alloc = this.allocationsByTuple.get(client.tupleKey);
    if (!alloc) return;

    const binding = alloc.channelToPeer.get(channel);
    if (!binding || binding.expiresAt <= Date.now()) return;

    const permUntil = alloc.permissions.get(binding.ip);
    if (!permUntil || permUntil <= Date.now()) return;

    this.sendToPeer(alloc, binding.ip, binding.port, data);
  }

  private sendToPeer(
    sourceAlloc: TurnAllocation,
    peerIp: string,
    peerPort: number,
    data: Buffer
  ): void {
    const targetAlloc =
      peerIp === this.resolvedExternalIp || peerIp === "127.0.0.1"
        ? this.allocationsByRelayPort.get(peerPort)
        : undefined;
    if (targetAlloc) {
      // Hairpin relay directly in-memory so peers behind the same NAT don't require external loopback
      this.deliverToClient(targetAlloc, this.resolvedExternalIp, sourceAlloc.relayPort, data);
      return;
    }
    sourceAlloc.relaySocket.send(data, peerPort, peerIp, () => undefined);
  }

  private deliverToClient(
    alloc: TurnAllocation,
    peerIp: string,
    peerPort: number,
    data: Buffer
  ): void {
    if (this.stopped) return;
    const permUntil = alloc.permissions.get(peerIp);
    if (!permUntil || permUntil <= Date.now()) return;

    const ch = alloc.peerToChannel.get(`${peerIp}:${peerPort}`);
    const binding = ch !== undefined ? alloc.channelToPeer.get(ch) : undefined;
    if (ch !== undefined && binding && binding.expiresAt > Date.now()) {
      const padLen =
        alloc.client.transport === "tcp" ? (4 - (data.byteLength % 4)) % 4 : 0;
      const frame = Buffer.alloc(4 + data.byteLength + padLen);
      frame.writeUInt16BE(ch, 0);
      frame.writeUInt16BE(data.byteLength, 2);
      data.copy(frame, 4);
      alloc.client.send(frame);
      return;
    }

    const txId = crypto.randomBytes(12);
    const ind = buildStunMessage(
      stunMsgType(STUN_METHOD.DATA, STUN_CLASS.INDICATION),
      txId,
      [encodeXorAddress(STUN_ATTR.XOR_PEER_ADDRESS, peerIp, peerPort), encodeAttr(STUN_ATTR.DATA, data)]
    );
    alloc.client.send(ind);
  }

  private destroyAllocation(alloc: TurnAllocation, reason: string): void {
    clearTimeout(alloc.lifetimeTimer);
    if (!this.allocationsByTuple.delete(alloc.tupleKey)) return;
    this.allocationsByRelayPort.delete(alloc.relayPort);
    try {
      alloc.relaySocket.close();
    } catch {
      // ignore
    }
    this.log(`deallocate tuple=${alloc.tupleKey} relayPort=${alloc.relayPort} reason=${reason}`);
  }
}
