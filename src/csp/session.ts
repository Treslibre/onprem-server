import crypto from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import type { KeyManager } from "../crypto/keyManager.js";
import { createLogger } from "../logger.js";
import {
  NonceCounter,
  boxDecryptShared,
  boxEncryptShared,
  computeCspVouchMac,
  concatBytes,
  constantTimeEqual,
  deriveSharedSecret,
  generateCurve25519KeyPair
} from "../crypto/primitives.js";
import {
  CLEVER_EXTENSION_MAGIC,
  CspPayloadType,
  convertCspMessagePayload,
  decodeCspContainer,
  encodeCspContainer,
  parseCspExtensions
} from "./protocol.js";

const log = createLogger("CSP");

const DEFAULT_IDLE_TIMEOUT_MS = 300_000; // 5 minutes per csp.struct.yml
const SHORT_LIVED_QUEUE_TTL_MS = 60_000;

type HandshakeState =
  | "AWAIT_CLIENT_HELLO"
  | "AWAIT_CLIENT_LOGIN"
  | "AWAIT_CLIENT_EXTENSIONS"
  | "AUTHENTICATED"
  | "CLOSED";

export interface CspSessionSnapshot {
  identity: string;
  transportKind: "tcp" | "d2m-proxy";
  isMultiDevice: boolean;
  incomingUnblocked: boolean;
  cspDeviceId?: string;
  clientInfo?: string;
  connectedAt: number;
}

export class CspRouter {
  private readonly sessionsByIdentity = new Map<string, Set<CspSessionHandler>>();

  register(identity: string, session: CspSessionHandler): void {
    let set = this.sessionsByIdentity.get(identity);
    if (!set) {
      set = new Set();
      this.sessionsByIdentity.set(identity, set);
    }

    for (const prev of Array.from(set)) {
      if (prev === session) continue;
      if (session.isMultiDevice) {
        if (session.cspDeviceId !== undefined && prev.cspDeviceId === session.cspDeviceId) {
          prev.closeWithError(true, "Another connection with the same ID was established");
        }
      } else if (!prev.isMultiDevice) {
        prev.closeWithError(true, "Another connection with the same ID was established");
      }
    }

    set.add(session);
  }

  unregister(identity: string, session: CspSessionHandler): void {
    const set = this.sessionsByIdentity.get(identity);
    if (!set) return;
    set.delete(session);
    if (set.size === 0) {
      this.sessionsByIdentity.delete(identity);
    }
  }

  setIncomingReceiver(identity: string, leaderSession: CspSessionHandler): void {
    const set = this.sessionsByIdentity.get(identity);
    if (!set) return;
    for (const s of Array.from(set)) {
      s.incomingUnblocked = s === leaderSession;
      if (s !== leaderSession && !s.isMultiDevice) {
        s.closeWithError(true, "Another connection with the same ID was established");
      }
    }
  }

  getActiveReceiver(identity: string): CspSessionHandler | undefined {
    const set = this.sessionsByIdentity.get(identity);
    if (!set) return undefined;
    for (const s of set) {
      if (s.incomingUnblocked && s.isAuthenticated()) {
        return s;
      }
    }
    return undefined;
  }

  getActive(identity: string): CspSessionHandler | undefined {
    return this.getActiveReceiver(identity);
  }

  kickIdentity(
    identity: string,
    reason = "Identity revoked by administrator",
    canReconnect = false
  ): number {
    const set = this.sessionsByIdentity.get(identity);
    if (!set) return 0;
    const targets = Array.from(set);
    for (const s of targets) {
      s.closeWithError(canReconnect, reason);
    }
    return targets.length;
  }

  sendAlert(identity: string | null, message: string): number {
    let delivered = 0;
    if (identity !== null) {
      const set = this.sessionsByIdentity.get(identity);
      if (!set) return 0;
      for (const s of Array.from(set)) {
        if (s.isAuthenticated()) {
          s.sendAlert(message);
          delivered++;
        }
      }
      return delivered;
    }

    for (const set of this.sessionsByIdentity.values()) {
      for (const s of Array.from(set)) {
        if (s.isAuthenticated()) {
          s.sendAlert(message);
          delivered++;
        }
      }
    }
    return delivered;
  }

  getStats(): {
    activeSessions: number;
    activeIdentities: number;
    sessions: CspSessionSnapshot[];
  } {
    const sessions: CspSessionSnapshot[] = [];
    for (const [identity, set] of this.sessionsByIdentity.entries()) {
      for (const s of set) {
        if (!s.isAuthenticated()) continue;
        sessions.push({
          identity,
          transportKind: s.transportKind,
          isMultiDevice: s.isMultiDevice,
          incomingUnblocked: s.incomingUnblocked,
          ...(s.cspDeviceId !== undefined ? { cspDeviceId: s.cspDeviceId.toString(16) } : {}),
          ...(s.clientInfo ? { clientInfo: s.clientInfo } : {}),
          connectedAt: s.connectedAt
        });
      }
    }
    return {
      activeSessions: sessions.length,
      activeIdentities: new Set(sessions.map((s) => s.identity)).size,
      sessions
    };
  }

  closeAll(): void {
    for (const set of this.sessionsByIdentity.values()) {
      for (const session of Array.from(set)) {
        session.close("normal");
      }
    }
    this.sessionsByIdentity.clear();
  }
}

export type CspCloseReason = "idle-timeout" | "error" | "normal";

export interface CspTransport {
  sendBytes: (data: Uint8Array) => void;
  close: (reason?: CspCloseReason) => void;
}

export interface CspSessionOptions {
  transportKind?: "tcp" | "d2m-proxy";
  remoteLabel?: string;
}

export class CspSessionHandler {
  private state: HandshakeState = "AWAIT_CLIENT_HELLO";
  private buffer = Buffer.alloc(0);
  private processing: Promise<void> = Promise.resolve();

  private clientTempPub!: Uint8Array;
  private clientCookie!: Uint8Array;
  private serverCookie!: Uint8Array;
  private serverTempKeyPair!: { publicKey: Uint8Array; secretKey: Uint8Array };
  private clientNonce!: NonceCounter;
  private serverNonce!: NonceCounter;
  private kServerTempClientTemp!: Uint8Array;

  private pendingIdentity?: string;
  private pendingVouchMac?: Uint8Array;
  private pendingExtensionsLen = 0;

  public identity?: string;
  public cspDeviceId?: bigint;
  public clientInfo?: string;
  public messagePayloadVersion = 0;
  public isMultiDevice = false;
  public incomingUnblocked = false;
  public readonly connectedAt = Date.now();
  public readonly transportKind: "tcp" | "d2m-proxy";
  private readonly remoteLabel: string;
  private idleTimer?: NodeJS.Timeout;
  private idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly keyManager: KeyManager,
    private readonly router: CspRouter,
    private readonly transport: CspTransport,
    options?: CspSessionOptions
  ) {
    this.transportKind = options?.transportKind ?? "tcp";
    this.remoteLabel = options?.remoteLabel ?? "-";
    this.resetIdleTimer();
  }

  isAuthenticated(): boolean {
    return this.state === "AUTHENTICATED";
  }

  feedBytes(chunk: Uint8Array): void {
    if (this.state === "CLOSED") return;
    this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
    this.processing = this.processing
      .then(() => this.processBuffer())
      .catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        log.error(
          `session error identity=${this.identity ?? "unauth"} transport=${this.transportKind} remote=${this.remoteLabel}: ${msg}`
        );
        this.close("error");
      });
  }

  close(reason: CspCloseReason = "normal"): void {
    if (this.state === "CLOSED") return;
    const prevIdentity = this.identity;
    this.state = "CLOSED";
    this.incomingUnblocked = false;
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
    if (prevIdentity) {
      this.router.unregister(prevIdentity, this);
      log.info(
        `closed identity=${prevIdentity} transport=${this.transportKind} reason=${reason} cspDeviceId=${this.cspDeviceId?.toString(16) ?? "-"}`
      );
    }
    this.transport.close(reason);
  }

  closeWithError(canReconnect: boolean, message: string): void {
    if (this.state === "AUTHENTICATED") {
      try {
        const msgBytes = Buffer.from(message, "utf8");
        const payload = new Uint8Array(1 + msgBytes.byteLength);
        payload[0] = canReconnect ? 1 : 0;
        payload.set(msgBytes, 1);
        this.sendContainer(CspPayloadType.CLOSE_ERROR, payload);
      } catch {
        // Ignore send errors while closing
      }
    }
    this.close("error");
  }

  sendAlert(message: string): void {
    if (this.state !== "AUTHENTICATED") return;
    this.sendContainer(CspPayloadType.ALERT, new Uint8Array(Buffer.from(message, "utf8")));
  }

  async deliverIncomingMessage(rawPayload: Uint8Array): Promise<void> {
    if (this.state !== "AUTHENTICATED") return;
    const adapted = convertCspMessagePayload(rawPayload, this.messagePayloadVersion);
    this.sendContainer(CspPayloadType.INCOMING_MESSAGE, adapted);
  }

  private resetIdleTimer(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      this.close("idle-timeout");
    }, this.idleTimeoutMs);
    this.idleTimer.unref();
  }

  private async processBuffer(): Promise<void> {
    while (this.state !== "CLOSED") {
      if (this.state === "AWAIT_CLIENT_HELLO") {
        if (this.buffer.byteLength < 48) return;
        const packet = new Uint8Array(this.buffer.subarray(0, 48));
        this.buffer = this.buffer.subarray(48);
        this.handleClientHello(packet);
        this.resetIdleTimer();
        continue;
      }

      if (this.state === "AWAIT_CLIENT_LOGIN") {
        if (this.buffer.byteLength < 144) return;
        const loginBox = new Uint8Array(this.buffer.subarray(0, 144));
        this.buffer = this.buffer.subarray(144);
        this.handleClientLoginBox(loginBox);
        this.resetIdleTimer();
        if (this.pendingExtensionsLen === 0) {
          await this.finalizeLogin(new Uint8Array(0));
        }
        continue;
      }

      if (this.state === "AWAIT_CLIENT_EXTENSIONS") {
        if (this.buffer.byteLength < this.pendingExtensionsLen) return;
        const extBox = new Uint8Array(this.buffer.subarray(0, this.pendingExtensionsLen));
        this.buffer = this.buffer.subarray(this.pendingExtensionsLen);
        const extPlain = boxDecryptShared(
          extBox,
          this.clientNonce.nextNonce(),
          this.kServerTempClientTemp
        );
        this.resetIdleTimer();
        await this.finalizeLogin(extPlain);
        continue;
      }

      if (this.state === "AUTHENTICATED") {
        if (this.buffer.byteLength < 2) return;
        const frameLen = this.buffer.readUInt16LE(0);
        if (frameLen < 20 || frameLen > 8192) {
          throw new Error(`Invalid CSP frame length: ${frameLen}`);
        }
        if (this.buffer.byteLength < 2 + frameLen) return;
        const box = new Uint8Array(this.buffer.subarray(2, 2 + frameLen));
        this.buffer = this.buffer.subarray(2 + frameLen);
        this.resetIdleTimer();
        await this.handleAuthenticatedFrame(box);
        continue;
      }

      return;
    }
  }

  private handleClientHello(packet: Uint8Array): void {
    this.clientTempPub = packet.subarray(0, 32);
    this.clientCookie = packet.subarray(32, 48);
    this.clientNonce = new NonceCounter(this.clientCookie);

    let sck = new Uint8Array(crypto.randomBytes(16));
    while (constantTimeEqual(sck, this.clientCookie)) {
      sck = new Uint8Array(crypto.randomBytes(16));
    }
    this.serverCookie = sck;
    this.serverNonce = new NonceCounter(sck);
    this.serverTempKeyPair = generateCurve25519KeyPair();

    const serverPermPriv = this.keyManager.getCspKeyPair().privateKey;
    const kServerPermClientTemp = deriveSharedSecret(this.clientTempPub, serverPermPriv);
    this.kServerTempClientTemp = deriveSharedSecret(
      this.clientTempPub,
      this.serverTempKeyPair.secretKey
    );

    const serverHelloPlain = concatBytes(this.serverTempKeyPair.publicKey, this.clientCookie);
    const serverHelloBox = boxEncryptShared(
      serverHelloPlain,
      this.serverNonce.nextNonce(),
      kServerPermClientTemp
    );
    const serverHello = concatBytes(this.serverCookie, serverHelloBox);
    this.transport.sendBytes(serverHello);
    this.state = "AWAIT_CLIENT_LOGIN";
  }

  private handleClientLoginBox(loginBox: Uint8Array): void {
    const loginData = boxDecryptShared(
      loginBox,
      this.clientNonce.nextNonce(),
      this.kServerTempClientTemp
    );
    if (loginData.byteLength !== 128) {
      throw new Error(`Invalid loginData length: ${loginData.byteLength}`);
    }

    const identity = Buffer.from(loginData.subarray(0, 8)).toString("ascii");
    const extIndicator = Buffer.from(loginData.subarray(8, 40));
    const echoedServerCookie = loginData.subarray(40, 56);
    if (!constantTimeEqual(echoedServerCookie, this.serverCookie)) {
      throw new Error("Server cookie mismatch in ClientLogin");
    }

    let extensionsLen = 0;
    if (extIndicator.subarray(0, 30).equals(CLEVER_EXTENSION_MAGIC)) {
      extensionsLen = extIndicator.readUInt16LE(30);
    } else {
      const legacyInfo = extIndicator.toString("utf8").replace(/\0+$/, "").trim();
      if (legacyInfo) this.clientInfo = legacyInfo;
    }

    this.pendingIdentity = identity;
    this.pendingVouchMac = new Uint8Array(loginData.subarray(80, 112));
    this.pendingExtensionsLen = extensionsLen;

    if (extensionsLen > 0) {
      this.state = "AWAIT_CLIENT_EXTENSIONS";
    }
  }

  private async finalizeLogin(extPlain: Uint8Array): Promise<void> {
    const identity = this.pendingIdentity;
    const vouchMac = this.pendingVouchMac;
    if (!identity || !vouchMac) {
      throw new Error("Missing pending login state");
    }

    const identityRow = await this.prisma.identity.findUnique({ where: { id: identity } });
    if (!identityRow) {
      throw new Error(`Unknown identity: ${identity}`);
    }

    const clientPermPub = new Uint8Array(identityRow.publicKey);
    const serverPermPriv = this.keyManager.getCspKeyPair().privateKey;
    const ss1 = deriveSharedSecret(clientPermPub, serverPermPriv);
    const ss2 = deriveSharedSecret(clientPermPub, this.serverTempKeyPair.secretKey);
    const expectedVouch = computeCspVouchMac(ss1, ss2, this.serverCookie, this.clientTempPub);

    if (!constantTimeEqual(vouchMac, expectedVouch)) {
      throw new Error("CSP vouch MAC verification failed");
    }

    let presentedCookie: Uint8Array | undefined;
    if (extPlain.byteLength > 0) {
      const parsedExt = parseCspExtensions(extPlain);
      if (parsedExt.clientInfo) this.clientInfo = parsedExt.clientInfo;
      this.cspDeviceId = parsedExt.cspDeviceId;
      this.messagePayloadVersion = parsedExt.messagePayloadVersion ?? 0;
      presentedCookie = parsedExt.deviceCookie;
    } else {
      this.messagePayloadVersion = 0;
    }

    // Always send ServerLoginAck (serverNonce #2) before sending an encrypted CLOSE_ERROR
    const ackBox = boxEncryptShared(
      new Uint8Array(16),
      this.serverNonce.nextNonce(),
      this.kServerTempClientTemp
    );
    this.transport.sendBytes(ackBox);

    if (identityRow.state !== 1) {
      this.state = "AUTHENTICATED";
      log.warn(`rejected revoked/inactive identity=${identity} state=${identityRow.state}`);
      this.closeWithError(false, "Identity revoked or inactive");
      return;
    }

    this.isMultiDevice = this.transportKind === "d2m-proxy" || this.cspDeviceId !== undefined;

    // Device cookie change detection per csp.struct.yml (single-device connections)
    let notifyCookieChanged = identityRow.deviceCookieChanged;
    const updateData: {
      lastLoginAt: Date;
      deviceCookie?: Uint8Array<ArrayBuffer>;
      deviceCookieChanged?: boolean;
    } = {
      lastLoginAt: new Date()
    };

    if (!this.isMultiDevice) {
      const storedCookie = identityRow.deviceCookie
        ? new Uint8Array(identityRow.deviceCookie)
        : undefined;
      if (storedCookie && storedCookie.byteLength > 0) {
        const effectivePresented =
          presentedCookie && presentedCookie.byteLength > 0
            ? presentedCookie
            : new Uint8Array(16);
        if (!constantTimeEqual(storedCookie, effectivePresented)) {
          notifyCookieChanged = true;
          updateData.deviceCookieChanged = true;
          if (presentedCookie && presentedCookie.byteLength > 0) {
            updateData.deviceCookie = new Uint8Array(presentedCookie);
          }
          log.warn(`device cookie changed identity=${identity}`);
        }
      } else if (presentedCookie && presentedCookie.byteLength > 0) {
        updateData.deviceCookie = new Uint8Array(presentedCookie);
      }
    } else if (presentedCookie && presentedCookie.byteLength > 0) {
      updateData.deviceCookie = new Uint8Array(presentedCookie);
    }

    await this.prisma.identity.update({
      where: { id: identity },
      data: updateData
    });

    this.identity = identity;
    this.state = "AUTHENTICATED";
    this.incomingUnblocked = !this.isMultiDevice;
    this.router.register(identity, this);

    log.info(
      `login ok identity=${identity} transport=${this.transportKind} md=${this.isMultiDevice} msgVer=${this.messagePayloadVersion} cspDeviceId=${this.cspDeviceId?.toString(16) ?? "-"}`
    );

    if (!this.isMultiDevice) {
      if (notifyCookieChanged) {
        this.sendContainer(CspPayloadType.DEVICE_COOKIE_CHANGED_INDICATION, new Uint8Array(0));
      }
      await this.flushQueuedMessages();
      this.sendContainer(CspPayloadType.QUEUE_SEND_COMPLETE, new Uint8Array(0));
    }
  }

  private async flushQueuedMessages(): Promise<void> {
    if (!this.identity) return;
    const queued = await this.prisma.queuedMessage.findMany({
      where: { toIdentity: this.identity, delivered: false },
      orderBy: { id: "asc" }
    });
    const nowMs = Date.now();
    for (const msg of queued) {
      if (this.state !== "AUTHENTICATED") break;
      const flags = msg.rawPayload.length > 28 ? msg.rawPayload[28] : 0;
      if ((flags & 0x20) !== 0 && nowMs - msg.createdAt.getTime() > SHORT_LIVED_QUEUE_TTL_MS) {
        await this.prisma.queuedMessage.update({
          where: { id: msg.id },
          data: { delivered: true }
        });
        continue;
      }

      const adapted = convertCspMessagePayload(
        new Uint8Array(msg.rawPayload),
        this.messagePayloadVersion
      );
      this.sendContainer(CspPayloadType.INCOMING_MESSAGE, adapted);
      if ((flags & 0x04) !== 0) {
        await this.prisma.queuedMessage.update({
          where: { id: msg.id },
          data: { delivered: true }
        });
      }
    }
  }

  private async handleAuthenticatedFrame(box: Uint8Array): Promise<void> {
    const plain = boxDecryptShared(
      box,
      this.clientNonce.nextNonce(),
      this.kServerTempClientTemp
    );
    const { payloadType, payload } = decodeCspContainer(plain);

    switch (payloadType) {
      case CspPayloadType.ECHO_REQUEST: {
        this.sendContainer(CspPayloadType.ECHO_RESPONSE, payload);
        break;
      }

      case CspPayloadType.ECHO_RESPONSE: {
        break;
      }

      case CspPayloadType.OUTGOING_MESSAGE: {
        if (payload.byteLength < 96) {
          throw new Error(`OUTGOING_MESSAGE too short: ${payload.byteLength}`);
        }
        const fromId = Buffer.from(payload.subarray(0, 8)).toString("ascii");
        const toId = Buffer.from(payload.subarray(8, 16)).toString("ascii");
        const messageId = new Uint8Array(payload.subarray(16, 24));
        const flags = payload[28];
        const noQueue = (flags & 0x02) !== 0;
        const noAck = (flags & 0x04) !== 0;
        const shortLived = (flags & 0x20) !== 0;

        if (fromId !== this.identity) {
          throw new Error(`Spoofed sender identity: ${fromId} != ${this.identity}`);
        }

        // Override created-at timestamp when in the future or short-lived (0x20) per csp.struct.yml
        const nowSec = Math.floor(Date.now() / 1000);
        const rawBuf = Buffer.from(payload);
        const createdAtSec = rawBuf.readUInt32LE(24);
        let effectivePayload = payload;
        if (createdAtSec > nowSec || shortLived) {
          const copy = Buffer.from(rawBuf);
          copy.writeUInt32LE(nowSec >>> 0, 24);
          effectivePayload = new Uint8Array(copy);
        }

        const recipient = this.router.getActiveReceiver(toId);

        if (!noQueue) {
          await this.prisma.queuedMessage.create({
            data: {
              fromIdentity: fromId,
              toIdentity: toId,
              messageId: new Uint8Array(messageId),
              rawPayload: new Uint8Array(effectivePayload),
              delivered: Boolean(noAck && recipient)
            }
          });
        }

        // Acknowledge receipt to sender: [toIdentity(8) | messageId(8)] unless noAck flag (0x04) is set
        if (!noAck) {
          const ackPayload = concatBytes(effectivePayload.subarray(8, 16), messageId);
          this.sendContainer(CspPayloadType.OUTGOING_MESSAGE_ACK, ackPayload);
        }

        // Live push if recipient is connected
        if (recipient) {
          await recipient.deliverIncomingMessage(effectivePayload);
        }

        log.debug(
          `msg from=${fromId} to=${toId} flags=0x${flags.toString(16)} online=${Boolean(recipient)} queued=${!noQueue}`
        );
        break;
      }

      case CspPayloadType.INCOMING_MESSAGE_ACK: {
        if (payload.byteLength !== 16 || !this.identity) {
          throw new Error(`Invalid INCOMING_MESSAGE_ACK length: ${payload.byteLength}`);
        }
        const senderId = Buffer.from(payload.subarray(0, 8)).toString("ascii");
        const messageId = Buffer.from(payload.subarray(8, 16));
        await this.prisma.queuedMessage.updateMany({
          where: {
            fromIdentity: senderId,
            toIdentity: this.identity,
            messageId,
            delivered: false
          },
          data: { delivered: true }
        });
        break;
      }

      case CspPayloadType.UNBLOCK_INCOMING_MESSAGES: {
        if (this.identity) {
          this.router.setIncomingReceiver(this.identity, this);
        }
        log.info(
          `unblock incoming identity=${this.identity ?? "-"} cspDeviceId=${this.cspDeviceId?.toString(16) ?? "-"}`
        );
        await this.flushQueuedMessages();
        this.sendContainer(CspPayloadType.QUEUE_SEND_COMPLETE, new Uint8Array(0));
        break;
      }

      case CspPayloadType.SET_PUSH_NOTIFICATION_TOKEN:
      case CspPayloadType.SET_HIGH_PRIO_PUSH_NOTIFICATION_TOKEN: {
        if (!this.identity || payload.byteLength < 1) break;
        const tokenType = payload[0];
        const tokenBytes = new Uint8Array(payload.subarray(1, 256));
        const deviceIdStr = (this.cspDeviceId ?? 0n).toString();
        const priority =
          payloadType === CspPayloadType.SET_HIGH_PRIO_PUSH_NOTIFICATION_TOKEN ? "high" : "normal";

        if (tokenType === 0) {
          await this.prisma.pushToken.deleteMany({
            where: { identityId: this.identity, cspDeviceId: deviceIdStr, priority }
          });
        } else {
          await this.prisma.pushToken.upsert({
            where: {
              identityId_cspDeviceId_priority: {
                identityId: this.identity,
                cspDeviceId: deviceIdStr,
                priority
              }
            },
            create: {
              identityId: this.identity,
              cspDeviceId: deviceIdStr,
              priority,
              tokenType,
              token: tokenBytes
            },
            update: {
              tokenType,
              token: tokenBytes
            }
          });
        }
        break;
      }

      case CspPayloadType.DELETE_PUSH_NOTIFICATION_TOKEN: {
        if (!this.identity) break;
        if (payload.byteLength === 0) {
          const selfDeviceIdStr = (this.cspDeviceId ?? 0n).toString();
          await this.prisma.pushToken.deleteMany({
            where: {
              identityId: this.identity,
              cspDeviceId: { not: selfDeviceIdStr }
            }
          });
        } else {
          const targetIds: string[] = [];
          const buf = Buffer.from(payload);
          for (let off = 0; off + 8 <= buf.byteLength; off += 8) {
            targetIds.push(buf.readBigUInt64LE(off).toString());
          }
          if (targetIds.length > 0) {
            await this.prisma.pushToken.deleteMany({
              where: {
                identityId: this.identity,
                cspDeviceId: { in: targetIds }
              }
            });
          }
        }
        break;
      }

      case CspPayloadType.SET_CONNECTION_IDLE_TIMEOUT: {
        if (payload.byteLength === 2) {
          const seconds = Buffer.from(payload).readUInt16LE(0);
          if (seconds >= 30 && seconds <= 600) {
            this.idleTimeoutMs = seconds * 1000;
            this.resetIdleTimer();
          }
        }
        break;
      }

      case CspPayloadType.CLEAR_DEVICE_COOKIE_CHANGED_INDICATION: {
        if (this.identity) {
          await this.prisma.identity.update({
            where: { id: this.identity },
            data: { deviceCookieChanged: false }
          });
        }
        break;
      }

      default:
        break;
    }
  }

  private sendContainer(payloadType: number, payload: Uint8Array): void {
    if (this.state === "CLOSED") return;
    const container = encodeCspContainer(payloadType, payload);
    const box = boxEncryptShared(
      container,
      this.serverNonce.nextNonce(),
      this.kServerTempClientTemp
    );
    const frame = new Uint8Array(2 + box.byteLength);
    Buffer.from(frame.buffer, frame.byteOffset, frame.byteLength).writeUInt16LE(box.byteLength, 0);
    frame.set(box, 2);
    this.transport.sendBytes(frame);
  }
}
