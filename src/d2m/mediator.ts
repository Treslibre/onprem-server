import crypto from "node:crypto";
import type { WebSocket } from "ws";
import type { PrismaClient } from "@prisma/client";
import type { KeyManager } from "../crypto/keyManager.js";
import { createLogger } from "../logger.js";
import {
  boxDecryptShared,
  constantTimeEqual,
  deriveSharedSecret,
  generateCurve25519KeyPair
} from "../crypto/primitives.js";
import { CspRouter, CspSessionHandler } from "../csp/session.js";
import {
  type AugmentedDeviceInfoMsg,
  D2mCloseCode,
  D2mPayloadType,
  decodeBeginTransaction,
  decodeClientHello,
  decodeClientUrlInfo,
  decodeD2mContainer,
  decodeDeviceIdOnly,
  decodeSetSharedDeviceData,
  encodeD2mContainer,
  encodeDeviceIdOnly,
  encodeDevicesInfo,
  encodeServerHello,
  encodeServerInfo,
  encodeTransactionNotification
} from "./proto.js";

const log = createLogger("D2M");

const MAX_DEVICE_SLOTS = 8;
const MAX_REFLECTION_QUEUE_LENGTH = 5000;
const WS_HEARTBEAT_INTERVAL_MS = 30_000;

interface ActiveTransaction {
  deviceId: bigint;
  session: DeviceSession;
  encryptedScope: Uint8Array;
  timer: NodeJS.Timeout;
}

interface DeviceSession {
  ws: WebSocket;
  dgidHex: string;
  dgidBytes: Uint8Array;
  deviceId?: bigint;
  isLeader: boolean;
  handshakeComplete: boolean;
  disconnecting: boolean;
  isAlive: boolean;
  connectedAt: number;
  serverEskPriv: Uint8Array;
  challenge: Uint8Array;
  cspProxy?: CspSessionHandler;
}

export class D2mMediatorServer {
  private readonly allSessions = new Set<DeviceSession>();
  private readonly connectionsByGroup = new Map<string, Set<DeviceSession>>();
  private readonly transactionsByGroup = new Map<string, ActiveTransaction>();
  private readonly heartbeatTimer: NodeJS.Timeout;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly keyManager: KeyManager,
    private readonly cspRouter: CspRouter
  ) {
    this.heartbeatTimer = setInterval(() => {
      for (const session of Array.from(this.allSessions)) {
        if (!session.isAlive) {
          log.warn(
            `heartbeat timeout terminating dgid=${session.dgidHex.slice(0, 12)}... deviceId=${session.deviceId?.toString(16) ?? "-"}`
          );
          session.ws.terminate();
          continue;
        }
        session.isAlive = false;
        if (session.ws.readyState === session.ws.OPEN) {
          session.ws.ping();
        }
      }
    }, WS_HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimer.unref();
  }

  handleConnection(ws: WebSocket, pathname: string): void {
    const rawHex = pathname.replace(/^\/mediator\//, "").replace(/^\/+/, "");
    if (!rawHex || !/^[0-9a-f]+$/i.test(rawHex) || rawHex.length % 2 !== 0) {
      log.error(`rejected invalid ClientUrlInfo path=${pathname}`);
      ws.close(D2mCloseCode.PROTOCOL_ERROR, "Invalid ClientUrlInfo path");
      return;
    }

    let dgidBytes: Uint8Array;
    let serverGroup: string;
    try {
      const urlInfo = decodeClientUrlInfo(new Uint8Array(Buffer.from(rawHex, "hex")));
      dgidBytes = urlInfo.deviceGroupId;
      serverGroup = urlInfo.serverGroup || "0";
      if (dgidBytes.byteLength !== 32) {
        log.error(`rejected invalid dgid length=${dgidBytes.byteLength}`);
        ws.close(D2mCloseCode.PROTOCOL_ERROR, "Invalid dgid length");
        return;
      }
    } catch {
      log.error(`rejected malformed ClientUrlInfo path=${pathname}`);
      ws.close(D2mCloseCode.PROTOCOL_ERROR, "Malformed ClientUrlInfo");
      return;
    }

    const dgidHex = Buffer.from(dgidBytes).toString("hex");
    const shortDgid = dgidHex.slice(0, 12);
    const esk = generateCurve25519KeyPair();
    const challenge = new Uint8Array(crypto.randomBytes(32));

    const session: DeviceSession = {
      ws,
      dgidHex,
      dgidBytes,
      isLeader: false,
      handshakeComplete: false,
      disconnecting: false,
      isAlive: true,
      connectedAt: Date.now(),
      serverEskPriv: esk.secretKey,
      challenge
    };
    this.allSessions.add(session);

    log.info(`connect dgid=${shortDgid}... serverGroup=${serverGroup}`);

    const serverHelloPayload = encodeServerHello({
      version: 0, // MUST be 0 (D2M_PROTOCOL_VERSION.MIN === MAX === 0)
      esk: esk.publicKey,
      challenge
    });
    this.sendContainer(ws, D2mPayloadType.SERVER_HELLO, serverHelloPayload);

    let queue = Promise.resolve();

    ws.on("pong", () => {
      session.isAlive = true;
    });

    ws.on("message", (data, isBinary) => {
      session.isAlive = true;
      if (!isBinary) return;
      const bytes =
        data instanceof Buffer
          ? new Uint8Array(data)
          : Array.isArray(data)
            ? new Uint8Array(Buffer.concat(data))
            : new Uint8Array(data as ArrayBuffer);

      queue = queue
        .then(() => this.onContainer(session, serverGroup, bytes))
        .catch((err) => {
          const msg = err instanceof Error ? err.message : String(err);
          log.error(
            `error dgid=${shortDgid}... deviceId=${session.deviceId?.toString(16) ?? "-"}: ${msg}`
          );
          if (ws.readyState === ws.OPEN) {
            ws.close(D2mCloseCode.PROTOCOL_ERROR, "D2M protocol error");
          }
        });
    });

    ws.on("error", (err) => {
      log.error(
        `ws error dgid=${shortDgid}... deviceId=${session.deviceId?.toString(16) ?? "-"}: ${err.message}`
      );
    });

    ws.on("close", (code, reason) => {
      const reasonStr = reason.toString("utf8");
      log.info(
        `disconnect dgid=${shortDgid}... deviceId=${session.deviceId?.toString(16) ?? "-"} code=${code} reason=${reasonStr || "-"}`
      );
      queue = queue.then(() => this.onDisconnect(session)).catch(() => undefined);
    });
  }

  getStats(): {
    activeGroups: number;
    activeConnections: number;
    activeTransactions: number;
    groups: Array<{
      dgid: string;
      connections: Array<{ deviceId: string; isLeader: boolean; connectedAt: number }>;
    }>;
  } {
    const groups: Array<{
      dgid: string;
      connections: Array<{ deviceId: string; isLeader: boolean; connectedAt: number }>;
    }> = [];
    let activeConnections = 0;

    for (const [dgid, set] of this.connectionsByGroup.entries()) {
      const conns: Array<{ deviceId: string; isLeader: boolean; connectedAt: number }> = [];
      for (const s of set) {
        if (!s.handshakeComplete || s.deviceId === undefined) continue;
        conns.push({
          deviceId: s.deviceId.toString(),
          isLeader: s.isLeader,
          connectedAt: s.connectedAt
        });
      }
      if (conns.length > 0) {
        activeConnections += conns.length;
        groups.push({ dgid, connections: conns });
      }
    }

    return {
      activeGroups: groups.length,
      activeConnections,
      activeTransactions: this.transactionsByGroup.size,
      groups
    };
  }

  async dropDevice(dgidHex: string, deviceIdStr: string): Promise<boolean> {
    const res = await this.prisma.deviceSlot.updateMany({
      where: { dgid: dgidHex, deviceId: deviceIdStr },
      data: { dropped: true, connectedSince: null, lastDisconnectAt: BigInt(Date.now()) }
    });

    const targetId = BigInt(deviceIdStr);
    const groupConns = this.connectionsByGroup.get(dgidHex);
    if (groupConns) {
      for (const peer of Array.from(groupConns)) {
        if (peer.deviceId === targetId && peer.ws.readyState === peer.ws.OPEN) {
          peer.ws.close(D2mCloseCode.DEVICE_DROPPED, "Device dropped by administrator");
        }
      }
    }
    return res.count > 0;
  }

  closeAll(): void {
    clearInterval(this.heartbeatTimer);
    for (const tx of this.transactionsByGroup.values()) {
      clearTimeout(tx.timer);
    }
    this.transactionsByGroup.clear();
    for (const s of Array.from(this.allSessions)) {
      s.cspProxy?.close("normal");
      if (s.ws.readyState === s.ws.OPEN) {
        s.ws.close(D2mCloseCode.GOING_AWAY, "Server shutting down");
      }
    }
    this.allSessions.clear();
    this.connectionsByGroup.clear();
  }

  private sendContainer(ws: WebSocket, payloadType: number, payload: Uint8Array): void {
    if (ws.readyState !== ws.OPEN) return;
    ws.send(Buffer.from(encodeD2mContainer(payloadType, payload)));
  }

  private async onContainer(
    session: DeviceSession,
    serverGroup: string,
    frame: Uint8Array
  ): Promise<void> {
    const { payloadType, payload } = decodeD2mContainer(frame);

    // Handle CSP PROXY (0x00) before handshakeComplete check because clients run CSP & D2M handshakes concurrently
    if (payloadType === D2mPayloadType.PROXY) {
      if (!session.cspProxy) {
        session.cspProxy = new CspSessionHandler(
          this.prisma,
          this.keyManager,
          this.cspRouter,
          {
            sendBytes: (bytes) => {
              this.sendContainer(session.ws, D2mPayloadType.PROXY, bytes);
            },
            close: (reason) => {
              session.cspProxy = undefined;
              if (!session.disconnecting && session.ws.readyState === session.ws.OPEN) {
                const closeCode =
                  reason === "idle-timeout"
                    ? D2mCloseCode.CLIENT_TIMEOUT
                    : D2mCloseCode.CHAT_SERVER_CLOSED;
                session.ws.close(
                  closeCode,
                  reason === "idle-timeout" ? "CSP idle timeout" : "CSP proxy closed"
                );
              }
            }
          },
          { transportKind: "d2m-proxy", remoteLabel: `d2m:${session.dgidHex.slice(0, 12)}` }
        );
      }
      session.cspProxy.feedBytes(payload);
      return;
    }

    if (!session.handshakeComplete) {
      if (payloadType !== D2mPayloadType.CLIENT_HELLO) {
        log.error(
          `expected ClientHello dgid=${session.dgidHex.slice(0, 12)}... got payloadType=0x${payloadType.toString(16)}`
        );
        session.ws.close(D2mCloseCode.PROTOCOL_ERROR, "Expected ClientHello");
        return;
      }
      await this.handleClientHello(session, serverGroup, payload);
      return;
    }

    switch (payloadType) {
      case D2mPayloadType.GET_DEVICES_INFO: {
        const slots = await this.prisma.deviceSlot.findMany({
          where: { dgid: session.dgidHex, dropped: false }
        });
        const map = new Map<bigint, AugmentedDeviceInfoMsg>();
        for (const s of slots) {
          map.set(BigInt(s.deviceId), {
            encryptedDeviceInfo: new Uint8Array(s.encryptedDeviceInfo),
            deviceSlotExpirationPolicy: s.expirationPolicy,
            ...(s.connectedSince !== null ? { connectedSince: s.connectedSince } : {}),
            ...(s.lastDisconnectAt !== null ? { lastDisconnectAt: s.lastDisconnectAt } : {})
          });
        }
        this.sendContainer(session.ws, D2mPayloadType.DEVICES_INFO, encodeDevicesInfo(map));
        break;
      }

      case D2mPayloadType.DROP_DEVICE: {
        const targetId = decodeDeviceIdOnly(payload);
        const targetStr = targetId.toString();
        await this.prisma.deviceSlot.updateMany({
          where: { dgid: session.dgidHex, deviceId: targetStr },
          data: { dropped: true, connectedSince: null, lastDisconnectAt: BigInt(Date.now()) }
        });

        const groupConns = this.connectionsByGroup.get(session.dgidHex);
        if (groupConns) {
          for (const peer of Array.from(groupConns)) {
            if (peer.deviceId === targetId) {
              peer.ws.close(D2mCloseCode.DEVICE_DROPPED, "Device dropped");
            }
          }
        }
        log.info(
          `drop device dgid=${session.dgidHex.slice(0, 12)}... targetDeviceId=${targetId.toString(16)}`
        );
        this.sendContainer(
          session.ws,
          D2mPayloadType.DROP_DEVICE_ACK,
          encodeDeviceIdOnly(targetId)
        );
        break;
      }

      case D2mPayloadType.SET_SHARED_DEVICE_DATA: {
        const sharedData = decodeSetSharedDeviceData(payload);
        await this.prisma.deviceGroup.update({
          where: { dgid: session.dgidHex },
          data: { encryptedSharedDeviceData: Buffer.from(sharedData) }
        });
        break;
      }

      case D2mPayloadType.BEGIN_TRANSACTION: {
        if (session.deviceId === undefined) return;
        const { encryptedScope, ttl } = decodeBeginTransaction(payload);
        const existing = this.transactionsByGroup.get(session.dgidHex);
        if (existing && existing.deviceId !== session.deviceId) {
          this.sendContainer(
            session.ws,
            D2mPayloadType.TRANSACTION_REJECTED,
            encodeTransactionNotification(existing.deviceId, existing.encryptedScope)
          );
          return;
        }
        if (existing) clearTimeout(existing.timer);
        const ttlSec = ttl === 0 ? 300 : Math.min(Math.max(ttl, 1), 300);
        const timer = setTimeout(() => {
          this.expireTransaction(session.dgidHex, session);
        }, ttlSec * 1000);
        timer.unref();
        this.transactionsByGroup.set(session.dgidHex, {
          deviceId: session.deviceId,
          session,
          encryptedScope,
          timer
        });
        log.info(
          `begin tx dgid=${session.dgidHex.slice(0, 12)}... deviceId=${session.deviceId.toString(16)} ttl=${ttlSec}s`
        );
        this.sendContainer(session.ws, D2mPayloadType.BEGIN_TRANSACTION_ACK, new Uint8Array(0));
        break;
      }

      case D2mPayloadType.COMMIT_TRANSACTION: {
        if (session.deviceId === undefined) return;
        const existing = this.transactionsByGroup.get(session.dgidHex);
        if (existing && existing.deviceId === session.deviceId) {
          clearTimeout(existing.timer);
          this.transactionsByGroup.delete(session.dgidHex);
          log.info(
            `commit tx dgid=${session.dgidHex.slice(0, 12)}... deviceId=${session.deviceId.toString(16)}`
          );
          this.sendContainer(session.ws, D2mPayloadType.COMMIT_TRANSACTION_ACK, new Uint8Array(0));
          this.broadcastTransactionEnded(
            session.dgidHex,
            session.deviceId,
            existing.encryptedScope
          );
        } else {
          this.sendContainer(session.ws, D2mPayloadType.COMMIT_TRANSACTION_ACK, new Uint8Array(0));
        }
        break;
      }

      case D2mPayloadType.REFLECT: {
        if (session.deviceId === undefined || payload.byteLength < 8) return;
        const nodeBuf = Buffer.from(payload);
        const headerLen = nodeBuf.readUInt8(0);
        if (headerLen < 8 || payload.byteLength < headerLen) return;
        const flags = nodeBuf.readUInt16LE(2);
        const clientReflectId = nodeBuf.readUInt32LE(4);
        const envelope = new Uint8Array(payload.subarray(headerLen));
        const isEphemeral = (flags & 1) !== 0;
        const nowMs = BigInt(Date.now());

        let serverReflectId = clientReflectId;
        if (!isEphemeral) {
          const updatedGroup = await this.prisma.deviceGroup.update({
            where: { dgid: session.dgidHex },
            data: { nextReflectId: { increment: 1 } }
          });
          serverReflectId = updatedGroup.nextReflectId - 1;

          await this.prisma.reflectedEvent.create({
            data: {
              dgid: session.dgidHex,
              reflectId: serverReflectId,
              senderDeviceId: session.deviceId.toString(),
              flags,
              timestamp: nowMs,
              envelope: Buffer.from(envelope)
            }
          });
        }

        // Send REFLECT_ACK to sender
        const ackBuf = Buffer.alloc(16);
        ackBuf.writeUInt32LE(clientReflectId, 4);
        ackBuf.writeBigUInt64LE(nowMs, 8);
        this.sendContainer(session.ws, D2mPayloadType.REFLECT_ACK, new Uint8Array(ackBuf));

        log.debug(
          `reflect dgid=${session.dgidHex.slice(0, 12)}... from=${session.deviceId.toString(16)} ephemeral=${isEphemeral} reflectId=${serverReflectId}`
        );

        // Broadcast REFLECTED to other connected devices in the group
        const reflectedFrame = this.buildReflectedPayload(
          flags,
          serverReflectId,
          nowMs,
          envelope
        );
        const peers = this.connectionsByGroup.get(session.dgidHex);
        if (peers) {
          for (const peer of peers) {
            if (peer !== session && peer.handshakeComplete) {
              this.sendContainer(peer.ws, D2mPayloadType.REFLECTED, reflectedFrame);
            }
          }
        }
        break;
      }

      case D2mPayloadType.REFLECTED_ACK: {
        if (session.deviceId === undefined || payload.byteLength < 8) return;
        const reflectId = Buffer.from(payload).readUInt32LE(4);
        await this.prisma.deviceReflectionAck.upsert({
          where: {
            dgid_deviceId_reflectId: {
              dgid: session.dgidHex,
              deviceId: session.deviceId.toString(),
              reflectId
            }
          },
          create: {
            dgid: session.dgidHex,
            deviceId: session.deviceId.toString(),
            reflectId
          },
          update: {}
        });
        break;
      }

      default:
        break;
    }
  }

  private async handleClientHello(
    session: DeviceSession,
    serverGroup: string,
    payload: Uint8Array
  ): Promise<void> {
    const shortDgid = session.dgidHex.slice(0, 12);
    const clientHello = decodeClientHello(payload);
    if (clientHello.version !== 0) {
      log.error(`unsupported version=${clientHello.version} dgid=${shortDgid}...`);
      session.ws.close(D2mCloseCode.UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version");
      return;
    }

    if (clientHello.response.byteLength < 40) {
      log.error(`invalid challenge response len=${clientHello.response.byteLength} dgid=${shortDgid}...`);
      session.ws.close(D2mCloseCode.PROTOCOL_ERROR, "Invalid challenge response length");
      return;
    }

    const nonce = clientHello.response.subarray(0, 24);
    const box = clientHello.response.subarray(24);
    const shared = deriveSharedSecret(session.dgidBytes, session.serverEskPriv);
    let plainChallenge: Uint8Array;
    try {
      plainChallenge = boxDecryptShared(box, nonce, shared);
    } catch {
      log.error(`challenge decryption failed dgid=${shortDgid}...`);
      session.ws.close(D2mCloseCode.PROTOCOL_ERROR, "Challenge decryption failed");
      return;
    }

    if (!constantTimeEqual(plainChallenge, session.challenge)) {
      log.error(`challenge mismatch dgid=${shortDgid}...`);
      session.ws.close(D2mCloseCode.PROTOCOL_ERROR, "Challenge mismatch");
      return;
    }

    const deviceIdStr = clientHello.deviceId.toString();

    let group = await this.prisma.deviceGroup.findUnique({ where: { dgid: session.dgidHex } });
    if (!group) {
      group = await this.prisma.deviceGroup.create({
        data: {
          dgid: session.dgidHex,
          serverGroup,
          encryptedSharedDeviceData: Buffer.alloc(0)
        }
      });
    }

    const existingSlot = await this.prisma.deviceSlot.findUnique({
      where: { dgid_deviceId: { dgid: session.dgidHex, deviceId: deviceIdStr } }
    });

    if (existingSlot?.dropped) {
      log.error(`slot dropped dgid=${shortDgid}... deviceId=${clientHello.deviceId.toString(16)}`);
      session.ws.close(D2mCloseCode.DEVICE_DROPPED, "Device slot dropped");
      return;
    }

    // expectedDeviceSlotState: 0 = NEW, 1 = EXISTING
    if (clientHello.expectedDeviceSlotState === 1 && !existingSlot) {
      log.error(
        `expected EXISTING slot but missing dgid=${shortDgid}... deviceId=${clientHello.deviceId.toString(16)}`
      );
      session.ws.close(
        D2mCloseCode.EXPECTED_DEVICE_SLOT_STATE_MISMATCH,
        "Expected existing device slot"
      );
      return;
    }
    if (clientHello.expectedDeviceSlotState === 0 && existingSlot) {
      log.error(
        `expected NEW slot but exists dgid=${shortDgid}... deviceId=${clientHello.deviceId.toString(16)}`
      );
      session.ws.close(D2mCloseCode.DEVICE_ID_REUSED, "Device ID already exists");
      return;
    }

    const nowMs = BigInt(Date.now());
    const actualDeviceSlotState = existingSlot ? 1 : 0;
    const slotMinReflectId = existingSlot ? existingSlot.minReflectId : group.nextReflectId;

    // Fetch unacked reflected events since this slot joined
    const [allEvents, ackedRows] = existingSlot
      ? await Promise.all([
          this.prisma.reflectedEvent.findMany({
            where: {
              dgid: session.dgidHex,
              reflectId: { gte: slotMinReflectId },
              senderDeviceId: { not: deviceIdStr }
            },
            orderBy: { reflectId: "asc" }
          }),
          this.prisma.deviceReflectionAck.findMany({
            where: { dgid: session.dgidHex, deviceId: deviceIdStr },
            select: { reflectId: true }
          })
        ])
      : [[], []];
    const ackedSet = new Set(ackedRows.map((a) => a.reflectId));
    const pendingEvents = allEvents.filter((e) => !ackedSet.has(e.reflectId));

    if (existingSlot && pendingEvents.length > MAX_REFLECTION_QUEUE_LENGTH) {
      await this.prisma.deviceSlot.update({
        where: { id: existingSlot.id },
        data: { dropped: true, connectedSince: null, lastDisconnectAt: nowMs }
      });
      log.warn(
        `reflection queue limit reached dgid=${shortDgid}... deviceId=${clientHello.deviceId.toString(16)} pending=${pendingEvents.length}`
      );
      session.ws.close(
        D2mCloseCode.REFLECTION_QUEUE_LENGTH_LIMIT_REACHED,
        "Reflection queue length limit reached"
      );
      return;
    }

    if (!existingSlot) {
      const activeSlots = await this.prisma.deviceSlot.findMany({
        where: { dgid: session.dgidHex, dropped: false },
        orderBy: { updatedAt: "asc" }
      });
      if (activeSlots.length >= MAX_DEVICE_SLOTS) {
        if (clientHello.deviceSlotsExhaustedPolicy === 0) {
          log.error(`device limit reached dgid=${shortDgid}...`);
          session.ws.close(D2mCloseCode.DEVICE_LIMIT_REACHED, "Device limit reached");
          return;
        }
        const victim = activeSlots[0];
        await this.prisma.deviceSlot.update({
          where: { id: victim.id },
          data: { dropped: true, connectedSince: null, lastDisconnectAt: nowMs }
        });
      }

      await this.prisma.deviceSlot.create({
        data: {
          dgid: session.dgidHex,
          deviceId: deviceIdStr,
          expirationPolicy: clientHello.deviceSlotExpirationPolicy,
          encryptedDeviceInfo: Buffer.from(clientHello.encryptedDeviceInfo),
          minReflectId: slotMinReflectId,
          connectedSince: nowMs,
          lastDisconnectAt: null,
          dropped: false
        }
      });
    } else {
      await this.prisma.deviceSlot.update({
        where: { id: existingSlot.id },
        data: {
          expirationPolicy: clientHello.deviceSlotExpirationPolicy,
          encryptedDeviceInfo: Buffer.from(clientHello.encryptedDeviceInfo),
          connectedSince: nowMs,
          lastDisconnectAt: null
        }
      });
    }

    // Close duplicate active connection for same deviceId in same group if any
    let groupConns = this.connectionsByGroup.get(session.dgidHex);
    if (!groupConns) {
      groupConns = new Set();
      this.connectionsByGroup.set(session.dgidHex, groupConns);
    }
    for (const peer of Array.from(groupConns)) {
      if (peer.deviceId === clientHello.deviceId) {
        peer.ws.close(D2mCloseCode.DEVICE_ID_REUSED, "Replaced by newer connection");
      }
    }

    session.deviceId = clientHello.deviceId;
    session.handshakeComplete = true;
    groupConns.add(session);

    // Send SERVER_INFO
    const serverInfoBytes = encodeServerInfo({
      maxDeviceSlots: MAX_DEVICE_SLOTS,
      deviceSlotState: actualDeviceSlotState,
      encryptedSharedDeviceData: new Uint8Array(group.encryptedSharedDeviceData),
      currentTime: nowMs,
      reflectionQueueLength: pendingEvents.length
    });
    this.sendContainer(session.ws, D2mPayloadType.SERVER_INFO, serverInfoBytes);

    // Stream pending REFLECTED events
    for (const ev of pendingEvents) {
      const reflectedPayload = this.buildReflectedPayload(
        ev.flags,
        ev.reflectId,
        ev.timestamp,
        new Uint8Array(ev.envelope)
      );
      this.sendContainer(session.ws, D2mPayloadType.REFLECTED, reflectedPayload);
    }

    // Send REFLECTION_QUEUE_DRY BEFORE ROLE_PROMOTED_TO_LEADER (verified in MonitoringLayer.java)
    this.sendContainer(session.ws, D2mPayloadType.REFLECTION_QUEUE_DRY, new Uint8Array(0));

    // Leader election
    const hasLeader = Array.from(groupConns).some((s) => s !== session && s.isLeader);
    if (!hasLeader) {
      session.isLeader = true;
      this.sendContainer(session.ws, D2mPayloadType.ROLE_PROMOTED_TO_LEADER, new Uint8Array(0));
    }

    log.info(
      `handshake ok dgid=${shortDgid}... deviceId=${clientHello.deviceId.toString(16)} slotState=${actualDeviceSlotState === 0 ? "NEW" : "EXISTING"} pendingEvents=${pendingEvents.length} leader=${session.isLeader}`
    );
  }

  private buildReflectedPayload(
    flags: number,
    reflectedId: number,
    timestamp: bigint,
    envelope: Uint8Array
  ): Uint8Array {
    const out = Buffer.alloc(16 + envelope.byteLength);
    out.writeUInt8(16, 0);
    out.writeUInt8(0, 1);
    out.writeUInt16LE(flags & 0xffff, 2);
    out.writeUInt32LE(reflectedId >>> 0, 4);
    out.writeBigUInt64LE(timestamp, 8);
    Buffer.from(envelope).copy(out, 16);
    return new Uint8Array(out);
  }

  private expireTransaction(dgidHex: string, session: DeviceSession): void {
    if (session.deviceId === undefined) return;
    this.releaseTransaction(dgidHex, session.deviceId);
    if (session.ws.readyState === session.ws.OPEN) {
      session.ws.close(D2mCloseCode.TRANSACTION_TTL_REACHED, "Transaction TTL reached");
    }
  }

  private releaseTransaction(dgidHex: string, deviceId: bigint): void {
    const tx = this.transactionsByGroup.get(dgidHex);
    if (tx && tx.deviceId === deviceId) {
      clearTimeout(tx.timer);
      this.transactionsByGroup.delete(dgidHex);
      this.broadcastTransactionEnded(dgidHex, deviceId, tx.encryptedScope);
    }
  }

  private broadcastTransactionEnded(
    dgidHex: string,
    deviceId: bigint,
    encryptedScope: Uint8Array
  ): void {
    const groupConns = this.connectionsByGroup.get(dgidHex);
    if (!groupConns) return;
    const payload = encodeTransactionNotification(deviceId, encryptedScope);
    for (const peer of groupConns) {
      if (peer.deviceId !== deviceId && peer.handshakeComplete) {
        this.sendContainer(peer.ws, D2mPayloadType.TRANSACTION_ENDED, payload);
      }
    }
  }

  private async onDisconnect(session: DeviceSession): Promise<void> {
    this.allSessions.delete(session);
    session.disconnecting = true;
    session.cspProxy?.close("normal");
    session.cspProxy = undefined;

    const groupConns = this.connectionsByGroup.get(session.dgidHex);
    if (groupConns) {
      groupConns.delete(session);
      if (groupConns.size === 0) {
        this.connectionsByGroup.delete(session.dgidHex);
      }
    }

    if (session.deviceId !== undefined) {
      this.releaseTransaction(session.dgidHex, session.deviceId);
      const stillConnectedSameDevice = groupConns
        ? Array.from(groupConns).some(
            (s) => s.handshakeComplete && s.deviceId === session.deviceId
          )
        : false;
      if (!stillConnectedSameDevice) {
        await this.prisma.deviceSlot
          .updateMany({
            where: { dgid: session.dgidHex, deviceId: session.deviceId.toString() },
            data: { connectedSince: null, lastDisconnectAt: BigInt(Date.now()) }
          })
          .catch(() => undefined);
      }
    }

    if (session.isLeader && groupConns && groupConns.size > 0) {
      session.isLeader = false;
      const next = Array.from(groupConns).find((s) => s.handshakeComplete);
      if (next) {
        next.isLeader = true;
        log.info(
          `leader promoted dgid=${session.dgidHex.slice(0, 12)}... deviceId=${next.deviceId?.toString(16) ?? "-"}`
        );
        this.sendContainer(next.ws, D2mPayloadType.ROLE_PROMOTED_TO_LEADER, new Uint8Array(0));
      }
    }
  }
}
