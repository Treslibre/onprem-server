import fs from "node:fs";
import path from "node:path";
import type { PrismaClient } from "@prisma/client";
import { createLogger } from "../logger.js";
import { resolveSafeBlobPath } from "../routes/blob.js";

const log = createLogger("Sweeper");

export interface HousekeepingOptions {
  blobStorageDir: string;
  blobTtlHours: number;
  safeRetentionDays?: number;
  messageTtlDays?: number;
  deliveredMessageGraceMs?: number;
  shortLivedMessageTtlMs?: number;
  volatileSlotTtlMs?: number;
  reflectionTtlDays?: number;
  nowMs?: number;
}

export interface HousekeepingStats {
  expiredChallenges: number;
  expiredAuthTokens: number;
  prunedMessages: number;
  droppedVolatileSlots: number;
  prunedReflectedEvents: number;
  prunedBlobs: number;
  prunedSafeBackups: number;
  ranAt: string;
}

export async function runHousekeeping(
  prisma: PrismaClient,
  opts: HousekeepingOptions
): Promise<HousekeepingStats> {
  const nowMs = opts.nowMs ?? Date.now();
  const nowDate = new Date(nowMs);
  const safeRetentionDays = opts.safeRetentionDays ?? 180;
  const messageTtlDays = opts.messageTtlDays ?? 14;
  const deliveredMessageGraceMs = opts.deliveredMessageGraceMs ?? 60 * 60 * 1000;
  const shortLivedTtlMs = opts.shortLivedMessageTtlMs ?? 60 * 1000;
  const volatileSlotTtlMs = opts.volatileSlotTtlMs ?? 15 * 60 * 1000;
  const reflectionTtlDays = opts.reflectionTtlDays ?? 30;

  // 1. Expired directory/work challenges
  const chRes = await prisma.challenge.deleteMany({
    where: { expiresAt: { lt: nowDate } }
  });

  // 2. Expired auth tokens
  const tokRes = await prisma.authToken.deleteMany({
    where: { expiresAt: { lt: nowDate } }
  });

  // 3. Queued messages (delivered past grace window, undelivered past TTL, or expired short-lived 0x20)
  const deliveredCutoff = new Date(nowMs - deliveredMessageGraceMs);
  const undeliveredCutoff = new Date(nowMs - messageTtlDays * 86_400_000);
  const shortLivedCutoff = new Date(nowMs - shortLivedTtlMs);

  const shortLivedCandidates = await prisma.queuedMessage.findMany({
    where: { delivered: false, createdAt: { lt: shortLivedCutoff } },
    select: { id: true, rawPayload: true }
  });
  const expiredShortLivedIds = shortLivedCandidates
    .filter((m) => m.rawPayload.length > 28 && (m.rawPayload[28] & 0x20) !== 0)
    .map((m) => m.id);

  const msgDelRes = await prisma.queuedMessage.deleteMany({
    where: {
      OR: [
        { delivered: true, createdAt: { lt: deliveredCutoff } },
        { delivered: false, createdAt: { lt: undeliveredCutoff } },
        ...(expiredShortLivedIds.length > 0 ? [{ id: { in: expiredShortLivedIds } }] : [])
      ]
    }
  });

  // 4. Stale disconnected VOLATILE device slots
  const volatileCutoffBig = BigInt(nowMs - volatileSlotTtlMs);
  const volatileRes = await prisma.deviceSlot.updateMany({
    where: {
      expirationPolicy: 0,
      dropped: false,
      connectedSince: null,
      lastDisconnectAt: { lt: volatileCutoffBig }
    },
    data: { dropped: true }
  });

  // 5. Reflected events that are either expired or acked by every active peer slot
  const reflectionCutoff = new Date(nowMs - reflectionTtlDays * 86_400_000);
  const [oldReflectionsRes, remainingEvents, activeSlots, ackRows] = await Promise.all([
    prisma.reflectedEvent.deleteMany({ where: { createdAt: { lt: reflectionCutoff } } }),
    prisma.reflectedEvent.findMany({
      select: { id: true, dgid: true, reflectId: true, senderDeviceId: true }
    }),
    prisma.deviceSlot.findMany({
      where: { dropped: false },
      select: { dgid: true, deviceId: true, minReflectId: true }
    }),
    prisma.deviceReflectionAck.findMany({
      select: { dgid: true, deviceId: true, reflectId: true }
    })
  ]);

  let prunedReflectedCount = oldReflectionsRes.count;

  const slotsByGroup = new Map<string, Array<{ deviceId: string; minReflectId: number }>>();
  for (const s of activeSlots) {
    let arr = slotsByGroup.get(s.dgid);
    if (!arr) {
      arr = [];
      slotsByGroup.set(s.dgid, arr);
    }
    arr.push({ deviceId: s.deviceId, minReflectId: s.minReflectId });
  }

  const ackKeySet = new Set(ackRows.map((a) => `${a.dgid}|${a.deviceId}|${a.reflectId}`));
  const fullyAckedIds: number[] = [];
  const ackConditionsToDelete: Array<{ dgid: string; reflectId: number }> = [];

  for (const ev of remainingEvents) {
    const groupSlots = slotsByGroup.get(ev.dgid) ?? [];
    const targetSlots = groupSlots.filter(
      (s) => s.deviceId !== ev.senderDeviceId && s.minReflectId <= ev.reflectId
    );
    // A newly joined slot gets minReflectId = group.nextReflectId > ev.reflectId,
    // so once every non-dropped peer with minReflectId <= ev.reflectId has acked (or none remain), ev is unreachable.
    if (targetSlots.every((s) => ackKeySet.has(`${ev.dgid}|${s.deviceId}|${ev.reflectId}`))) {
      fullyAckedIds.push(ev.id);
      ackConditionsToDelete.push({ dgid: ev.dgid, reflectId: ev.reflectId });
    }
  }

  if (fullyAckedIds.length > 0) {
    const delEv = await prisma.reflectedEvent.deleteMany({
      where: { id: { in: fullyAckedIds } }
    });
    prunedReflectedCount += delEv.count;
    await prisma.deviceReflectionAck.deleteMany({
      where: { OR: ackConditionsToDelete }
    });
  }

  // Clean orphaned ack rows for events that no longer exist
  const survivingEventKeys = new Set(
    remainingEvents
      .filter((e) => !fullyAckedIds.includes(e.id))
      .map((e) => `${e.dgid}|${e.reflectId}`)
  );
  const orphanAckKeys = new Set<string>();
  const orphanAckPairs: Array<{ dgid: string; reflectId: number }> = [];
  for (const a of ackRows) {
    const k = `${a.dgid}|${a.reflectId}`;
    if (!survivingEventKeys.has(k) && !orphanAckKeys.has(k)) {
      orphanAckKeys.add(k);
      orphanAckPairs.push({ dgid: a.dgid, reflectId: a.reflectId });
    }
  }
  if (orphanAckPairs.length > 0) {
    await prisma.deviceReflectionAck.deleteMany({ where: { OR: orphanAckPairs } });
  }

  // 6. Expired non-persistent blobs (remove DB rows + disk payloads)
  const blobCutoff = new Date(nowMs - opts.blobTtlHours * 3_600_000);
  const expiredBlobs = await prisma.blobItem.findMany({
    where: { persist: false, createdAt: { lt: blobCutoff } },
    select: { id: true, storagePath: true }
  });
  let prunedBlobs = 0;
  if (expiredBlobs.length > 0) {
    const delBlobs = await prisma.blobItem.deleteMany({
      where: { id: { in: expiredBlobs.map((b) => b.id) } }
    });
    prunedBlobs = delBlobs.count;
    const blobRoot = path.resolve(opts.blobStorageDir);
    for (const b of expiredBlobs) {
      if (b.storagePath) {
        const fullPath = resolveSafeBlobPath(blobRoot, b.storagePath);
        if (fullPath) {
          await fs.promises.unlink(fullPath).catch(() => undefined);
        }
      }
    }
  }

  // 7. Expired Safe backups
  const safeCutoff = new Date(nowMs - safeRetentionDays * 86_400_000);
  const safeRes = await prisma.safeBackup.deleteMany({
    where: { updatedAt: { lt: safeCutoff } }
  });

  const stats: HousekeepingStats = {
    expiredChallenges: chRes.count,
    expiredAuthTokens: tokRes.count,
    prunedMessages: msgDelRes.count,
    droppedVolatileSlots: volatileRes.count,
    prunedReflectedEvents: prunedReflectedCount,
    prunedBlobs,
    prunedSafeBackups: safeRes.count,
    ranAt: nowDate.toISOString()
  };

  log.debug(
    `cleanup complete challenges=${stats.expiredChallenges} tokens=${stats.expiredAuthTokens} msgs=${stats.prunedMessages} volatile=${stats.droppedVolatileSlots} reflected=${stats.prunedReflectedEvents} blobs=${stats.prunedBlobs} safe=${stats.prunedSafeBackups}`
  );
  return stats;
}

export class HousekeepingScheduler {
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly intervalMs: number,
    private readonly options: Omit<HousekeepingOptions, "nowMs">
  ) {}

  start(): void {
    if (this.intervalMs <= 0 || this.timer) return;
    this.timer = setInterval(() => {
      runHousekeeping(this.prisma, this.options).catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        log.error(`housekeeping sweep failed: ${msg}`);
      });
    }, this.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}
