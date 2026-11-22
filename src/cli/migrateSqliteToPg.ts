import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { loadConfig } from "../config.js";
import { createPrismaClient } from "../db.js";

function toBytes(v: unknown): Uint8Array<ArrayBuffer> {
  if (v instanceof Uint8Array) {
    const copy = new Uint8Array(v.byteLength);
    copy.set(v);
    return copy;
  }
  if (Buffer.isBuffer(v)) {
    const copy = new Uint8Array(v.byteLength);
    copy.set(v);
    return copy;
  }
  return new Uint8Array(0);
}

function toNullableBytes(v: unknown): Uint8Array<ArrayBuffer> | null {
  if (v === null || v === undefined) return null;
  return toBytes(v);
}

function toDate(v: unknown): Date {
  if (v instanceof Date) return v;
  if (typeof v === "number") return new Date(v);
  if (typeof v === "bigint") return new Date(Number(v));
  if (typeof v === "string") {
    const num = Number(v);
    if (Number.isFinite(num) && /^\d+$/.test(v)) return new Date(num);
    return new Date(v);
  }
  return new Date();
}

function toNullableDate(v: unknown): Date | null {
  if (v === null || v === undefined) return null;
  return toDate(v);
}

function toBool(v: unknown, fallback = false): boolean {
  if (v === null || v === undefined) return fallback;
  if (typeof v === "boolean") return v;
  if (typeof v === "number" || typeof v === "bigint") return Number(v) !== 0;
  if (typeof v === "string") return v === "1" || v.toLowerCase() === "true";
  return Boolean(v);
}

function toBigInt(v: unknown, fallback = 0n): bigint {
  if (v === null || v === undefined) return fallback;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(Math.trunc(v));
  if (typeof v === "string" && v.trim() !== "") return BigInt(v);
  return fallback;
}

function toNullableBigInt(v: unknown): bigint | null {
  if (v === null || v === undefined) return null;
  return toBigInt(v);
}

async function main() {
  const projectRoot = path.resolve(import.meta.dirname, "../..");
  const sqliteArg = process.argv[2];
  const sqlitePath = sqliteArg
    ? path.resolve(sqliteArg)
    : path.join(projectRoot, "prisma", "dev.db");

  if (!fs.existsSync(sqlitePath)) {
    console.error(`SQLite file not found at ${sqlitePath}`);
    process.exit(1);
  }

  const config = loadConfig();
  if (config.databaseUrl.startsWith("file:")) {
    console.error(
      `DATABASE_URL is still pointing to a SQLite file (${config.databaseUrl}). Set DATABASE_URL to your PostgreSQL connection string first.`
    );
    process.exit(1);
  }

  const sqlite = new DatabaseSync(sqlitePath, { open: true, readOnly: true });
  const prisma = createPrismaClient(config.databaseUrl);

  const hasTable = (name: string): boolean => {
    const row = sqlite
      .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`)
      .get(name) as { name?: string } | undefined;
    return Boolean(row?.name);
  };

  const readRows = (table: string): Array<Record<string, unknown>> => {
    if (!hasTable(table)) return [];
    return sqlite.prepare(`SELECT * FROM "${table}"`).all() as Array<Record<string, unknown>>;
  };

  try {
    console.log(`Migrating SQLite data from ${sqlitePath} -> PostgreSQL...`);

    // 1. ServerKey
    const serverKeys = readRows("ServerKey");
    for (const r of serverKeys) {
      const name = String(r.name);
      await prisma.serverKey.upsert({
        where: { name },
        create: {
          name,
          publicKey: toBytes(r.publicKey),
          privateKey: toBytes(r.privateKey),
          createdAt: toDate(r.createdAt),
          updatedAt: toDate(r.updatedAt)
        },
        update: {
          publicKey: toBytes(r.publicKey),
          privateKey: toBytes(r.privateKey),
          updatedAt: toDate(r.updatedAt)
        }
      });
    }
    console.log(`  ServerKey: ${serverKeys.length} migrated`);

    // 2. WorkMdmConfig
    const mdmConfigs = readRows("WorkMdmConfig");
    for (const r of mdmConfigs) {
      const id = String(r.id || "default");
      const data = {
        override: toBool(r.override, false),
        paramsJson: String(r.paramsJson ?? "{}"),
        logoLight: r.logoLight ? String(r.logoLight) : null,
        logoDark: r.logoDark ? String(r.logoDark) : null,
        logoLightData: toNullableBytes(r.logoLightData),
        logoLightContentType: r.logoLightContentType ? String(r.logoLightContentType) : null,
        logoDarkData: toNullableBytes(r.logoDarkData),
        logoDarkContentType: r.logoDarkContentType ? String(r.logoDarkContentType) : null,
        directoryEnabled: toBool(r.directoryEnabled, true),
        categoriesJson: String(r.categoriesJson ?? "{}"),
        orgName: String(r.orgName ?? "OnPrem Organization"),
        support: r.support ? String(r.support) : null,
        checkInterval: Number(r.checkInterval ?? 86400),
        remoteSecretEnabled: toBool(r.remoteSecretEnabled, false)
      };
      await prisma.workMdmConfig.upsert({
        where: { id },
        create: { id, ...data },
        update: data
      });
    }
    console.log(`  WorkMdmConfig: ${mdmConfigs.length} migrated`);

    // 3. WorkAccount
    const workAccounts = readRows("WorkAccount");
    for (const r of workAccounts) {
      const id = String(r.id);
      const data = {
        username: String(r.username),
        passwordHash: String(r.passwordHash),
        enabled: toBool(r.enabled, true),
        firstName: r.firstName ? String(r.firstName) : null,
        lastName: r.lastName ? String(r.lastName) : null,
        jobTitle: r.jobTitle ? String(r.jobTitle) : null,
        department: r.department ? String(r.department) : null,
        category: r.category ? String(r.category) : null,
        csi: r.csi ? String(r.csi) : null,
        availability: r.availability ? String(r.availability) : null,
        createdAt: toDate(r.createdAt),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.workAccount.upsert({
        where: { id },
        create: { id, ...data },
        update: data
      });
    }
    console.log(`  WorkAccount: ${workAccounts.length} migrated`);

    // 4. Identity
    const identities = readRows("Identity");
    for (const r of identities) {
      const id = String(r.id);
      const data = {
        publicKey: toBytes(r.publicKey),
        serverGroup: String(r.serverGroup ?? "0"),
        state: Number(r.state ?? 1),
        type: Number(r.type ?? 0),
        featureMask: toBigInt(r.featureMask, 0n),
        email: r.email ? String(r.email) : null,
        emailHash: r.emailHash ? String(r.emailHash) : null,
        mobileNo: r.mobileNo ? String(r.mobileNo) : null,
        mobileNoHash: r.mobileNoHash ? String(r.mobileNoHash) : null,
        pendingMobileNo: r.pendingMobileNo ? String(r.pendingMobileNo) : null,
        mobileVerifyId: r.mobileVerifyId ? String(r.mobileVerifyId) : null,
        mobileVerifyCode: r.mobileVerifyCode ? String(r.mobileVerifyCode) : null,
        revocationKeyHash: r.revocationKeyHash ? String(r.revocationKeyHash) : null,
        revocationKeyUpdatedAt: toNullableDate(r.revocationKeyUpdatedAt),
        publicNickname: r.publicNickname ? String(r.publicNickname) : null,
        deviceCookie: toNullableBytes(r.deviceCookie),
        deviceCookieChanged: toBool(r.deviceCookieChanged, false),
        lastLoginAt: toNullableDate(r.lastLoginAt),
        workAccountId: r.workAccountId ? String(r.workAccountId) : null,
        workEnabled: toBool(r.workEnabled, true),
        firstName: r.firstName ? String(r.firstName) : null,
        lastName: r.lastName ? String(r.lastName) : null,
        jobTitle: r.jobTitle ? String(r.jobTitle) : null,
        department: r.department ? String(r.department) : null,
        category: r.category ? String(r.category) : null,
        csi: r.csi ? String(r.csi) : null,
        availability: r.availability ? String(r.availability) : null,
        createdAt: toDate(r.createdAt),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.identity.upsert({
        where: { id },
        create: { id, ...data },
        update: data
      });
    }
    console.log(`  Identity: ${identities.length} migrated`);

    // 5. Avatar
    const avatars = readRows("Avatar");
    for (const r of avatars) {
      const identityId = String(r.identityId);
      const data = {
        contentType: String(r.contentType ?? "image/jpeg"),
        data: toBytes(r.data),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.avatar.upsert({
        where: { identityId },
        create: { identityId, ...data },
        update: data
      });
    }
    console.log(`  Avatar: ${avatars.length} migrated`);

    // 6. SafeBackup
    const safeBackups = readRows("SafeBackup");
    for (const r of safeBackups) {
      const backupId = String(r.backupId);
      const data = {
        data: toBytes(r.data),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.safeBackup.upsert({
        where: { backupId },
        create: { backupId, ...data },
        update: data
      });
    }
    console.log(`  SafeBackup: ${safeBackups.length} migrated`);

    // 7. BlobItem
    const blobs = readRows("BlobItem");
    for (const r of blobs) {
      const id = String(r.id);
      const data = {
        scope: String(r.scope ?? "usual"),
        deviceGroupId: r.deviceGroupId ? String(r.deviceGroupId) : null,
        persist: toBool(r.persist, false),
        data: toBytes(r.data),
        storagePath: r.storagePath ? String(r.storagePath) : null,
        size: Number(r.size ?? 0),
        doneCount: Number(r.doneCount ?? 0),
        createdAt: toDate(r.createdAt)
      };
      await prisma.blobItem.upsert({
        where: { id },
        create: { id, ...data },
        update: data
      });
    }
    console.log(`  BlobItem: ${blobs.length} migrated`);

    // 8. DeviceGroup, DeviceSlot, ReflectedEvent, DeviceReflectionAck
    const deviceGroups = readRows("DeviceGroup");
    for (const r of deviceGroups) {
      const dgid = String(r.dgid);
      const data = {
        serverGroup: String(r.serverGroup ?? "0"),
        encryptedSharedDeviceData: toBytes(r.encryptedSharedDeviceData),
        nextReflectId: Number(r.nextReflectId ?? 1),
        createdAt: toDate(r.createdAt),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.deviceGroup.upsert({
        where: { dgid },
        create: { dgid, ...data },
        update: data
      });
    }
    console.log(`  DeviceGroup: ${deviceGroups.length} migrated`);

    const deviceSlots = readRows("DeviceSlot");
    for (const r of deviceSlots) {
      const dgid = String(r.dgid);
      const deviceId = String(r.deviceId);
      const data = {
        expirationPolicy: Number(r.expirationPolicy ?? 1),
        encryptedDeviceInfo: toBytes(r.encryptedDeviceInfo),
        minReflectId: Number(r.minReflectId ?? 1),
        connectedSince: toNullableBigInt(r.connectedSince),
        lastDisconnectAt: toNullableBigInt(r.lastDisconnectAt),
        dropped: toBool(r.dropped, false),
        createdAt: toDate(r.createdAt),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.deviceSlot.upsert({
        where: { dgid_deviceId: { dgid, deviceId } },
        create: { dgid, deviceId, ...data },
        update: data
      });
    }
    console.log(`  DeviceSlot: ${deviceSlots.length} migrated`);

    const reflectedEvents = readRows("ReflectedEvent");
    for (const r of reflectedEvents) {
      const dgid = String(r.dgid);
      const reflectId = Number(r.reflectId);
      const data = {
        senderDeviceId: String(r.senderDeviceId),
        flags: Number(r.flags ?? 0),
        timestamp: toBigInt(r.timestamp, 0n),
        envelope: toBytes(r.envelope),
        createdAt: toDate(r.createdAt)
      };
      await prisma.reflectedEvent.upsert({
        where: { dgid_reflectId: { dgid, reflectId } },
        create: { dgid, reflectId, ...data },
        update: data
      });
    }
    console.log(`  ReflectedEvent: ${reflectedEvents.length} migrated`);

    const reflectionAcks = readRows("DeviceReflectionAck");
    for (const r of reflectionAcks) {
      const dgid = String(r.dgid);
      const deviceId = String(r.deviceId);
      const reflectId = Number(r.reflectId);
      await prisma.deviceReflectionAck.upsert({
        where: { dgid_deviceId_reflectId: { dgid, deviceId, reflectId } },
        create: { dgid, deviceId, reflectId, ackedAt: toDate(r.ackedAt) },
        update: { ackedAt: toDate(r.ackedAt) }
      });
    }
    console.log(`  DeviceReflectionAck: ${reflectionAcks.length} migrated`);

    // 9. QueuedMessage
    const queuedMessages = readRows("QueuedMessage");
    for (const r of queuedMessages) {
      if (toBool(r.delivered, false)) continue;
      await prisma.queuedMessage.create({
        data: {
          fromIdentity: String(r.fromIdentity),
          toIdentity: String(r.toIdentity),
          messageId: toBytes(r.messageId),
          rawPayload: toBytes(r.rawPayload),
          delivered: false,
          createdAt: toDate(r.createdAt)
        }
      });
    }
    console.log(`  QueuedMessage (undelivered): ${queuedMessages.filter((r) => !toBool(r.delivered, false)).length} migrated`);

    // 10. PushToken & RemoteSecret & SpamReport
    const pushTokens = readRows("PushToken");
    for (const r of pushTokens) {
      const identityId = String(r.identityId);
      const cspDeviceId = String(r.cspDeviceId ?? "0");
      const priority = String(r.priority ?? "normal");
      const data = {
        tokenType: Number(r.tokenType),
        token: toBytes(r.token),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.pushToken.upsert({
        where: { identityId_cspDeviceId_priority: { identityId, cspDeviceId, priority } },
        create: { identityId, cspDeviceId, priority, ...data },
        update: data
      });
    }
    console.log(`  PushToken: ${pushTokens.length} migrated`);

    const remoteSecrets = readRows("RemoteSecret");
    for (const r of remoteSecrets) {
      const authTokenHash = String(r.authTokenHash);
      const data = {
        identityId: String(r.identityId),
        secret: toBytes(r.secret),
        blocked: toBool(r.blocked, false),
        createdAt: toDate(r.createdAt),
        updatedAt: toDate(r.updatedAt)
      };
      await prisma.remoteSecret.upsert({
        where: { authTokenHash },
        create: { authTokenHash, ...data },
        update: data
      });
    }
    console.log(`  RemoteSecret: ${remoteSecrets.length} migrated`);

    console.log("Migration to PostgreSQL completed successfully!");
  } finally {
    sqlite.close();
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error("Failed to migrate SQLite to PostgreSQL:", err);
  process.exit(1);
});
