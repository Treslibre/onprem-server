import express from "express";
import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "../config.js";
import type { KeyManager } from "../crypto/keyManager.js";
import type { CspRouter } from "../csp/session.js";
import type { D2mMediatorServer } from "../d2m/mediator.js";
import type { RendezvousServer } from "../rendezvous/server.js";
import type { HousekeepingStats } from "../maintenance/sweeper.js";
import { constantTimeStringEqual, hashPassword } from "../crypto/primitives.js";
import { revokeIdentityAndKick } from "./directory/shared.js";
import { renderAdminUiHtml } from "./adminUi.js";

export interface AdminRouterDeps {
  prisma: PrismaClient;
  config: ServerConfig;
  keyManager: KeyManager;
  cspRouter?: CspRouter;
  mediator?: D2mMediatorServer;
  rendezvous?: RendezvousServer;
  getTurnStats?: () => {
    enabled: boolean;
    port: number;
    externalIp: string;
    activeAllocations: number;
    activeTcpSockets: number;
  };
  getAddresses?: () => {
    httpPort: number;
    cspPort: number;
    turnPort: number;
    turnExternalIp: string;
    httpOrigin: string;
    wsOrigin: string;
  };
  runCleanup?: () => Promise<HousekeepingStats>;
}

function optStr(v: unknown): string | null | undefined {
  if (v === undefined) return undefined;
  if (v === null) return null;
  if (typeof v === "string") {
    const trimmed = v.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  return undefined;
}

export function createAdminRouter(deps: AdminRouterDeps): express.Router {
  const { prisma, config, keyManager, cspRouter, mediator, rendezvous, getTurnStats, getAddresses, runCleanup } = deps;
  const router = express.Router();
  const startedAtMs = Date.now();

  // Serve self-hosted Admin Panel SPA HTML unauthenticated (API calls inside authenticate via X-Admin-Key)
  router.get(["/ui", "/ui/"], (_req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.status(200).send(renderAdminUiHtml());
  });

  // Constant-time X-Admin-Key protection for all admin API routes
  router.use((req, res, next) => {
    if (config.adminApiKey) {
      const provided = req.header("x-admin-key") ?? "";
      if (!provided || !constantTimeStringEqual(provided, config.adminApiKey)) {
        res.status(401).json({ error: "Unauthorized" });
        return;
      }
    }
    next();
  });

  // Logo binary upload/delete must register BEFORE express.json middleware consumes body
  router.put(
    "/mdm/logo/:variant",
    express.raw({ type: "*/*", limit: "2mb" }),
    async (req, res) => {
      const variant = req.params.variant;
      if (variant !== "light" && variant !== "dark") {
        res.status(400).json({ error: "variant must be 'light' or 'dark'" });
        return;
      }
      const data = new Uint8Array(Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0));
      if (data.byteLength === 0) {
        res.status(400).json({ error: "Empty logo payload" });
        return;
      }
      const contentType = req.header("content-type") || "image/png";
      await prisma.workMdmConfig.upsert({
        where: { id: "default" },
        create: {
          id: "default",
          ...(variant === "light"
            ? { logoLightData: data, logoLightContentType: contentType }
            : { logoDarkData: data, logoDarkContentType: contentType })
        },
        update:
          variant === "light"
            ? { logoLightData: data, logoLightContentType: contentType }
            : { logoDarkData: data, logoDarkContentType: contentType }
      });
      res.status(204).end();
    }
  );

  router.delete("/mdm/logo/:variant", async (req, res) => {
    const variant = req.params.variant;
    if (variant !== "light" && variant !== "dark") {
      res.status(400).json({ error: "variant must be 'light' or 'dark'" });
      return;
    }
    await prisma.workMdmConfig
      .update({
        where: { id: "default" },
        data:
          variant === "light"
            ? { logoLightData: null, logoLightContentType: null }
            : { logoDarkData: null, logoDarkContentType: null }
      })
      .catch(() => undefined);
    res.status(204).end();
  });

  router.use(express.json({ limit: "1mb" }));

  router.get("/keys", (_req, res) => {
    res.json({
      oppfPublicKeyBase64: keyManager.getOppfPublicKeyBase64(),
      cspPublicKeyBase64: keyManager.getCspKeyPair().publicKeyBase64
    });
  });

  router.get("/status", async (_req, res) => {
    const [
      accounts,
      activeIdentities,
      inactiveIdentities,
      revokedIdentities,
      queuedMessages,
      blobsAgg,
      safeBackups,
      spamReports,
      deviceGroups,
      deviceSlots,
      remoteSecrets,
      pushTokens,
      mdm
    ] = await Promise.all([
      prisma.workAccount.count(),
      prisma.identity.count({ where: { state: 1 } }),
      prisma.identity.count({ where: { state: 2 } }),
      prisma.identity.count({ where: { state: 0 } }),
      prisma.queuedMessage.count({ where: { delivered: false } }),
      prisma.blobItem.aggregate({ _count: true, _sum: { size: true } }),
      prisma.safeBackup.count(),
      prisma.spamReport.count(),
      prisma.deviceGroup.count(),
      prisma.deviceSlot.count({ where: { dropped: false } }),
      prisma.remoteSecret.count(),
      prisma.pushToken.count(),
      prisma.workMdmConfig.findUnique({ where: { id: "default" }, select: { remoteSecretEnabled: true } })
    ]);

    const addrs = getAddresses?.() ?? {
      httpPort: config.httpPort,
      cspPort: config.cspPort,
      turnPort: config.turnEnabled ? config.turnPort : 0,
      turnExternalIp: config.turnExternalIp || config.turnHost,
      httpOrigin: config.publicHttpOrigin,
      wsOrigin: config.publicWsOrigin
    };

    res.json({
      uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
      addresses: addrs,
      keys: {
        oppfPublicKeyBase64: keyManager.getOppfPublicKeyBase64(),
        cspPublicKeyBase64: keyManager.getCspKeyPair().publicKeyBase64
      },
      config: {
        cspHost: config.cspHost,
        turnEnabled: config.turnEnabled,
        tlsEnabled: config.tlsEnabled,
        tlsPinSpki: config.tlsPinSpki,
        remoteSecretEnabled: Boolean(config.remoteSecretEnabled || mdm?.remoteSecretEnabled),
        blobTtlHours: config.blobTtlHours
      },
      live: {
        csp: cspRouter?.getStats() ?? { activeSessions: 0, activeIdentities: 0, sessions: [] },
        d2m: mediator?.getStats() ?? {
          activeGroups: 0,
          activeConnections: 0,
          activeTransactions: 0,
          groups: []
        },
        rendezvous: rendezvous?.getStats() ?? {
          totalChannels: 0,
          waitingChannels: 0,
          pairedChannels: 0
        },
        turn: getTurnStats?.() ?? {
          enabled: config.turnEnabled,
          port: addrs.turnPort,
          externalIp: addrs.turnExternalIp,
          activeAllocations: 0,
          activeTcpSockets: 0
        }
      },
      counts: {
        accounts,
        activeIdentities,
        inactiveIdentities,
        revokedIdentities,
        queuedMessages,
        blobs: blobsAgg._count,
        blobTotalBytes: blobsAgg._sum.size ?? 0,
        safeBackups,
        spamReports,
        deviceGroups,
        deviceSlots,
        remoteSecrets,
        pushTokens
      }
    });
  });

  router.get("/accounts", async (_req, res) => {
    const accounts = await prisma.workAccount.findMany({
      select: {
        id: true,
        username: true,
        enabled: true,
        firstName: true,
        lastName: true,
        jobTitle: true,
        department: true,
        category: true,
        csi: true,
        availability: true,
        identities: {
          select: {
            id: true,
            publicNickname: true,
            firstName: true,
            lastName: true
          }
        },
        createdAt: true,
        updatedAt: true
      }
    });
    res.json({ accounts });
  });

  router.post("/accounts", async (req, res) => {
    const body = req.body ?? {};
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!username || !password) {
      res.status(400).json({ error: "username and password are required" });
      return;
    }

    const existing = await prisma.workAccount.findUnique({ where: { username } });
    if (existing) {
      res.status(409).json({ error: "Account already exists" });
      return;
    }

    const created = await prisma.workAccount.create({
      data: {
        username,
        passwordHash: hashPassword(password),
        enabled: body.enabled !== false,
        firstName: typeof body.firstName === "string" ? body.firstName : null,
        lastName: typeof body.lastName === "string" ? body.lastName : null,
        jobTitle: typeof body.jobTitle === "string" ? body.jobTitle : null,
        department: typeof body.department === "string" ? body.department : null,
        category: typeof body.category === "string" ? body.category : null,
        csi: typeof body.csi === "string" ? body.csi : null,
        availability: typeof body.availability === "string" ? body.availability : null
      },
      select: {
        id: true,
        username: true,
        enabled: true,
        firstName: true,
        lastName: true,
        jobTitle: true,
        department: true,
        category: true,
        csi: true
      }
    });

    res.status(201).json({ account: created });
  });

  router.patch("/accounts/:id", async (req, res) => {
    const existing = await prisma.workAccount.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: "Account not found" });
      return;
    }
    const body = req.body ?? {};
    const newPassword = typeof body.password === "string" && body.password.length > 0 ? body.password : null;

    const updated = await prisma.workAccount.update({
      where: { id: existing.id },
      data: {
        ...(typeof body.enabled === "boolean" ? { enabled: body.enabled } : {}),
        ...(newPassword ? { passwordHash: hashPassword(newPassword) } : {}),
        ...(optStr(body.firstName) !== undefined ? { firstName: optStr(body.firstName) } : {}),
        ...(optStr(body.lastName) !== undefined ? { lastName: optStr(body.lastName) } : {}),
        ...(optStr(body.jobTitle) !== undefined ? { jobTitle: optStr(body.jobTitle) } : {}),
        ...(optStr(body.department) !== undefined ? { department: optStr(body.department) } : {}),
        ...(optStr(body.category) !== undefined ? { category: optStr(body.category) } : {}),
        ...(optStr(body.csi) !== undefined ? { csi: optStr(body.csi) } : {}),
        ...(optStr(body.availability) !== undefined
          ? { availability: optStr(body.availability) }
          : {})
      },
      select: {
        id: true,
        username: true,
        enabled: true,
        firstName: true,
        lastName: true,
        jobTitle: true,
        department: true,
        category: true,
        csi: true,
        updatedAt: true
      }
    });
    res.json({ account: updated });
  });

  router.delete("/accounts/:id", async (req, res) => {
    const existing = await prisma.workAccount.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: "Account not found" });
      return;
    }
    await prisma.workAccount.delete({ where: { id: existing.id } });
    res.status(204).end();
  });

  router.get("/identities", async (_req, res) => {
    const identities = await prisma.identity.findMany({
      select: {
        id: true,
        state: true,
        type: true,
        publicNickname: true,
        firstName: true,
        lastName: true,
        jobTitle: true,
        department: true,
        category: true,
        csi: true,
        availability: true,
        workEnabled: true,
        workAccountId: true,
        lastLoginAt: true,
        deviceCookieChanged: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { createdAt: "asc" }
    });
    res.json({ identities });
  });

  router.patch("/identities/:id", async (req, res) => {
    const existing = await prisma.identity.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: "Identity not found" });
      return;
    }

    const body = req.body ?? {};
    const nextState = typeof body.state === "number" ? body.state : undefined;

    if (nextState === 0 && existing.state !== 0) {
      await revokeIdentityAndKick(prisma, existing.id, cspRouter);
    }

    const updated = await prisma.identity.update({
      where: { id: existing.id },
      data: {
        ...(optStr(body.publicNickname) !== undefined
          ? { publicNickname: optStr(body.publicNickname) }
          : {}),
        ...(optStr(body.firstName) !== undefined ? { firstName: optStr(body.firstName) } : {}),
        ...(optStr(body.lastName) !== undefined ? { lastName: optStr(body.lastName) } : {}),
        ...(optStr(body.jobTitle) !== undefined ? { jobTitle: optStr(body.jobTitle) } : {}),
        ...(optStr(body.department) !== undefined ? { department: optStr(body.department) } : {}),
        ...(optStr(body.category) !== undefined ? { category: optStr(body.category) } : {}),
        ...(optStr(body.csi) !== undefined ? { csi: optStr(body.csi) } : {}),
        ...(optStr(body.availability) !== undefined
          ? { availability: optStr(body.availability) }
          : {}),
        ...(typeof body.workEnabled === "boolean" ? { workEnabled: body.workEnabled } : {}),
        ...(nextState !== undefined ? { state: nextState } : {})
      },
      select: {
        id: true,
        state: true,
        type: true,
        publicNickname: true,
        firstName: true,
        lastName: true,
        jobTitle: true,
        department: true,
        category: true,
        csi: true,
        availability: true,
        workEnabled: true,
        workAccountId: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (nextState === 2) {
      cspRouter?.kickIdentity(existing.id, "Identity deactivated by administrator", false);
    }

    res.json({ identity: updated });
  });

  router.delete("/identities/:id", async (req, res) => {
    const existing = await prisma.identity.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      res.status(404).json({ error: "Identity not found" });
      return;
    }
    cspRouter?.kickIdentity(existing.id, "Identity deleted by administrator", false);
    await prisma.identity.delete({ where: { id: existing.id } });
    res.status(204).end();
  });

  router.post("/alert", (req, res) => {
    const body = req.body ?? {};
    const message = typeof body.message === "string" ? body.message.trim() : "";
    if (!message) {
      res.status(400).json({ error: "message is required" });
      return;
    }
    const targetIdentity =
      typeof body.identity === "string" && body.identity.trim().length > 0
        ? body.identity.trim()
        : null;
    const deliveredCount = cspRouter?.sendAlert(targetIdentity, message) ?? 0;
    res.json({ success: true, deliveredCount });
  });

  router.get("/mdm", async (_req, res) => {
    const row = await prisma.workMdmConfig.findUnique({ where: { id: "default" } });
    let categories: Record<string, string> = {};
    let params: Record<string, unknown> = {};
    try {
      categories = row ? (JSON.parse(row.categoriesJson) as Record<string, string>) : {};
    } catch {
      categories = {};
    }
    try {
      params = row ? (JSON.parse(row.paramsJson) as Record<string, unknown>) : {};
    } catch {
      params = {};
    }

    res.json({
      mdm: {
        orgName: row?.orgName ?? config.orgName,
        support: row?.support ?? null,
        directoryEnabled: row?.directoryEnabled ?? true,
        checkInterval: row?.checkInterval ?? 86400,
        override: row?.override ?? false,
        remoteSecretEnabled: row?.remoteSecretEnabled ?? config.remoteSecretEnabled,
        logoLight: row?.logoLight ?? null,
        logoDark: row?.logoDark ?? null,
        hasLogoLightData: Boolean(row?.logoLightData && row.logoLightData.byteLength > 0),
        hasLogoDarkData: Boolean(row?.logoDarkData && row.logoDarkData.byteLength > 0),
        categories,
        params
      }
    });
  });

  router.put("/mdm", async (req, res) => {
    const body = req.body ?? {};
    const checkInterval =
      typeof body.checkInterval === "number" && body.checkInterval >= 60
        ? Math.floor(body.checkInterval)
        : undefined;
    const categoriesJson =
      body.categories && typeof body.categories === "object" && !Array.isArray(body.categories)
        ? JSON.stringify(body.categories)
        : undefined;
    const paramsJson =
      body.params && typeof body.params === "object" && !Array.isArray(body.params)
        ? JSON.stringify(body.params)
        : undefined;

    await prisma.workMdmConfig.upsert({
      where: { id: "default" },
      create: {
        id: "default",
        orgName: optStr(body.orgName) ?? config.orgName,
        support: optStr(body.support) ?? null,
        directoryEnabled: body.directoryEnabled !== false,
        checkInterval: checkInterval ?? 86400,
        override: Boolean(body.override),
        remoteSecretEnabled: Boolean(body.remoteSecretEnabled),
        logoLight: optStr(body.logoLight) ?? null,
        logoDark: optStr(body.logoDark) ?? null,
        categoriesJson: categoriesJson ?? "{}",
        paramsJson: paramsJson ?? "{}"
      },
      update: {
        ...(optStr(body.orgName) !== undefined && optStr(body.orgName) !== null
          ? { orgName: optStr(body.orgName)! }
          : {}),
        ...(optStr(body.support) !== undefined ? { support: optStr(body.support) } : {}),
        ...(typeof body.directoryEnabled === "boolean"
          ? { directoryEnabled: body.directoryEnabled }
          : {}),
        ...(checkInterval !== undefined ? { checkInterval } : {}),
        ...(typeof body.override === "boolean" ? { override: body.override } : {}),
        ...(typeof body.remoteSecretEnabled === "boolean"
          ? { remoteSecretEnabled: body.remoteSecretEnabled }
          : {}),
        ...(optStr(body.logoLight) !== undefined ? { logoLight: optStr(body.logoLight) } : {}),
        ...(optStr(body.logoDark) !== undefined ? { logoDark: optStr(body.logoDark) } : {}),
        ...(categoriesJson !== undefined ? { categoriesJson } : {}),
        ...(paramsJson !== undefined ? { paramsJson } : {})
      }
    });

    res.json({ success: true });
  });

  router.get("/devices", async (_req, res) => {
    const groups = await prisma.deviceGroup.findMany({
      include: {
        devices: { orderBy: { id: "asc" } },
        _count: { select: { events: true } }
      },
      orderBy: { createdAt: "desc" }
    });
    const d2mLive = mediator?.getStats().groups ?? [];
    const liveByGroup = new Map(d2mLive.map((g) => [g.dgid, g.connections]));

    res.json({
      groups: groups.map((g) => {
        const liveConns = liveByGroup.get(g.dgid) ?? [];
        const liveByDev = new Map(liveConns.map((c) => [c.deviceId, c]));
        return {
          dgid: g.dgid,
          serverGroup: g.serverGroup,
          nextReflectId: g.nextReflectId,
          storedEvents: g._count.events,
          devices: g.devices.map((d) => {
            const live = liveByDev.get(d.deviceId);
            return {
              deviceId: d.deviceId,
              expirationPolicy: d.expirationPolicy,
              minReflectId: d.minReflectId,
              dropped: d.dropped,
              online: Boolean(live),
              isLeader: Boolean(live?.isLeader),
              connectedSince: d.connectedSince !== null ? Number(d.connectedSince) : null,
              lastDisconnectAt: d.lastDisconnectAt !== null ? Number(d.lastDisconnectAt) : null
            };
          })
        };
      })
    });
  });

  router.delete("/devices/:dgid/:deviceId", async (req, res) => {
    const { dgid, deviceId } = req.params;
    if (!mediator) {
      await prisma.deviceSlot.updateMany({
        where: { dgid, deviceId },
        data: { dropped: true, connectedSince: null, lastDisconnectAt: BigInt(Date.now()) }
      });
      res.status(204).end();
      return;
    }
    const found = await mediator.dropDevice(dgid, deviceId);
    if (!found) {
      res.status(404).json({ error: "Device slot not found" });
      return;
    }
    res.status(204).end();
  });

  router.get("/remote-secrets", async (_req, res) => {
    const remoteSecrets = await prisma.remoteSecret.findMany({
      select: {
        authTokenHash: true,
        identityId: true,
        blocked: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { updatedAt: "desc" }
    });
    res.json({ remoteSecrets });
  });

  router.patch("/remote-secrets/:authTokenHash", async (req, res) => {
    const existing = await prisma.remoteSecret.findUnique({
      where: { authTokenHash: req.params.authTokenHash }
    });
    if (!existing) {
      res.status(404).json({ error: "Remote secret not found" });
      return;
    }
    const blocked = Boolean(req.body?.blocked);
    const updated = await prisma.remoteSecret.update({
      where: { authTokenHash: existing.authTokenHash },
      data: { blocked },
      select: { authTokenHash: true, identityId: true, blocked: true, updatedAt: true }
    });
    res.json({ remoteSecret: updated });
  });

  router.delete("/remote-secrets/:authTokenHash", async (req, res) => {
    await prisma.remoteSecret
      .delete({ where: { authTokenHash: req.params.authTokenHash } })
      .catch(() => undefined);
    res.status(204).end();
  });

  router.get("/reports", async (_req, res) => {
    const reports = await prisma.spamReport.findMany({
      orderBy: { id: "desc" },
      take: 200
    });
    res.json({ reports });
  });

  router.delete("/reports/:id", async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) {
      res.status(400).json({ error: "Invalid report ID" });
      return;
    }
    await prisma.spamReport.delete({ where: { id } }).catch(() => undefined);
    res.status(204).end();
  });

  router.post("/cleanup", async (_req, res) => {
    if (!runCleanup) {
      res.status(501).json({ error: "Cleanup runner unavailable" });
      return;
    }
    const stats = await runCleanup();
    res.json({ success: true, stats });
  });

  return router;
}
