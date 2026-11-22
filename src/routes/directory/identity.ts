import type express from "express";
import { type AuthenticatedRequest, verifyWorkCredentials } from "../../auth/workAuth.js";
import { constantTimeStringEqual } from "../../crypto/primitives.js";
import {
  type DirectoryRouterDeps,
  formatIdentityRow,
  formatSimpleDateOffsetUtc,
  generateThreemaId,
  handleChallengeStep,
  revokeIdentityAndKick,
  toWireActivityState
} from "./shared.js";

export function registerUnauthenticatedIdentityRoutes(
  router: express.Router,
  deps: DirectoryRouterDeps
): void {
  const { prisma, cspRouter } = deps;

  // check_license accepts credentials inside JSON body (no Basic Auth required on Desktop)
  router.post("/check_license", async (req, res) => {
    const body = req.body ?? {};
    const username = typeof body.licenseUsername === "string" ? body.licenseUsername : "";
    const password = typeof body.licensePassword === "string" ? body.licensePassword : "";

    if (username && password) {
      const account = await verifyWorkCredentials(prisma, username, password);
      if (!account) {
        res.json({ success: false, error: "Invalid username or password" });
        return;
      }
      res.json({ success: true });
      return;
    }

    if (typeof body.licenseKey === "string" && body.licenseKey.length > 0) {
      res.json({ success: true });
      return;
    }

    res.json({ success: false, error: "Missing license credentials" });
  });

  // Web/password-based ID revocation per directory.openapi.yml (/identity/ws/revoke)
  router.post("/identity/ws/revoke", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity.trim() : "";
    const revocationKey = typeof body.revocationKey === "string" ? body.revocationKey : "";
    if (!identityId || !revocationKey) {
      res.json({ success: false, error: "missing-parameters" });
      return;
    }

    const row = await prisma.identity.findUnique({ where: { id: identityId } });
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }
    if (!row.revocationKeyHash || !constantTimeStringEqual(revocationKey, row.revocationKeyHash)) {
      res.json({ success: false, error: "invalid-revocation-key" });
      return;
    }

    await revokeIdentityAndKick(prisma, row.id, cspRouter);
    res.json({ success: true });
  });
}

export function registerAuthenticatedIdentityRoutes(
  router: express.Router,
  deps: DirectoryRouterDeps
): void {
  const { prisma, cspRouter } = deps;

  router.post("/identity/create", async (req: AuthenticatedRequest, res) => {
    const body = req.body ?? {};
    if (typeof body.publicKey !== "string") {
      res.status(400).json({ success: false, error: "Missing publicKey" });
      return;
    }
    const pubKey = new Uint8Array(Buffer.from(body.publicKey, "base64"));
    if (pubKey.byteLength !== 32) {
      res.status(400).json({ success: false, error: "Invalid publicKey length" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "create",
      clientPublicKey: pubKey,
      tokenB64: body.token,
      responseB64: body.response
    });

    if (step.status === "challenge") {
      res.json({ token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
      return;
    }
    if (step.status === "failed") {
      res.json({ success: false, error: step.error });
      return;
    }

    let id = generateThreemaId();
    for (let attempt = 0; attempt < 10; attempt++) {
      const exists = await prisma.identity.findUnique({ where: { id } });
      if (!exists) break;
      id = generateThreemaId();
    }

    let templateFields: {
      firstName?: string | null;
      lastName?: string | null;
      jobTitle?: string | null;
      department?: string | null;
      category?: string | null;
      csi?: string | null;
      availability?: string | null;
    } = {};

    if (req.workAccount) {
      const hasTemplate = Boolean(
        req.workAccount.firstName ||
          req.workAccount.lastName ||
          req.workAccount.jobTitle ||
          req.workAccount.department ||
          req.workAccount.category ||
          req.workAccount.csi ||
          req.workAccount.availability
      );
      if (hasTemplate) {
        const existingLinkedCount = await prisma.identity.count({
          where: { workAccountId: req.workAccount.id }
        });
        if (existingLinkedCount === 0) {
          templateFields = {
            firstName: req.workAccount.firstName,
            lastName: req.workAccount.lastName,
            jobTitle: req.workAccount.jobTitle,
            department: req.workAccount.department,
            category: req.workAccount.category,
            csi: req.workAccount.csi,
            availability: req.workAccount.availability
          };
        }
      }
    }

    const created = await prisma.identity.create({
      data: {
        id,
        publicKey: Buffer.from(pubKey),
        serverGroup: "0",
        state: 1,
        type: 1,
        featureMask: BigInt(0),
        workAccountId: req.workAccount?.id ?? null,
        workEnabled: true,
        ...templateFields
      }
    });

    res.json({
      success: true,
      identity: created.id,
      serverGroup: created.serverGroup
    });
  });

  router.post("/identity/fetch_bulk", async (req, res) => {
    const list: unknown = req.body?.identities;
    if (!Array.isArray(list)) {
      res.status(400).json({ success: false, error: "identities must be an array" });
      return;
    }
    const ids = list.filter((x): x is string => typeof x === "string");
    const rows = await prisma.identity.findMany({
      where: {
        id: { in: ids },
        state: { not: 0 }
      }
    });
    res.json({ identities: rows.map(formatIdentityRow) });
  });

  router.post("/identity/fetch_priv", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity", errorType: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "fetch_priv",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.json({ token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
      return;
    }
    if (step.status === "failed") {
      res.json({ success: false, error: step.error, errorType: "invalid-token" });
      return;
    }

    res.json({
      success: true,
      identity: row.id,
      serverGroup: row.serverGroup,
      ...(row.email ? { email: row.email } : {}),
      ...(row.mobileNo ? { mobileNo: row.mobileNo } : {})
    });
  });

  router.post("/identity/check", async (req, res) => {
    const list: unknown = req.body?.identities;
    if (!Array.isArray(list)) {
      res.status(400).json({ success: false, error: "identities must be an array" });
      return;
    }
    const ids = list.filter((x): x is string => typeof x === "string");
    const rows = await prisma.identity.findMany({ where: { id: { in: ids } } });
    const byId = new Map(rows.map((r) => [r.id, r]));

    res.json({
      checkInterval: 86400,
      states: ids.map((id) => toWireActivityState(byId.get(id)?.state)),
      types: ids.map((id) => byId.get(id)?.type ?? 0),
      featureMasks: ids.map((id) => {
        const r = byId.get(id);
        return r && r.state !== 0 ? Number(r.featureMask) : null;
      })
    });
  });

  router.post("/identity/set_featuremask", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "set_featuremask",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.json({ token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
      return;
    }
    if (step.status === "failed") {
      res.json({ success: false, error: step.error });
      return;
    }

    const mask = BigInt(body.featureMask ?? 0);
    await prisma.identity.update({
      where: { id: row.id },
      data: { featureMask: mask }
    });
    res.json({ success: true });
  });

  router.post("/identity/check_featuremask", async (req, res) => {
    const list: unknown = req.body?.identities;
    if (!Array.isArray(list)) {
      res.status(400).json({ success: false, error: "identities must be an array" });
      return;
    }
    const ids = list.filter((x): x is string => typeof x === "string");
    const rows = await prisma.identity.findMany({
      where: { id: { in: ids }, state: { not: 0 } }
    });
    const byId = new Map(rows.map((r) => [r.id, r]));
    res.json({
      featureMasks: ids.map((id) => {
        const r = byId.get(id);
        return r ? Number(r.featureMask) : null;
      })
    });
  });

  router.post("/identity/check_revocation_key", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "check_revocation_key",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.json({ token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
      return;
    }
    if (step.status === "failed") {
      res.json({ success: false, error: step.error });
      return;
    }

    res.json({
      revocationKeySet: Boolean(row.revocationKeyHash),
      ...(row.revocationKeyUpdatedAt
        ? { lastChanged: formatSimpleDateOffsetUtc(row.revocationKeyUpdatedAt) }
        : {})
    });
  });

  router.post("/identity/set_revocation_key", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "set_revocation_key",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.json({ token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
      return;
    }
    if (step.status === "failed") {
      res.json({ success: false, error: step.error });
      return;
    }

    const revKey = typeof body.revocationKey === "string" ? body.revocationKey : null;
    await prisma.identity.update({
      where: { id: row.id },
      data: {
        revocationKeyHash: revKey,
        revocationKeyUpdatedAt: new Date()
      }
    });
    res.json({ success: true });
  });

  // Challenge-authenticated ID revocation per directory.openapi.yml (/identity/revoke)
  router.post("/identity/revoke", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "revoke",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.json({ token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
      return;
    }
    if (step.status === "failed") {
      res.json({ success: false, error: step.error });
      return;
    }

    await revokeIdentityAndKick(prisma, row.id, cspRouter);
    res.json({ success: true });
  });

  router.post("/identity/update_work_info", async (req: AuthenticatedRequest, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "update_work_info",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.json({ token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
      return;
    }
    if (step.status === "failed") {
      res.json({ success: false, error: step.error });
      return;
    }

    const targetUsername =
      typeof body.licenseUsername === "string" ? body.licenseUsername : req.workAccount?.username;
    const targetAccount = targetUsername
      ? await prisma.workAccount.findUnique({ where: { username: targetUsername } })
      : null;

    const cleanOptionalString = (val: unknown): string | null | undefined => {
      if (typeof val !== "string") return undefined;
      const trimmed = val.trim();
      return trimmed.length > 0 ? trimmed : null;
    };

    const nextFirstName = cleanOptionalString(body.firstName);
    const nextLastName = cleanOptionalString(body.lastName);
    const nextJobTitle =
      body.jobTitle !== undefined
        ? typeof body.jobTitle === "string" && body.jobTitle.trim().length > 0
          ? body.jobTitle.trim()
          : null
        : undefined;
    const nextDepartment =
      body.department !== undefined
        ? typeof body.department === "string" && body.department.trim().length > 0
          ? body.department.trim()
          : null
        : undefined;
    const nextCsi = cleanOptionalString(body.csi);
    const nextCategory = cleanOptionalString(body.category);
    const nextAvailability = cleanOptionalString(body.availability);

    await prisma.identity.update({
      where: { id: row.id },
      data: {
        publicNickname:
          typeof body.publicNickname === "string" ? body.publicNickname : row.publicNickname,
        ...(targetAccount ? { workAccountId: targetAccount.id } : {}),
        ...(nextFirstName !== undefined ? { firstName: nextFirstName } : {}),
        ...(nextLastName !== undefined ? { lastName: nextLastName } : {}),
        ...(nextJobTitle !== undefined ? { jobTitle: nextJobTitle } : {}),
        ...(nextDepartment !== undefined ? { department: nextDepartment } : {}),
        ...(nextCsi !== undefined ? { csi: nextCsi } : {}),
        ...(nextCategory !== undefined ? { category: nextCategory } : {}),
        ...(nextAvailability !== undefined ? { availability: nextAvailability } : {})
      }
    });

    res.json({ success: true });
  });

  // Single identity lookup must come after fixed POST /identity/* routes
  router.get("/identity/:id", async (req, res) => {
    const row = await prisma.identity.findUnique({ where: { id: req.params.id } });
    if (!row || row.state === 0) {
      res.status(404).json({ state: 2 });
      return;
    }
    res.json(formatIdentityRow(row));
  });
}
