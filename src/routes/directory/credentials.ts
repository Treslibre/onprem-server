import crypto from "node:crypto";
import type express from "express";
import type { AuthenticatedRequest } from "../../auth/workAuth.js";
import { generateTurnCredentials } from "../../turn/server.js";
import { type DirectoryRouterDeps, handleChallengeStep } from "./shared.js";

export function registerUnauthenticatedCredentialRoutes(
  router: express.Router,
  deps: DirectoryRouterDeps
): void {
  const { prisma } = deps;

  // Android BlobUploadRequestInterceptor authenticates via Curve25519 challenge-response without Basic Auth
  router.post("/identity/blob_cred", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.status(404).json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "blob_cred",
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
      res.status(401).json({ success: false, error: step.error });
      return;
    }

    const expiresIn = 3600;
    const authToken = crypto.randomBytes(32).toString("hex");
    await prisma.authToken.create({
      data: {
        token: authToken,
        kind: "blob",
        identityId: row.id,
        expiresAt: new Date(Date.now() + expiresIn * 1000)
      }
    });

    res.json({
      success: true,
      token: authToken,
      expiration: expiresIn,
      authToken,
      expiresIn
    });
  });
}

export function registerAuthenticatedCredentialRoutes(
  router: express.Router,
  deps: DirectoryRouterDeps
): void {
  const { prisma, config, getHttpOrigin, getTurnConfig } = deps;

  router.get("/auth_token", async (req: AuthenticatedRequest, res) => {
    const authToken = crypto.randomBytes(32).toString("hex");
    await prisma.authToken.create({
      data: {
        token: authToken,
        kind: "legacy",
        username: req.workAccount?.username ?? null,
        identityId: null,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
      }
    });
    res.json({ authToken });
  });

  router.post("/identity/turn_cred", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "turn_cred",
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

    const turnCfg = getTurnConfig?.() ?? {
      host: config.turnHost,
      port: config.turnPort,
      secret: config.turnSecret
    };
    const { turnUsername, turnPassword, expiration } = generateTurnCredentials(
      row.id,
      turnCfg.secret,
      3600
    );

    let turnUrls = config.turnUrls;
    if (turnUrls.length === 0) {
      const reqHostRaw =
        req.header("x-forwarded-host")?.split(",")[0]?.trim() || req.header("host")?.trim();
      let derivedReqHost = "";
      if (reqHostRaw) {
        try {
          derivedReqHost = new URL(`https://${reqHostRaw}`).hostname;
        } catch {
          derivedReqHost = "";
        }
      }
      const fallbackHost = derivedReqHost || new URL(getHttpOrigin()).hostname;
      const effectiveTurnHost =
        turnCfg.host && turnCfg.host !== "localhost" ? turnCfg.host : fallbackHost;
      turnUrls = [
        `turn:${effectiveTurnHost}:${turnCfg.port}?transport=udp`,
        `turn:${effectiveTurnHost}:${turnCfg.port}?transport=tcp`
      ];
    }

    res.json({
      success: true,
      turnUrls,
      turnUrlsDualStack: turnUrls,
      turnUsername,
      turnPassword,
      expiration
    });
  });

  router.post("/identity/sfu_cred", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "sfu_cred",
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

    const httpOrigin = getHttpOrigin().replace(/\/+$/, "");
    const sfuBaseUrl = config.sfuBaseUrl || `${httpOrigin}/sfu/`;
    res.json({
      success: true,
      sfuBaseUrl,
      allowedSfuHostnameSuffixes: [new URL(sfuBaseUrl).hostname],
      sfuToken: crypto.randomBytes(24).toString("hex"),
      expiration: 3600
    });
  });
}
