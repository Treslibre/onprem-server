import crypto from "node:crypto";
import type express from "express";
import { hmacEmail, hmacMobileNo } from "../../crypto/primitives.js";
import { type DirectoryRouterDeps, handleChallengeStep } from "./shared.js";

export function registerMatchingRoutes(router: express.Router, deps: DirectoryRouterDeps): void {
  const { prisma } = deps;

  router.post("/identity/match_token", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "match_token",
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

    const matchToken = crypto.randomBytes(24).toString("hex");
    await prisma.authToken.create({
      data: {
        token: matchToken,
        kind: "match",
        identityId: row.id,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
      }
    });
    res.json({ success: true, matchToken });
  });

  router.post("/identity/match", async (req, res) => {
    const body = req.body ?? {};
    const emailHashes: string[] = Array.isArray(body.emailHashes)
      ? body.emailHashes.filter((x: unknown): x is string => typeof x === "string")
      : [];
    const mobileNoHashes: string[] = Array.isArray(body.mobileNoHashes)
      ? body.mobileNoHashes.filter((x: unknown): x is string => typeof x === "string")
      : [];
    const includeInactive = Boolean(body.includeInactive);

    if (typeof body.matchToken === "string" && body.matchToken.length > 0) {
      const tok = await prisma.authToken.findUnique({ where: { token: body.matchToken } });
      if (!tok || tok.kind !== "match" || tok.expiresAt.getTime() <= Date.now()) {
        res.status(401).json({ success: false, error: "Invalid matchToken" });
        return;
      }
    }

    if (emailHashes.length === 0 && mobileNoHashes.length === 0) {
      res.json({ checkInterval: 86400, identities: [] });
      return;
    }

    const orClauses: Array<{ emailHash?: { in: string[] }; mobileNoHash?: { in: string[] } }> = [];
    if (emailHashes.length > 0) orClauses.push({ emailHash: { in: emailHashes } });
    if (mobileNoHashes.length > 0) orClauses.push({ mobileNoHash: { in: mobileNoHashes } });

    const matches = await prisma.identity.findMany({
      where: {
        OR: orClauses,
        state: includeInactive ? { in: [1, 2] } : 1
      }
    });

    const emailSet = new Set(emailHashes);
    const mobileSet = new Set(mobileNoHashes);
    res.json({
      checkInterval: 86400,
      identities: matches.map((m) => ({
        identity: m.id,
        publicKey: Buffer.from(m.publicKey).toString("base64"),
        ...(m.emailHash && emailSet.has(m.emailHash) ? { emailHash: m.emailHash } : {}),
        ...(m.mobileNoHash && mobileSet.has(m.mobileNoHash)
          ? { mobileNoHash: m.mobileNoHash }
          : {})
      }))
    });
  });

  router.post("/identity/link_email", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ error: "invalid-identity" });
      return;
    }

    // Check status call: no "lang" and no challenge response
    if (typeof body.lang !== "string" && !body.token) {
      res.json({ linked: Boolean(email && row.email === email) });
      return;
    }

    if (!body.token || !body.response) {
      if (email && row.email === email) {
        res.json({ linked: true });
        return;
      }
      const step = await handleChallengeStep(prisma, {
        purpose: "link_email",
        identityId: row.id,
        clientPublicKey: new Uint8Array(row.publicKey)
      });
      if (step.status === "challenge") {
        res.json({ linked: false, token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
        return;
      }
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "link_email",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status !== "verified") {
      res.json({ success: false, error: "invalid-token" });
      return;
    }

    await prisma.identity.update({
      where: { id: row.id },
      data: {
        email: email || null,
        emailHash: email ? hmacEmail(email) : null
      }
    });
    res.json({ success: true });
  });

  router.post("/identity/link_mobileno", async (req, res) => {
    const body = req.body ?? {};
    if (typeof body.verificationId === "string" && typeof body.code === "string") {
      const row = await prisma.identity.findFirst({
        where: { mobileVerifyId: body.verificationId }
      });
      if (!row || row.mobileVerifyCode !== body.code) {
        res.json({ success: false, error: "invalid-verification-code" });
        return;
      }
      const mobile = row.pendingMobileNo ?? "";
      await prisma.identity.update({
        where: { id: row.id },
        data: {
          mobileNo: mobile || null,
          mobileNoHash: mobile ? hmacMobileNo(mobile) : null,
          pendingMobileNo: null,
          mobileVerifyId: null,
          mobileVerifyCode: null
        }
      });
      res.json({ success: true });
      return;
    }

    const identityId = typeof body.identity === "string" ? body.identity : "";
    const mobileNo = typeof body.mobileNo === "string" ? body.mobileNo.trim() : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ error: "invalid-identity" });
      return;
    }

    if (!body.token || !body.response) {
      if (mobileNo && row.mobileNo === mobileNo) {
        res.json({ linked: true });
        return;
      }
      const step = await handleChallengeStep(prisma, {
        purpose: "link_mobileno",
        identityId: row.id,
        clientPublicKey: new Uint8Array(row.publicKey)
      });
      if (step.status === "challenge") {
        res.json({ linked: false, token: step.token, tokenRespKeyPub: step.tokenRespKeyPub });
        return;
      }
    }

    const step = await handleChallengeStep(prisma, {
      purpose: "link_mobileno",
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      tokenB64: body.token,
      responseB64: body.response
    });
    if (step.status !== "verified") {
      res.json({ success: false, error: "invalid-token" });
      return;
    }

    if (mobileNo === "") {
      await prisma.identity.update({
        where: { id: row.id },
        data: {
          mobileNo: null,
          mobileNoHash: null,
          pendingMobileNo: null,
          mobileVerifyId: null,
          mobileVerifyCode: null
        }
      });
      res.json({ success: true });
      return;
    }

    const verificationId = crypto.randomBytes(16).toString("hex");
    await prisma.identity.update({
      where: { id: row.id },
      data: {
        pendingMobileNo: mobileNo,
        mobileVerifyId: verificationId,
        mobileVerifyCode: "123456"
      }
    });
    res.json({ success: true, verificationId });
  });

  router.post("/identity/link_mobileno_call", async (req, res) => {
    const verificationId = typeof req.body?.verificationId === "string" ? req.body.verificationId : "";
    const row = verificationId
      ? await prisma.identity.findFirst({ where: { mobileVerifyId: verificationId } })
      : null;
    if (!row) {
      res.json({ success: false, error: "invalid-verification-id" });
      return;
    }
    res.json({ success: true });
  });
}
