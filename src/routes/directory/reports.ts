import type express from "express";
import { type DirectoryRouterDeps, handleChallengeStep } from "./shared.js";

export function registerReportRoutes(router: express.Router, deps: DirectoryRouterDeps): void {
  const { prisma } = deps;

  router.post("/identity/report_junk", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }
    const step = await handleChallengeStep(prisma, {
      purpose: "report_junk",
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

    await prisma.spamReport.create({
      data: {
        kind: "contact",
        reporterIdentity: row.id,
        payloadJson: JSON.stringify(body)
      }
    });
    res.json({ success: true });
  });

  router.post("/identity/report_group", async (req, res) => {
    const body = req.body ?? {};
    const identityId =
      typeof body.reporter_identity === "string"
        ? body.reporter_identity
        : typeof body.identity === "string"
          ? body.identity
          : "";
    const row = identityId ? await prisma.identity.findUnique({ where: { id: identityId } }) : null;
    if (!row || row.state === 0) {
      res.json({ success: false, error: "invalid-identity" });
      return;
    }
    const step = await handleChallengeStep(prisma, {
      purpose: "report_group",
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

    await prisma.spamReport.create({
      data: {
        kind: "group",
        reporterIdentity: row.id,
        payloadJson: JSON.stringify(body)
      }
    });
    res.json({ success: true });
  });
}
