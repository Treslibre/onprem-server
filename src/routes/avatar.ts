import express from "express";
import type { PrismaClient } from "@prisma/client";
import { requireWorkBasicAuth } from "../auth/workAuth.js";
import { sha256Hex } from "../crypto/primitives.js";

export function createAvatarRouter(prisma: PrismaClient): express.Router {
  const router = express.Router();

  router.get("/:identity", async (req, res) => {
    const row = await prisma.avatar.findUnique({ where: { identityId: req.params.identity } });
    if (!row) {
      res.status(404).send("Not found");
      return;
    }
    const buf = Buffer.from(row.data);
    const etag = `"${sha256Hex(buf)}"`;
    if (req.header("if-none-match") === etag) {
      res.status(304).end();
      return;
    }
    res.setHeader("Content-Type", row.contentType);
    res.setHeader("Content-Length", String(buf.byteLength));
    res.setHeader("Cache-Control", "public, max-age=300");
    res.setHeader("ETag", etag);
    res.setHeader("Last-Modified", row.updatedAt.toUTCString());
    res.status(200).send(buf);
  });

  router.put(
    "/:identity",
    requireWorkBasicAuth(prisma),
    express.raw({ type: "*/*", limit: "2mb" }),
    async (req, res) => {
      const identity = await prisma.identity.findUnique({ where: { id: req.params.identity } });
      if (!identity || identity.state === 0) {
        res.status(404).send("Identity not found");
        return;
      }
      const data = new Uint8Array(Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0));
      const contentType = req.header("content-type") || "image/jpeg";
      await prisma.avatar.upsert({
        where: { identityId: identity.id },
        create: { identityId: identity.id, contentType, data },
        update: { contentType, data }
      });
      res.status(204).end();
    }
  );

  router.delete("/:identity", requireWorkBasicAuth(prisma), async (req, res) => {
    await prisma.avatar.delete({ where: { identityId: req.params.identity } }).catch(() => undefined);
    res.status(204).end();
  });

  return router;
}
