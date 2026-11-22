import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import multer from "multer";
import type { PrismaClient } from "@prisma/client";
import { requireBlobAuth } from "../auth/workAuth.js";
import { createLogger } from "../logger.js";

const log = createLogger("Blob");
const BLOB_ID_RE = /^[0-9a-f]{32}$/i;

export function resolveSafeBlobPath(baseDir: string, relPath: string): string | null {
  const root = path.resolve(baseDir);
  const full = path.resolve(root, relPath);
  if (!full.startsWith(root + path.sep) && full !== root) {
    return null;
  }
  return full;
}

export function createBlobRouter(
  prisma: PrismaClient,
  defaultScope: "usual" | "mirror",
  blobStorageDir = "./data/blobs"
): express.Router {
  const router = express.Router();
  const resolvedRoot = path.resolve(blobStorageDir);
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 }
  });

  router.post("/upload", requireBlobAuth(prisma), upload.single("blob"), async (req, res) => {
    if (!req.file) {
      log.warn(`upload missing blob field scopeDefault=${defaultScope}`);
      res.status(400).send("Missing blob field");
      return;
    }

    const persist = req.query.persist === "1" || req.query.persist === "true";
    const queryScope = typeof req.query.scope === "string" ? req.query.scope : undefined;
    const scope =
      defaultScope === "usual"
        ? "usual"
        : queryScope === "local" || queryScope === "public"
          ? queryScope
          : "local";
    const deviceGroupId =
      typeof req.query.deviceGroupId === "string" ? req.query.deviceGroupId : null;

    const id = crypto.randomBytes(16).toString("hex");
    const relPath = path.join(id.slice(0, 2), id);
    const fullPath = resolveSafeBlobPath(resolvedRoot, relPath);
    if (!fullPath) {
      res.status(500).send("Invalid storage path");
      return;
    }

    await fs.promises.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.promises.writeFile(fullPath, req.file.buffer);

    try {
      await prisma.blobItem.create({
        data: {
          id,
          scope,
          deviceGroupId,
          persist,
          data: new Uint8Array(0),
          storagePath: relPath,
          size: req.file.buffer.byteLength
        }
      });
    } catch (err) {
      await fs.promises.unlink(fullPath).catch(() => undefined);
      throw err;
    }

    log.info(
      `upload id=${id} scope=${scope} bytes=${req.file.buffer.byteLength} persist=${persist} disk=${relPath}`
    );
    res.type("text/plain; charset=utf-8").status(200).send(id);
  });

  const handleDownload = async (req: express.Request, res: express.Response): Promise<void> => {
    const blobId = req.params.blobId.toLowerCase();
    if (!BLOB_ID_RE.test(blobId)) {
      log.warn(`download invalid id=${req.params.blobId}`);
      res.status(400).send("Invalid blob id");
      return;
    }
    const row = await prisma.blobItem.findUnique({ where: { id: blobId } });
    if (!row) {
      log.warn(`download not found id=${blobId}`);
      res.status(404).send("Not found");
      return;
    }

    let buf: Buffer;
    if (row.storagePath) {
      const fullPath = resolveSafeBlobPath(resolvedRoot, row.storagePath);
      if (!fullPath) {
        res.status(404).send("Not found");
        return;
      }
      try {
        buf = await fs.promises.readFile(fullPath);
      } catch {
        log.warn(`download missing disk file id=${blobId} path=${row.storagePath}`);
        res.status(404).send("Not found");
        return;
      }
    } else {
      buf = Buffer.from(row.data);
    }

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", String(buf.byteLength));
    res.status(200).send(buf);
  };

  const handleDone = async (req: express.Request, res: express.Response): Promise<void> => {
    const blobId = req.params.blobId.toLowerCase();
    if (!BLOB_ID_RE.test(blobId)) {
      log.warn(`done invalid id=${req.params.blobId}`);
      res.status(400).send("Invalid blob id");
      return;
    }
    const row = await prisma.blobItem.findUnique({ where: { id: blobId } });
    if (!row) {
      log.warn(`done not found id=${blobId}`);
      res.status(404).send("Not found");
      return;
    }
    if (!row.persist && defaultScope === "usual" && row.scope === "usual") {
      await prisma.blobItem.delete({ where: { id: blobId } }).catch(() => undefined);
      if (row.storagePath) {
        const fullPath = resolveSafeBlobPath(resolvedRoot, row.storagePath);
        if (fullPath) {
          await fs.promises.unlink(fullPath).catch(() => undefined);
        }
      }
    } else {
      await prisma.blobItem.update({
        where: { id: blobId },
        data: { doneCount: { increment: 1 } }
      });
    }
    res.status(204).end();
  };

  router.get("/:blobId", handleDownload);
  router.get("/:prefix/:blobId", handleDownload);
  router.post("/:blobId/done", handleDone);
  router.post("/:prefix/:blobId/done", handleDone);

  return router;
}
