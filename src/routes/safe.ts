import express from "express";
import type { PrismaClient } from "@prisma/client";
import { requireSafeAuth } from "../auth/workAuth.js";
import { sha256Hex } from "../crypto/primitives.js";

const BACKUP_ID_RE = /^[0-9a-f]{64}$/i;
const MAX_BACKUP_BYTES = 5 * 1024 * 1024;
const RETENTION_DAYS = 180;

export function createSafeRouter(prisma: PrismaClient): express.Router {
  const router = express.Router();
  router.use(requireSafeAuth(prisma));

  const handleConfig = (_req: express.Request, res: express.Response): void => {
    res.json({
      maxBackupBytes: MAX_BACKUP_BYTES,
      retentionDays: RETENTION_DAYS
    });
  };

  const handleGetBackup = async (req: express.Request, res: express.Response): Promise<void> => {
    const backupId = req.params.backupId.toLowerCase();
    if (!BACKUP_ID_RE.test(backupId)) {
      res.status(400).send("Invalid backupId");
      return;
    }
    const row = await prisma.safeBackup.findUnique({ where: { backupId } });
    if (!row) {
      res.status(404).send("Not found");
      return;
    }
    const buf = Buffer.from(row.data);
    const etag = `"${sha256Hex(buf)}"`;
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", String(buf.byteLength));
    res.setHeader("Last-Modified", row.updatedAt.toUTCString());
    res.setHeader("ETag", etag);
    if (req.header("if-none-match") === etag) {
      res.status(304).end();
      return;
    }
    if (req.method === "HEAD") {
      res.status(200).end();
      return;
    }
    res.status(200).send(buf);
  };

  const handlePutBackup = async (req: express.Request, res: express.Response): Promise<void> => {
    const backupId = req.params.backupId.toLowerCase();
    if (!BACKUP_ID_RE.test(backupId)) {
      res.status(400).send("Invalid backupId");
      return;
    }
    const data = new Uint8Array(Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0));
    if (data.byteLength > MAX_BACKUP_BYTES) {
      res.status(413).send("Backup too large");
      return;
    }
    await prisma.safeBackup.upsert({
      where: { backupId },
      create: { backupId, data },
      update: { data }
    });
    res.status(200).end();
  };

  const handleDeleteBackup = async (req: express.Request, res: express.Response): Promise<void> => {
    const backupId = req.params.backupId.toLowerCase();
    if (!BACKUP_ID_RE.test(backupId)) {
      res.status(400).send("Invalid backupId");
      return;
    }
    await prisma.safeBackup.delete({ where: { backupId } }).catch(() => undefined);
    res.status(200).end();
  };

  router.get("/config", handleConfig);
  router.get("/:prefix/config", handleConfig);
  router.get("/backups/:backupId", handleGetBackup);
  router.get("/:prefix/backups/:backupId", handleGetBackup);
  router.put(
    "/backups/:backupId",
    express.raw({ type: "*/*", limit: MAX_BACKUP_BYTES }),
    handlePutBackup
  );
  router.put(
    "/:prefix/backups/:backupId",
    express.raw({ type: "*/*", limit: MAX_BACKUP_BYTES }),
    handlePutBackup
  );
  router.delete("/backups/:backupId", handleDeleteBackup);
  router.delete("/:prefix/backups/:backupId", handleDeleteBackup);

  return router;
}
