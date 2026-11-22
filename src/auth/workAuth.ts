import type { PrismaClient, WorkAccount } from "@prisma/client";
import type { NextFunction, Request, Response } from "express";
import { verifyPassword } from "../crypto/primitives.js";

export interface AuthenticatedRequest extends Request {
  workAccount?: WorkAccount;
  blobToken?: { token: string; identityId: string | null };
}

export function parseBasicAuth(header?: string): { username: string; password: string } | null {
  if (!header) return null;
  const match = /^Basic\s+(.+)$/i.exec(header.trim());
  if (!match) return null;
  const decoded = Buffer.from(match[1], "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  if (idx === -1) return null;
  return {
    username: decoded.slice(0, idx),
    password: decoded.slice(idx + 1)
  };
}

export async function verifyWorkCredentials(
  prisma: PrismaClient,
  username: string,
  password: string
): Promise<WorkAccount | null> {
  const account = await prisma.workAccount.findUnique({ where: { username } });
  if (!account || !account.enabled) return null;
  if (!verifyPassword(password, account.passwordHash)) return null;
  return account;
}

export function requireWorkBasicAuth(prisma: PrismaClient) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const creds = parseBasicAuth(req.header("authorization"));
    if (!creds) {
      res.setHeader("WWW-Authenticate", 'Basic realm="Threema OnPrem"');
      res.status(401).json({ success: false, error: "Unauthorized" });
      return;
    }
    const account = await verifyWorkCredentials(prisma, creds.username, creds.password);
    if (!account) {
      res.setHeader("WWW-Authenticate", 'Basic realm="Threema OnPrem"');
      res.status(401).json({ success: false, error: "Invalid credentials" });
      return;
    }
    req.workAccount = account;
    next();
  };
}

export function requireBlobAuth(prisma: PrismaClient) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const auth = req.header("authorization")?.trim();
    if (!auth) {
      res.status(401).send("Unauthorized");
      return;
    }

    let kind: "blob" | "legacy" | null = null;
    let token: string | null = null;
    if (auth.startsWith("ThreemaBlobToken ")) {
      kind = "blob";
      token = auth.slice("ThreemaBlobToken ".length).trim();
    } else if (auth.startsWith("Token ")) {
      kind = "legacy";
      token = auth.slice("Token ".length).trim();
    }

    if (!kind || !token) {
      res.status(401).send("Unauthorized");
      return;
    }

    const row = await prisma.authToken.findUnique({ where: { token } });
    if (!row || row.kind !== kind || row.expiresAt.getTime() <= Date.now()) {
      res.status(401).send("Invalid or expired token");
      return;
    }
    req.blobToken = { token: row.token, identityId: row.identityId };
    next();
  };
}

export function requireSafeAuth(prisma: PrismaClient) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const auth = req.header("authorization")?.trim();
    if (!auth) {
      res.status(401).send("Unauthorized");
      return;
    }

    if (auth.startsWith("Token ")) {
      const token = auth.slice("Token ".length).trim();
      const row = await prisma.authToken.findUnique({ where: { token } });
      if (row && row.kind === "legacy" && row.expiresAt.getTime() > Date.now()) {
        next();
        return;
      }
      res.status(401).send("Invalid token");
      return;
    }

    const basic = parseBasicAuth(auth);
    if (basic) {
      const account = await verifyWorkCredentials(prisma, basic.username, basic.password);
      if (account) {
        req.workAccount = account;
        next();
        return;
      }
    }

    res.status(401).send("Unauthorized");
  };
}
