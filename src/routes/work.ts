import crypto from "node:crypto";
import express from "express";
import protobuf from "protobufjs";
import type { Identity, PrismaClient, WorkAccount } from "@prisma/client";
import { verifyWorkCredentials } from "../auth/workAuth.js";
import {
  computeWorkChallengeResponse,
  constantTimeEqual,
  deriveSharedSecret,
  generateCurve25519KeyPair,
  sha256Hex
} from "../crypto/primitives.js";

const WORK_CHALLENGE_TTL_MS = 2 * 60 * 1000;

function formatWorkContact(identity: Identity) {
  const firstName = identity.firstName?.trim();
  const lastName = identity.lastName?.trim();
  const nickname = identity.publicNickname?.trim();
  const first = firstName || (!lastName ? nickname : undefined) || undefined;
  const last = lastName || undefined;
  const jobTitle = identity.jobTitle?.trim() || undefined;
  const department = identity.department?.trim() || undefined;
  const availability = identity.availability?.trim() || undefined;

  return {
    id: identity.id,
    pk: Buffer.from(identity.publicKey).toString("base64"),
    ...(first ? { first } : {}),
    ...(last ? { last } : {}),
    ...(jobTitle ? { jobTitle } : {}),
    ...(department ? { department } : {}),
    ...(availability ? { availability } : {})
  };
}

/**
 * Decodes protobuf `directory.WorkProperties` and returns the base64-encoded
 * `d2d_sync.WorkAvailabilityStatus` (or `null` when reset to `NONE`).
 */
function parseWorkPropertiesAvailability(raw: Buffer): string | null {
  let availabilityBytes: Uint8Array | null = null;
  const r = protobuf.Reader.create(raw);
  while (r.pos < r.len) {
    const tag = r.uint32();
    const field = tag >>> 3;
    const wireType = tag & 7;
    if (field === 1 && wireType === 2) {
      availabilityBytes = new Uint8Array(r.bytes());
    } else {
      r.skipType(wireType);
    }
  }
  if (!availabilityBytes || availabilityBytes.byteLength === 0) {
    return null;
  }

  let category = 0;
  const inner = protobuf.Reader.create(availabilityBytes);
  while (inner.pos < inner.len) {
    const tag = inner.uint32();
    const field = tag >>> 3;
    const wireType = tag & 7;
    if (field === 1 && wireType === 0) {
      category = inner.int32();
    } else {
      inner.skipType(wireType);
    }
  }

  if (category === 0) {
    return null;
  }
  return Buffer.from(availabilityBytes).toString("base64");
}

async function handleWorkChallengeStep(
  prisma: PrismaClient,
  opts: {
    purpose: string;
    identityId: string;
    clientPublicKey: Uint8Array;
    challengeB64?: unknown;
    responseB64?: unknown;
  }
): Promise<
  | { status: "challenge"; challengePublicKey: string; challenge: string }
  | { status: "verified" }
  | { status: "failed"; code: "challenge-expired" | "invalid-challenge-response" }
> {
  const challengeB64 = typeof opts.challengeB64 === "string" ? opts.challengeB64 : undefined;
  const responseB64 = typeof opts.responseB64 === "string" ? opts.responseB64 : undefined;

  if (!challengeB64 || !responseB64) {
    const challenge = crypto.randomBytes(32).toString("base64");
    const eph = generateCurve25519KeyPair();
    await prisma.challenge.create({
      data: {
        token: challenge,
        purpose: opts.purpose,
        identityId: opts.identityId,
        clientPublicKey: Buffer.from(opts.clientPublicKey),
        serverEphemeralPriv: Buffer.from(eph.secretKey),
        expiresAt: new Date(Date.now() + WORK_CHALLENGE_TTL_MS)
      }
    });
    return {
      status: "challenge",
      challengePublicKey: Buffer.from(eph.publicKey).toString("base64"),
      challenge
    };
  }

  const row = await prisma.challenge.findUnique({ where: { token: challengeB64 } });
  if (!row) {
    return { status: "failed", code: "invalid-challenge-response" };
  }
  await prisma.challenge.delete({ where: { token: challengeB64 } }).catch(() => undefined);

  if (row.expiresAt.getTime() <= Date.now()) {
    return { status: "failed", code: "challenge-expired" };
  }
  if (row.purpose !== opts.purpose || row.identityId !== opts.identityId) {
    return { status: "failed", code: "invalid-challenge-response" };
  }

  const shared = deriveSharedSecret(opts.clientPublicKey, new Uint8Array(row.serverEphemeralPriv));
  const expected = computeWorkChallengeResponse(
    shared,
    new Uint8Array(Buffer.from(challengeB64, "base64"))
  );
  const actual = new Uint8Array(Buffer.from(responseB64, "base64"));

  if (!constantTimeEqual(expected, actual)) {
    return { status: "failed", code: "invalid-challenge-response" };
  }

  return { status: "verified" };
}

export function createWorkRouter(
  prisma: PrismaClient,
  getHttpOrigin?: () => string
): express.Router {
  const router = express.Router();
  router.use(
    express.json({
      limit: "2mb",
      type: (req) => {
        const ct = req.headers["content-type"]?.toLowerCase();
        return !ct || ct.includes("json") || ct.startsWith("text/plain");
      }
    })
  );

  const authenticateBody = async (
    req: express.Request,
    res: express.Response
  ): Promise<WorkAccount | null> => {
    const username = typeof req.body?.username === "string" ? req.body.username : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!username || !password) {
      res.status(401).json({ code: "invalid-credentials", error: "Missing credentials" });
      return null;
    }
    const account = await verifyWorkCredentials(prisma, username, password);
    if (!account) {
      res.status(401).json({ code: "invalid-credentials", error: "Invalid credentials" });
      return null;
    }
    return account;
  };

  const loadEnabledIdentities = async (requestedIds?: string[]) => {
    const filterIds = requestedIds && requestedIds.length > 0 ? { id: { in: requestedIds } } : {};
    return prisma.identity.findMany({
      where: {
        state: 1,
        workEnabled: true,
        OR: [{ workAccountId: null }, { workAccount: { enabled: true } }],
        ...filterIds
      }
    });
  };

  const resolveRequestHttpOrigin = (req: express.Request): string => {
    const proto = req.header("x-forwarded-proto")?.split(",")[0]?.trim() || req.protocol;
    const host = req.header("x-forwarded-host")?.split(",")[0]?.trim() || req.header("host")?.trim();
    if (host) return `${proto}://${host}`.replace(/\/+$/, "");
    return getHttpOrigin ? getHttpOrigin().replace(/\/+$/, "") : "";
  };

  // Self-hosted org logo endpoint used when uploaded via /admin/mdm/logo/:variant
  router.get("/logo/:variant", async (req, res) => {
    const variant = req.params.variant === "dark" ? "dark" : req.params.variant === "light" ? "light" : null;
    if (!variant) {
      res.status(404).send("Not found");
      return;
    }
    const mdm = await prisma.workMdmConfig.findUnique({ where: { id: "default" } });
    const data = variant === "dark" ? mdm?.logoDarkData : mdm?.logoLightData;
    const contentType =
      (variant === "dark" ? mdm?.logoDarkContentType : mdm?.logoLightContentType) || "image/png";
    if (!data || data.byteLength === 0) {
      res.status(404).send("Not found");
      return;
    }
    const buf = Buffer.from(data);
    const etag = `"${sha256Hex(buf)}"`;
    if (req.header("if-none-match") === etag) {
      res.status(304).end();
      return;
    }
    res.setHeader("Content-Type", contentType);
    res.setHeader("Content-Length", String(buf.byteLength));
    res.setHeader("Cache-Control", "public, max-age=300");
    res.setHeader("ETag", etag);
    res.status(200).send(buf);
  });

  router.post("/fetch2", async (req, res) => {
    const account = await authenticateBody(req, res);
    if (!account) return;

    const requestedIds = Array.isArray(req.body?.contacts)
      ? req.body.contacts.filter((c: unknown): c is string => typeof c === "string")
      : undefined;

    const [mdm, identities] = await Promise.all([
      prisma.workMdmConfig.findUnique({ where: { id: "default" } }),
      loadEnabledIdentities(requestedIds)
    ]);

    const contacts = identities.map(formatWorkContact);

    let params: Record<string, string | boolean | number> = {};
    let categories: Record<string, string> = {};
    try {
      params = mdm ? (JSON.parse(mdm.paramsJson) as Record<string, string | boolean | number>) : {};
    } catch {
      params = {};
    }
    try {
      categories = mdm ? (JSON.parse(mdm.categoriesJson) as Record<string, string>) : {};
    } catch {
      categories = {};
    }

    const baseOrigin = resolveRequestHttpOrigin(req);
    const logoLight =
      mdm?.logoLight ||
      (mdm?.logoLightData && mdm.logoLightData.byteLength > 0 && baseOrigin
        ? `${baseOrigin}/work/logo/light`
        : undefined);
    const logoDark =
      mdm?.logoDark ||
      (mdm?.logoDarkData && mdm.logoDarkData.byteLength > 0 && baseOrigin
        ? `${baseOrigin}/work/logo/dark`
        : undefined);

    res.json({
      time: Date.now(),
      checkInterval: mdm?.checkInterval ?? 86400,
      contacts,
      directory: mdm?.directoryEnabled
        ? { enabled: true as const, cat: categories }
        : { enabled: false as const },
      logo: {
        ...(logoLight ? { light: logoLight } : {}),
        ...(logoDark ? { dark: logoDark } : {})
      },
      mdm: {
        override: mdm?.override ?? false,
        params
      },
      org: {
        ...(mdm?.orgName ? { name: mdm.orgName } : {})
      },
      ...(mdm?.support ? { support: mdm.support } : {})
    });
  });

  router.post("/identities", async (req, res) => {
    const account = await authenticateBody(req, res);
    if (!account) return;

    const requestedIds = Array.isArray(req.body?.contacts)
      ? req.body.contacts.filter((c: unknown): c is string => typeof c === "string")
      : [];

    const identities = requestedIds.length > 0 ? await loadEnabledIdentities(requestedIds) : [];
    const contacts = identities.map(formatWorkContact);

    // Must not include unknown top-level keys (e.g. `time`) due to Desktop strict Valita schema
    res.json({
      contacts
    });
  });

  router.post("/directory", async (req, res) => {
    const account = await authenticateBody(req, res);
    if (!account) return;

    const requesterId = typeof req.body?.identity === "string" ? req.body.identity.trim() : "";
    const rawQuery = typeof req.body?.query === "string" ? req.body.query.trim() : "";
    const query = rawQuery === "*" ? "" : rawQuery.toLowerCase();
    const categoriesFilter: string[] = Array.isArray(req.body?.categories)
      ? req.body.categories.filter((c: unknown): c is string => typeof c === "string")
      : [];
    const sortAsc = req.body?.sort?.asc !== false;
    const sortBy = req.body?.sort?.by === "lastName" ? "lastName" : "firstName";
    const page = typeof req.body?.page === "number" && req.body.page >= 0 ? req.body.page : 0;
    const pageSize = 50;

    const [mdm, allIdentities] = await Promise.all([
      prisma.workMdmConfig.findUnique({ where: { id: "default" } }),
      loadEnabledIdentities()
    ]);

    const filtered = allIdentities.filter((ident) => {
      if (requesterId && ident.id === requesterId) return false;
      if (categoriesFilter.length > 0) {
        if (!ident.category || !categoriesFilter.includes(ident.category)) return false;
      }
      if (query) {
        const haystack = [
          ident.firstName,
          ident.lastName,
          ident.publicNickname,
          ident.jobTitle,
          ident.department,
          ident.csi,
          ident.id
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });

    filtered.sort((a, b) => {
      const av =
        (sortBy === "lastName" ? a.lastName : a.firstName ?? a.publicNickname ?? a.id) ?? "";
      const bv =
        (sortBy === "lastName" ? b.lastName : b.firstName ?? b.publicNickname ?? b.id) ?? "";
      const cmp = av.localeCompare(bv);
      return sortAsc ? cmp : -cmp;
    });

    const total = filtered.length;
    const slice = filtered.slice(page * pageSize, (page + 1) * pageSize);
    const orgName = mdm?.orgName ?? null;

    const contacts = slice.map((ident) => ({
      ...formatWorkContact(ident),
      ...(ident.csi ? { csi: ident.csi } : {}),
      org: { name: orgName },
      cat: ident.category ? [ident.category] : []
    }));

    const hasNext = (page + 1) * pageSize < total;
    const hasPrev = page > 0;

    res.json({
      time: Date.now(),
      contacts,
      paging: {
        size: contacts.length,
        total,
        ...(hasNext ? { next: page + 1 } : {}),
        ...(hasPrev ? { prev: page - 1 } : {})
      }
    });
  });

  // Work Properties v1 (availability status etc.) per directory.openapi.yml
  router.post("/api-client/v1/user-properties", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity.trim() : "";
    const propsB64 = typeof body.properties === "string" ? body.properties : "";
    if (!identityId || !propsB64) {
      res.status(400).json({ error: "Missing identity or properties" });
      return;
    }

    const propsBuf = Buffer.from(propsB64, "base64");
    let availability: string | null;
    try {
      availability = parseWorkPropertiesAvailability(propsBuf);
    } catch {
      res.status(400).json({ error: "Invalid WorkProperties protobuf" });
      return;
    }

    const account = await authenticateBody(req, res);
    if (!account) return;

    const row = await prisma.identity.findUnique({ where: { id: identityId } });
    if (!row || row.state === 0) {
      res.status(401).json({ code: "invalid-credentials" });
      return;
    }

    const step = await handleWorkChallengeStep(prisma, {
      purpose: `wdir:props:${sha256Hex(propsBuf)}`,
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      challengeB64: body.challenge,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.status(200).json({
        challengePublicKey: step.challengePublicKey,
        challenge: step.challenge
      });
      return;
    }
    if (step.status === "failed") {
      res.status(401).json({ code: step.code });
      return;
    }

    await prisma.identity.update({
      where: { id: row.id },
      data: { availability }
    });
    res.status(204).end();
  });

  // Remote Secret PUT/DELETE/POST per directory.openapi.yml
  router.put("/api-client/v1/remote-secret", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity.trim() : "";
    const secretB64 = typeof body.secret === "string" ? body.secret : "";
    const secretBuf = Buffer.from(secretB64, "base64");
    if (!identityId || secretBuf.byteLength !== 32) {
      res.status(400).json({ error: "Invalid identity or 32-byte base64 secret" });
      return;
    }

    const account = await authenticateBody(req, res);
    if (!account) return;

    const row = await prisma.identity.findUnique({ where: { id: identityId } });
    if (!row || row.state === 0) {
      res.status(401).json({ code: "invalid-credentials" });
      return;
    }

    const step = await handleWorkChallengeStep(prisma, {
      purpose: `wdir:rs_create:${sha256Hex(secretBuf)}`,
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      challengeB64: body.challenge,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.status(200).json({
        challengePublicKey: step.challengePublicKey,
        challenge: step.challenge
      });
      return;
    }
    if (step.status === "failed") {
      res.status(401).json({ code: step.code });
      return;
    }

    const rawAuthToken = crypto.randomBytes(32);
    const authTokenHash = sha256Hex(rawAuthToken);
    await prisma.remoteSecret.create({
      data: {
        authTokenHash,
        identityId: row.id,
        secret: new Uint8Array(secretBuf),
        blocked: false
      }
    });

    res.status(200).json({
      secretAuthenticationToken: rawAuthToken.toString("base64")
    });
  });

  router.delete("/api-client/v1/remote-secret", async (req, res) => {
    const body = req.body ?? {};
    const identityId = typeof body.identity === "string" ? body.identity.trim() : "";
    const tokB64 =
      typeof body.secretAuthenticationToken === "string" ? body.secretAuthenticationToken : "";
    const tokBuf = Buffer.from(tokB64, "base64");
    if (!identityId || tokBuf.byteLength !== 32) {
      res.status(400).json({ error: "Invalid identity or secretAuthenticationToken" });
      return;
    }

    const account = await authenticateBody(req, res);
    if (!account) return;

    const row = await prisma.identity.findUnique({ where: { id: identityId } });
    if (!row || row.state === 0) {
      res.status(401).json({ code: "invalid-credentials" });
      return;
    }

    const authTokenHash = sha256Hex(tokBuf);
    const step = await handleWorkChallengeStep(prisma, {
      purpose: `wdir:rs_delete:${authTokenHash}`,
      identityId: row.id,
      clientPublicKey: new Uint8Array(row.publicKey),
      challengeB64: body.challenge,
      responseB64: body.response
    });
    if (step.status === "challenge") {
      res.status(200).json({
        challengePublicKey: step.challengePublicKey,
        challenge: step.challenge
      });
      return;
    }
    if (step.status === "failed") {
      res.status(401).json({ code: step.code });
      return;
    }

    await prisma.remoteSecret.deleteMany({
      where: { authTokenHash, identityId: row.id }
    });
    res.status(204).end();
  });

  router.post("/api-client/v1/remote-secret", async (req, res) => {
    const body = req.body ?? {};
    const tokB64 =
      typeof body.secretAuthenticationToken === "string" ? body.secretAuthenticationToken : "";
    const tokBuf = Buffer.from(tokB64, "base64");
    if (tokBuf.byteLength !== 32) {
      res.status(400).json({ error: "Invalid secretAuthenticationToken" });
      return;
    }

    const authTokenHash = sha256Hex(tokBuf);
    const entry = await prisma.remoteSecret.findUnique({
      where: { authTokenHash },
      include: { identity: { select: { state: true } } }
    });
    if (!entry) {
      res.status(404).end();
      return;
    }
    if (entry.blocked || entry.identity.state !== 1) {
      res.status(403).end();
      return;
    }

    res.status(200).json({
      secret: Buffer.from(entry.secret).toString("base64"),
      checkIntervalS: 3600,
      nMissedChecksMax: 3
    });
  });

  return router;
}
