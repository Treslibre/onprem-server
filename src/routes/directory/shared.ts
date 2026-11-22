import crypto from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "../../config.js";
import type { CspRouter } from "../../csp/session.js";
import {
  computeDirectoryChallengeResponse,
  constantTimeEqual,
  deriveSharedSecret,
  generateCurve25519KeyPair
} from "../../crypto/primitives.js";

const ID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CHALLENGE_TTL_MS = 2 * 60 * 1000;

export interface DirectoryTurnConfig {
  host: string;
  port: number;
  secret: string;
}

export interface DirectoryRouterDeps {
  prisma: PrismaClient;
  config: ServerConfig;
  getHttpOrigin: () => string;
  getTurnConfig?: () => DirectoryTurnConfig;
  cspRouter?: CspRouter;
}

export function generateThreemaId(): string {
  const bytes = crypto.randomBytes(8);
  let id = "";
  for (let i = 0; i < 8; i++) {
    id += ID_ALPHABET[bytes[i] % ID_ALPHABET.length];
  }
  return id;
}

export function formatSimpleDateOffsetUtc(d: Date): string {
  const iso = d.toISOString(); // YYYY-MM-DDTHH:mm:ss.sssZ
  return `${iso.slice(0, 19)}+0000`;
}

/**
 * Maps internal DB identity state (`1 = active, 2 = inactive, 0 = revoked`)
 * to protocol wire `ActivityState` (`0 = ACTIVE, 1 = INACTIVE, 2 = INVALID`)
 * used by Android and Desktop clients.
 */
export function toWireActivityState(dbState: number | undefined): 0 | 1 | 2 {
  if (dbState === 1) return 0;
  if (dbState === 2) return 1;
  return 2;
}

export function formatIdentityRow(row: {
  id: string;
  publicKey: Uint8Array;
  featureMask: bigint;
  state: number;
  type: number;
}) {
  return {
    identity: row.id,
    publicKey: Buffer.from(row.publicKey).toString("base64"),
    featureLevel: 3,
    featureMask: Number(row.featureMask),
    state: toWireActivityState(row.state),
    type: row.type
  };
}

export async function handleChallengeStep(
  prisma: PrismaClient,
  opts: {
    purpose: string;
    identityId?: string;
    clientPublicKey?: Uint8Array;
    tokenB64?: unknown;
    responseB64?: unknown;
  }
): Promise<
  | { status: "challenge"; token: string; tokenRespKeyPub: string }
  | { status: "verified" }
  | { status: "failed"; error: string }
> {
  const tokenB64 = typeof opts.tokenB64 === "string" ? opts.tokenB64 : undefined;
  const responseB64 = typeof opts.responseB64 === "string" ? opts.responseB64 : undefined;

  if (!tokenB64 || !responseB64) {
    const tokenBytes = crypto.randomBytes(32);
    const token = tokenBytes.toString("base64");
    const eph = generateCurve25519KeyPair();
    await prisma.challenge.create({
      data: {
        token,
        purpose: opts.purpose,
        identityId: opts.identityId ?? null,
        clientPublicKey: opts.clientPublicKey ? Buffer.from(opts.clientPublicKey) : null,
        serverEphemeralPriv: Buffer.from(eph.secretKey),
        expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS)
      }
    });
    return {
      status: "challenge",
      token,
      tokenRespKeyPub: Buffer.from(eph.publicKey).toString("base64")
    };
  }

  const row = await prisma.challenge.findUnique({ where: { token: tokenB64 } });
  if (!row) {
    return { status: "failed", error: "invalid-token" };
  }
  await prisma.challenge.delete({ where: { token: tokenB64 } }).catch(() => undefined);

  if (row.expiresAt.getTime() <= Date.now()) {
    return { status: "failed", error: "expired-token" };
  }
  if (row.purpose !== opts.purpose) {
    return { status: "failed", error: "purpose-mismatch" };
  }
  if (opts.identityId && row.identityId !== opts.identityId) {
    return { status: "failed", error: "identity-mismatch" };
  }

  let pubKey = opts.clientPublicKey;
  if (!pubKey && row.clientPublicKey) {
    pubKey = new Uint8Array(row.clientPublicKey);
  }
  if (!pubKey || pubKey.byteLength !== 32) {
    return { status: "failed", error: "missing-public-key" };
  }

  const shared = deriveSharedSecret(pubKey, new Uint8Array(row.serverEphemeralPriv));
  const expected = computeDirectoryChallengeResponse(
    shared,
    new Uint8Array(Buffer.from(tokenB64, "base64"))
  );
  const actual = new Uint8Array(Buffer.from(responseB64, "base64"));

  if (!constantTimeEqual(expected, actual)) {
    return { status: "failed", error: "invalid-response" };
  }

  return { status: "verified" };
}

export async function revokeIdentityAndKick(
  prisma: PrismaClient,
  identityId: string,
  cspRouter?: CspRouter
): Promise<void> {
  await prisma.$transaction([
    prisma.identity.update({
      where: { id: identityId },
      data: {
        state: 0,
        workEnabled: false,
        email: null,
        emailHash: null,
        mobileNo: null,
        mobileNoHash: null,
        pendingMobileNo: null,
        mobileVerifyId: null,
        mobileVerifyCode: null,
        deviceCookie: null,
        deviceCookieChanged: false
      }
    }),
    prisma.pushToken.deleteMany({ where: { identityId } }),
    prisma.remoteSecret.deleteMany({ where: { identityId } })
  ]);

  cspRouter?.kickIdentity(identityId, "Identity revoked", false);
}
