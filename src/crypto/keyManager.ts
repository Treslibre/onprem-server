import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "../config.js";
import {
  constantTimeEqual,
  deriveCurve25519PublicKey,
  deriveEd25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  generateCurve25519KeyPair,
  generateEd25519KeyPair
} from "./primitives.js";

export class KeyManager {
  private oppfPub!: Uint8Array;
  private oppfPriv!: Uint8Array;
  private cspPub!: Uint8Array;
  private cspPriv!: Uint8Array;
  private initialized = false;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly config: ServerConfig
  ) {}

  async init(): Promise<void> {
    if (this.initialized) return;

    // 1. OPPF Ed25519 signing keypair
    if (this.config.oppfEd25519PrivateKeyB64) {
      const raw = Buffer.from(this.config.oppfEd25519PrivateKeyB64, "base64");
      const seed = raw.byteLength === 64 ? raw.subarray(0, 32) : raw;
      const pub = deriveEd25519PublicKey(seed);
      this.oppfPriv = new Uint8Array(seed);
      this.oppfPub = pub;
      await this.prisma.serverKey.upsert({
        where: { name: "oppf_ed25519" },
        create: { name: "oppf_ed25519", publicKey: Buffer.from(pub), privateKey: Buffer.from(seed) },
        update: { publicKey: Buffer.from(pub), privateKey: Buffer.from(seed) }
      });
    } else {
      const existing = await this.prisma.serverKey.findUnique({ where: { name: "oppf_ed25519" } });
      if (existing) {
        this.oppfPub = new Uint8Array(existing.publicKey);
        this.oppfPriv = new Uint8Array(existing.privateKey);
      } else {
        const kp = generateEd25519KeyPair();
        this.oppfPub = kp.publicKey;
        this.oppfPriv = kp.privateKey;
        await this.prisma.serverKey.create({
          data: {
            name: "oppf_ed25519",
            publicKey: Buffer.from(kp.publicKey),
            privateKey: Buffer.from(kp.privateKey)
          }
        });
      }
    }

    // 2. CSP Curve25519 server identity keypair
    if (this.config.cspCurve25519PrivateKeyB64) {
      const priv = new Uint8Array(Buffer.from(this.config.cspCurve25519PrivateKeyB64, "base64"));
      const pub = deriveCurve25519PublicKey(priv);
      this.cspPriv = priv;
      this.cspPub = pub;
      await this.prisma.serverKey.upsert({
        where: { name: "csp_curve25519" },
        create: {
          name: "csp_curve25519",
          publicKey: Buffer.from(pub),
          privateKey: Buffer.from(priv)
        },
        update: {
          publicKey: Buffer.from(pub),
          privateKey: Buffer.from(priv)
        }
      });
    } else {
      const existing = await this.prisma.serverKey.findUnique({ where: { name: "csp_curve25519" } });
      if (existing) {
        this.cspPub = new Uint8Array(existing.publicKey);
        this.cspPriv = new Uint8Array(existing.privateKey);
      } else {
        const kp = generateCurve25519KeyPair();
        this.cspPub = kp.publicKey;
        this.cspPriv = kp.secretKey;
        await this.prisma.serverKey.create({
          data: {
            name: "csp_curve25519",
            publicKey: Buffer.from(kp.publicKey),
            privateKey: Buffer.from(kp.secretKey)
          }
        });
      }
    }

    this.initialized = true;
  }

  getOppfPublicKey(): Uint8Array {
    return this.oppfPub;
  }

  getOppfPublicKeyBase64(): string {
    return Buffer.from(this.oppfPub).toString("base64");
  }

  getCspKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array; publicKeyBase64: string } {
    return {
      publicKey: this.cspPub,
      privateKey: this.cspPriv,
      publicKeyBase64: Buffer.from(this.cspPub).toString("base64")
    };
  }

  signOppfPayload(payloadObj: Record<string, unknown>): string {
    const withKey = {
      ...payloadObj,
      signatureKey: this.getOppfPublicKeyBase64()
    };
    const body = JSON.stringify(withKey);
    const sig = ed25519Sign(Buffer.from(body, "utf8"), this.oppfPriv);
    const sigB64 = Buffer.from(sig).toString("base64");
    return `${body}\n${sigB64}`;
  }

  verifyOppfString(oppfText: string, trustedPubKeysB64?: string[]): Record<string, unknown> {
    const trimmed = oppfText.replace(/\n+$/, "");
    const lastNl = trimmed.lastIndexOf("\n");
    if (lastNl === -1) {
      throw new Error("Invalid OPPF format: missing signature line");
    }
    const body = trimmed.slice(0, lastNl);
    const sigB64 = trimmed.slice(lastNl + 1);
    const sig = new Uint8Array(Buffer.from(sigB64, "base64"));
    const parsed = JSON.parse(body) as Record<string, unknown>;
    if (typeof parsed.signatureKey !== "string") {
      throw new Error("Missing signatureKey in OPPF");
    }
    const sigKey = new Uint8Array(Buffer.from(parsed.signatureKey, "base64"));
    const allowed = (trustedPubKeysB64 ?? [this.getOppfPublicKeyBase64()]).map(
      (k) => new Uint8Array(Buffer.from(k, "base64"))
    );
    if (!allowed.some((k) => constantTimeEqual(k, sigKey))) {
      throw new Error("Untrusted OPPF signatureKey");
    }
    if (!ed25519Verify(Buffer.from(body, "utf8"), sig, sigKey)) {
      throw new Error("OPPF Ed25519 signature verification failed");
    }
    return parsed;
  }
}
