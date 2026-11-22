import crypto from "node:crypto";
import nacl from "tweetnacl";
import { blake2b } from "@noble/hashes/blake2";

// Exact HMAC-SHA256 keys from Threema APIConnector.java
export const EMAIL_HMAC_KEY = Buffer.from(
  "30a5500fed9701fa6defdb610841900febb8e430881f7ad816826264ec09bad7",
  "hex"
);
export const MOBILENO_HMAC_KEY = Buffer.from(
  "85adf8226953f3d96cfd5d09bf29555eb955fcd8aa5ec4f9fcd869e258370723",
  "hex"
);

// Ed25519 DER ASN.1 wrappers for Node.js crypto
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((acc, p) => acc + p.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

// Curve25519 + HSalsa20 (NaCl box shared key)
export function generateCurve25519KeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return nacl.box.keyPair();
}

export function deriveCurve25519PublicKey(privateKey32: Uint8Array): Uint8Array {
  if (privateKey32.byteLength !== 32) {
    throw new Error(`Invalid Curve25519 private key length: ${privateKey32.byteLength}`);
  }
  return nacl.box.keyPair.fromSecretKey(privateKey32).publicKey;
}

export function deriveSharedSecret(publicKey32: Uint8Array, privateKey32: Uint8Array): Uint8Array {
  if (publicKey32.byteLength !== 32 || privateKey32.byteLength !== 32) {
    throw new Error("Curve25519 keys must be 32 bytes");
  }
  return nacl.box.before(publicKey32, privateKey32);
}

export function boxEncryptShared(
  plaintext: Uint8Array,
  nonce24: Uint8Array,
  sharedKey32: Uint8Array
): Uint8Array {
  return nacl.box.after(plaintext, nonce24, sharedKey32);
}

export function boxDecryptShared(
  ciphertext: Uint8Array,
  nonce24: Uint8Array,
  sharedKey32: Uint8Array
): Uint8Array {
  const plain = nacl.box.open.after(ciphertext, nonce24, sharedKey32);
  if (!plain) {
    throw new Error("XSalsa20-Poly1305 decryption failed");
  }
  return plain;
}

// BLAKE2b-256 with 16-byte zero-padded salt & personalization
function zeroPad16(value?: string): Uint8Array | undefined {
  if (value === undefined) return undefined;
  const encoded = Buffer.from(value, "utf8");
  if (encoded.byteLength > 8) {
    throw new Error(`BLAKE2b parameter too long: ${value}`);
  }
  const out = new Uint8Array(16);
  out.set(encoded, 0);
  return out;
}

export function blake2bMac256(
  key: Uint8Array,
  data: Uint8Array,
  opts?: { personal?: string; salt?: string }
): Uint8Array {
  return blake2b(data, {
    dkLen: 32,
    key,
    salt: zeroPad16(opts?.salt),
    personalization: zeroPad16(opts?.personal)
  });
}

export function computeDirectoryChallengeResponse(
  sharedSecret32: Uint8Array,
  token: Uint8Array
): Uint8Array {
  const responseKey = blake2bMac256(sharedSecret32, new Uint8Array(0), {
    personal: "3ma-csp",
    salt: "dir"
  });
  return blake2bMac256(responseKey, token);
}

export function computeWorkChallengeResponse(
  sharedSecret32: Uint8Array,
  challenge: Uint8Array
): Uint8Array {
  const responseKey = blake2bMac256(sharedSecret32, new Uint8Array(0), {
    personal: "3ma-csp",
    salt: "wdir"
  });
  return blake2bMac256(responseKey, challenge);
}

export function sha256Hex(data: Uint8Array | string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function constantTimeStringEqual(a: string, b: string): boolean {
  const ha = crypto.createHash("sha256").update(a, "utf8").digest();
  const hb = crypto.createHash("sha256").update(b, "utf8").digest();
  return crypto.timingSafeEqual(ha, hb);
}

export function computeCspVouchMac(
  ss1: Uint8Array,
  ss2: Uint8Array,
  serverCookie16: Uint8Array,
  clientTempPub32: Uint8Array
): Uint8Array {
  const vouchKey = blake2bMac256(concatBytes(ss1, ss2), new Uint8Array(0), {
    personal: "3ma-csp",
    salt: "v2"
  });
  return blake2bMac256(vouchKey, concatBytes(serverCookie16, clientTempPub32));
}

export class NonceCounter {
  private readonly cookie: Uint8Array;
  private counter = 1n;

  constructor(cookie: Uint8Array) {
    if (cookie.byteLength !== 16) {
      throw new Error(`Nonce cookie must be 16 bytes, got ${cookie.byteLength}`);
    }
    this.cookie = new Uint8Array(cookie);
  }

  nextNonce(): Uint8Array {
    const out = new Uint8Array(24);
    out.set(this.cookie, 0);
    const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
    view.setBigUint64(16, this.counter, true);
    this.counter += 1n;
    return out;
  }
}

export function hmacEmail(email: string): string {
  const normalized = email.toLowerCase().trim();
  return crypto
    .createHmac("sha256", EMAIL_HMAC_KEY)
    .update(Buffer.from(normalized, "ascii"))
    .digest("base64");
}

export function hmacMobileNo(mobileNo: string): string {
  const digits = mobileNo.replace(/[^0-9]/g, "");
  return crypto
    .createHmac("sha256", MOBILENO_HMAC_KEY)
    .update(Buffer.from(digits, "ascii"))
    .digest("base64");
}

export function generateEd25519KeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  return {
    publicKey: new Uint8Array(spki.subarray(spki.length - 32)),
    privateKey: new Uint8Array(pkcs8.subarray(pkcs8.length - 32))
  };
}

export function deriveEd25519PublicKey(privateKeySeed32: Uint8Array): Uint8Array {
  if (privateKeySeed32.byteLength !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${privateKeySeed32.byteLength}`);
  }
  const privKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKeySeed32)]),
    format: "der",
    type: "pkcs8"
  });
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const spki = pubKeyObj.export({ type: "spki", format: "der" });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

export function ed25519Sign(message: Uint8Array, privateKeySeed32: Uint8Array): Uint8Array {
  const privKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKeySeed32)]),
    format: "der",
    type: "pkcs8"
  });
  return new Uint8Array(crypto.sign(null, Buffer.from(message), privKeyObj));
}

export function ed25519Verify(
  message: Uint8Array,
  signature64: Uint8Array,
  publicKey32: Uint8Array
): boolean {
  if (signature64.byteLength !== 64 || publicKey32.byteLength !== 32) {
    return false;
  }
  const pubKeyObj = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey32)]),
    format: "der",
    type: "spki"
  });
  return crypto.verify(null, Buffer.from(message), pubKeyObj, Buffer.from(signature64));
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 32);
  return `${salt.toString("hex")}:${derived.toString("hex")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split(":");
  if (parts.length !== 2) return false;
  const [saltHex, hashHex] = parts;
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(password, salt, expected.byteLength);
  return constantTimeEqual(actual, expected);
}
