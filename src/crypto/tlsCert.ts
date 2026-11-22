import crypto from "node:crypto";
import net from "node:net";

export interface LocalTlsBundle {
  caCertPem: string;
  caKeyPem: string;
  serverCertPem: string;
  serverKeyPem: string;
  fullchainPem: string;
  spkiSha256Base64: string;
}

export interface GenerateLocalTlsOptions {
  dnsNames?: string[];
  ipAddresses?: string[];
  commonName?: string;
  validityDays?: number;
}

function derEncodeLength(len: number): Buffer {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derEncodeLength(content.byteLength), content]);
}

function derSequence(...items: Buffer[]): Buffer {
  return derTlv(0x30, Buffer.concat(items));
}

function derSet(...items: Buffer[]): Buffer {
  return derTlv(0x31, Buffer.concat(items));
}

function derBoolean(value: boolean): Buffer {
  return derTlv(0x01, Buffer.from([value ? 0xff : 0x00]));
}

function derSmallInteger(value: number): Buffer {
  if (value < 0 || value > 127) {
    throw new Error(`Unsupported small integer: ${value}`);
  }
  return derTlv(0x02, Buffer.from([value]));
}

function derPositiveInteger(raw: Buffer): Buffer {
  let buf = Buffer.from(raw);
  buf[0] &= 0x7f;
  if (buf[0] === 0) {
    buf[0] = 0x01;
  }
  return derTlv(0x02, buf);
}

function derBitString(bytes: Buffer, unusedBits = 0): Buffer {
  return derTlv(0x03, Buffer.concat([Buffer.from([unusedBits]), bytes]));
}

function derOctetString(bytes: Buffer): Buffer {
  return derTlv(0x04, bytes);
}

function derOid(oid: string): Buffer {
  const parts = oid.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length < 2 || parts.some((n) => Number.isNaN(n) || n < 0)) {
    throw new Error(`Invalid OID: ${oid}`);
  }
  const out: number[] = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i];
    if (val === 0) {
      out.push(0);
      continue;
    }
    const stack: number[] = [];
    while (val > 0) {
      stack.push(val & 0x7f);
      val >>>= 7;
    }
    for (let j = stack.length - 1; j >= 0; j--) {
      out.push(j === 0 ? stack[j] : stack[j] | 0x80);
    }
  }
  return derTlv(0x06, Buffer.from(out));
}

function derUtf8String(value: string): Buffer {
  return derTlv(0x0c, Buffer.from(value, "utf8"));
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

function derTime(date: Date): Buffer {
  const year = date.getUTCFullYear();
  const body =
    `${pad2(date.getUTCMonth() + 1)}${pad2(date.getUTCDate())}` +
    `${pad2(date.getUTCHours())}${pad2(date.getUTCMinutes())}${pad2(date.getUTCSeconds())}Z`;
  if (year >= 1950 && year <= 2049) {
    return derTlv(0x17, Buffer.from(`${pad2(year % 100)}${body}`, "ascii"));
  }
  return derTlv(0x18, Buffer.from(`${String(year).padStart(4, "0")}${body}`, "ascii"));
}

function derExplicit(tagNumber: number, inner: Buffer): Buffer {
  return derTlv(0xa0 | (tagNumber & 0x1f), inner);
}

function derImplicitPrimitive(tagNumber: number, content: Buffer): Buffer {
  return derTlv(0x80 | (tagNumber & 0x1f), content);
}

function parseIpv4Bytes(ip: string): Buffer {
  const octets = ip.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return Buffer.from(octets);
}

function parseIpv6Hextets(group: string): number[] {
  if (!group) return [];
  const parts = group.split(":");
  const out: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part.includes(".")) {
      const v4 = parseIpv4Bytes(part);
      out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
    } else {
      const parsed = Number.parseInt(part, 16);
      if (Number.isNaN(parsed) || parsed < 0 || parsed > 0xffff) {
        throw new Error(`Invalid IPv6 segment: ${part}`);
      }
      out.push(parsed);
    }
  }
  return out;
}

function parseIpv6Bytes(ip: string): Buffer {
  const clean = ip.replace(/^\[|\]$/g, "").split("%")[0];
  const halves = clean.split("::");
  if (halves.length > 2) {
    throw new Error(`Invalid IPv6 address: ${ip}`);
  }
  const left = parseIpv6Hextets(halves[0]);
  const right = halves.length === 2 ? parseIpv6Hextets(halves[1]) : [];
  const missingZeros = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if (missingZeros < 0 || (halves.length === 1 && left.length !== 8)) {
    throw new Error(`Invalid IPv6 address length: ${ip}`);
  }
  const words = [...left, ...new Array<number>(missingZeros).fill(0), ...right];
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    out.writeUInt16BE(words[i], i * 2);
  }
  return out;
}

function encodeIpGeneralName(ip: string): Buffer {
  const kind = net.isIP(ip);
  if (kind === 4) {
    return derImplicitPrimitive(7, parseIpv4Bytes(ip));
  }
  if (kind === 6) {
    return derImplicitPrimitive(7, parseIpv6Bytes(ip));
  }
  throw new Error(`Invalid IP address for SAN: ${ip}`);
}

function encodeRdnName(entries: Array<{ oid: string; value: string }>): Buffer {
  const rdns = entries.map((e) => derSet(derSequence(derOid(e.oid), derUtf8String(e.value))));
  return derSequence(...rdns);
}

function encodeExtension(oid: string, critical: boolean, extnValueDer: Buffer): Buffer {
  const fields: Buffer[] = [derOid(oid)];
  if (critical) {
    fields.push(derBoolean(true));
  }
  fields.push(derOctetString(extnValueDer));
  return derSequence(...fields);
}

function readDerLength(buf: Buffer, offset: number): { length: number; nextOffset: number } {
  const first = buf[offset];
  if ((first & 0x80) === 0) {
    return { length: first, nextOffset: offset + 1 };
  }
  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return { length, nextOffset: offset + 1 + numBytes };
}

function computeSubjectKeyIdentifier(spkiDer: Buffer): Buffer {
  // Skip outer SubjectPublicKeyInfo SEQUENCE tag+len, skip AlgorithmIdentifier TLV, read BIT STRING
  const outerLen = readDerLength(spkiDer, 1);
  let pos = outerLen.nextOffset;
  const algLen = readDerLength(spkiDer, pos + 1);
  pos = algLen.nextOffset + algLen.length;
  if (spkiDer[pos] !== 0x03) {
    throw new Error("Expected BIT STRING inside SPKI");
  }
  const bitLen = readDerLength(spkiDer, pos + 1);
  // Skip unused-bits byte (0x00) at bitLen.nextOffset
  const keyBytes = spkiDer.subarray(bitLen.nextOffset + 1, bitLen.nextOffset + bitLen.length);
  return crypto.createHash("sha1").update(keyBytes).digest();
}

function derToPem(label: string, der: Buffer): string {
  const b64 = der.toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function signX509Certificate(tbsDer: Buffer, issuerKey: crypto.KeyObject): string {
  // RFC 5758 §3.2: ecdsa-with-SHA256 MUST omit parameters (no NULL)
  const sigAlg = derSequence(derOid("1.2.840.10045.4.3.2"));
  const sigDer = crypto.sign("sha256", tbsDer, issuerKey);
  const certDer = derSequence(tbsDer, sigAlg, derBitString(sigDer, 0));
  return derToPem("CERTIFICATE", certDer);
}

/**
 * Compute Base64-encoded SHA-256 fingerprint of a certificate's SubjectPublicKeyInfo (SPKI),
 * matching Threema Desktop's `spkiFingerprint(certPem, "sha256")`.
 */
export function computeCertSpkiSha256Base64(certPem: string): string {
  const x509 = new crypto.X509Certificate(certPem);
  const spkiDer = x509.publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spkiDer).digest("base64");
}

/**
 * Generate a local P-256 ECDSA Root CA and SAN leaf server certificate for HTTPS/WSS testing.
 */
export function generateLocalTlsBundle(options: GenerateLocalTlsOptions = {}): LocalTlsBundle {
  const dnsNames = Array.from(new Set(options.dnsNames ?? ["localhost"])).filter(Boolean);
  const ipAddresses = Array.from(new Set(options.ipAddresses ?? ["127.0.0.1", "::1"])).filter(
    Boolean
  );
  const commonName = options.commonName || dnsNames[0] || "localhost";
  const validityDays = options.validityDays ?? 825;

  const now = Date.now();
  const notBefore = new Date(now - 5 * 60 * 1000);
  const caNotAfter = new Date(now + 3650 * 24 * 60 * 60 * 1000);
  const leafNotAfter = new Date(now + validityDays * 24 * 60 * 60 * 1000);

  const sigAlg = derSequence(derOid("1.2.840.10045.4.3.2"));

  // 1. Root CA keypair & self-signed X.509 v3 certificate
  const caKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const caSpkiDer = caKeys.publicKey.export({ type: "spki", format: "der" });
  const caSki = computeSubjectKeyIdentifier(caSpkiDer);
  const caName = encodeRdnName([
    { oid: "2.5.4.10", value: "OnPrem Local Dev" },
    { oid: "2.5.4.3", value: "Threema OnPrem Local Dev CA" }
  ]);

  const caExtensions = derExplicit(
    3,
    derSequence(
      // BasicConstraints (2.5.29.19, critical): CA=TRUE, pathLenConstraint=0
      encodeExtension("2.5.29.19", true, derSequence(derBoolean(true), derSmallInteger(0))),
      // KeyUsage (2.5.29.15, critical): keyCertSign(5) | cRLSign(6) -> [0x01, 0x06]
      encodeExtension("2.5.29.15", true, derBitString(Buffer.from([0x06]), 1)),
      // SubjectKeyIdentifier (2.5.29.14)
      encodeExtension("2.5.29.14", false, derOctetString(caSki))
    )
  );

  const caTbs = derSequence(
    derExplicit(0, derSmallInteger(2)),
    derPositiveInteger(crypto.randomBytes(16)),
    sigAlg,
    caName,
    derSequence(derTime(notBefore), derTime(caNotAfter)),
    caName,
    caSpkiDer,
    caExtensions
  );

  const caCertPem = signX509Certificate(caTbs, caKeys.privateKey);
  const caKeyPem = caKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  // 2. Server leaf keypair & CA-signed X.509 v3 certificate with SANs
  const leafKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const leafSpkiDer = leafKeys.publicKey.export({ type: "spki", format: "der" });
  const leafSki = computeSubjectKeyIdentifier(leafSpkiDer);
  const leafName = encodeRdnName([
    { oid: "2.5.4.10", value: "OnPrem Local Dev" },
    { oid: "2.5.4.3", value: commonName }
  ]);

  const sanEntries: Buffer[] = [
    ...dnsNames.map((dns) => derImplicitPrimitive(2, Buffer.from(dns, "ascii"))),
    ...ipAddresses.map((ip) => encodeIpGeneralName(ip))
  ];
  if (sanEntries.length === 0) {
    throw new Error("At least one DNS name or IP address is required for SAN");
  }

  const leafExtensions = derExplicit(
    3,
    derSequence(
      // BasicConstraints (critical): CA=FALSE (default fields omitted in DER)
      encodeExtension("2.5.29.19", true, derSequence()),
      // KeyUsage (critical): digitalSignature(0) -> [0x07, 0x80]
      encodeExtension("2.5.29.15", true, derBitString(Buffer.from([0x80]), 7)),
      // ExtendedKeyUsage: id-kp-serverAuth (1.3.6.1.5.5.7.3.1)
      encodeExtension("2.5.29.37", false, derSequence(derOid("1.3.6.1.5.5.7.3.1"))),
      // SubjectKeyIdentifier
      encodeExtension("2.5.29.14", false, derOctetString(leafSki)),
      // AuthorityKeyIdentifier: [0] keyIdentifier
      encodeExtension("2.5.29.35", false, derSequence(derImplicitPrimitive(0, caSki))),
      // SubjectAltName (2.5.29.17)
      encodeExtension("2.5.29.17", false, derSequence(...sanEntries))
    )
  );

  const leafTbs = derSequence(
    derExplicit(0, derSmallInteger(2)),
    derPositiveInteger(crypto.randomBytes(16)),
    sigAlg,
    caName,
    derSequence(derTime(notBefore), derTime(leafNotAfter)),
    leafName,
    leafSpkiDer,
    leafExtensions
  );

  const serverCertPem = signX509Certificate(leafTbs, caKeys.privateKey);
  const serverKeyPem = leafKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const fullchainPem = `${serverCertPem}${caCertPem}`;

  // Self-verify using Node's X509Certificate parser and verifier
  const caX509 = new crypto.X509Certificate(caCertPem);
  const leafX509 = new crypto.X509Certificate(serverCertPem);
  if (!leafX509.checkIssued(caX509) || !leafX509.verify(caX509.publicKey)) {
    throw new Error("Generated TLS certificate chain failed self-verification");
  }

  return {
    caCertPem,
    caKeyPem,
    serverCertPem,
    serverKeyPem,
    fullchainPem,
    spkiSha256Base64: computeCertSpkiSha256Base64(serverCertPem)
  };
}
