import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { loadConfig } from "../config.js";
import { computeCertSpkiSha256Base64, generateLocalTlsBundle } from "../crypto/tlsCert.js";

function collectSans(config: ReturnType<typeof loadConfig>): {
  dnsNames: string[];
  ipAddresses: string[];
} {
  const candidates = new Set<string>(["localhost", "127.0.0.1", "::1"]);

  try {
    const u = new URL(config.publicHttpOrigin);
    if (u.hostname) candidates.add(u.hostname);
  } catch {
    // Ignore unparseable PUBLIC_HTTP_ORIGIN
  }

  if (config.cspHost) candidates.add(config.cspHost.trim());
  for (const s of config.tlsSans) {
    if (s) candidates.add(s.trim());
  }

  const dnsNames: string[] = [];
  const ipAddresses: string[] = [];
  for (const raw of candidates) {
    const clean = raw.replace(/^\[|\]$/g, "");
    if (!clean) continue;
    if (net.isIP(clean) !== 0) {
      ipAddresses.push(clean);
    } else {
      dnsNames.push(clean);
    }
  }

  return { dnsNames, ipAddresses };
}

function printTrustInstructions(certsDir: string, spkiSha256Base64: string): void {
  const caPath = path.join(certsDir, "ca.crt");
  console.log(`  Leaf SPKI SHA-256 (Base64): ${spkiSha256Base64}`);
  console.log(`  CA certificate:             ${caPath}`);
  console.log(`  Server fullchain:           ${path.join(certsDir, "server-fullchain.crt")}`);
  console.log(`  Server private key:         ${path.join(certsDir, "server.key")}`);
  console.log("");
  console.log("Local trust commands (for Node / curl / Windows CurrentUser Root store):");
  console.log(`  Windows: certutil -user -addstore Root "${caPath}"`);
  console.log(`  Node.js: $env:NODE_EXTRA_CA_CERTS="${caPath}"`);
}

function main(): void {
  const force = process.argv.includes("--force");
  const config = loadConfig();
  const projectRoot = path.resolve(import.meta.dirname, "../..");
  const certsDir = path.join(projectRoot, "certs");

  const caCertPath = path.join(certsDir, "ca.crt");
  const caKeyPath = path.join(certsDir, "ca.key");
  const serverCertPath = path.join(certsDir, "server.crt");
  const serverKeyPath = path.join(certsDir, "server.key");
  const fullchainPath = path.join(certsDir, "server-fullchain.crt");

  if (!force && fs.existsSync(caCertPath) && fs.existsSync(fullchainPath) && fs.existsSync(serverKeyPath)) {
    const existingPem = fs.readFileSync(fullchainPath, "utf8");
    const spki = computeCertSpkiSha256Base64(existingPem);
    console.log("Existing local TLS certificates found (pass --force to regenerate):");
    printTrustInstructions(certsDir, spki);
    return;
  }

  const { dnsNames, ipAddresses } = collectSans(config);
  const bundle = generateLocalTlsBundle({
    dnsNames,
    ipAddresses,
    commonName: dnsNames[0] || "localhost"
  });

  fs.mkdirSync(certsDir, { recursive: true });
  fs.writeFileSync(caCertPath, bundle.caCertPem, "utf8");
  fs.writeFileSync(caKeyPath, bundle.caKeyPem, "utf8");
  fs.writeFileSync(serverCertPath, bundle.serverCertPem, "utf8");
  fs.writeFileSync(serverKeyPath, bundle.serverKeyPem, "utf8");
  fs.writeFileSync(fullchainPath, bundle.fullchainPem, "utf8");

  console.log("Generated local TLS CA and SAN server certificate:");
  console.log(`  DNS SANs: ${dnsNames.join(", ") || "(none)"}`);
  console.log(`  IP SANs:  ${ipAddresses.join(", ") || "(none)"}`);
  printTrustInstructions(certsDir, bundle.spkiSha256Base64);
}

main();
