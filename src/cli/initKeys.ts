import { loadConfig } from "../config.js";
import { createPrismaClient, seedDefaults } from "../db.js";
import { KeyManager } from "../crypto/keyManager.js";

async function main() {
  const config = loadConfig();
  const prisma = createPrismaClient(config.databaseUrl);
  try {
    await seedDefaults(prisma, config);
    const km = new KeyManager(prisma, config);
    await km.init();
    console.log("Initialized server keys and default account:");
    console.log("  OPPF Ed25519 Public Key (Base64):", km.getOppfPublicKeyBase64());
    console.log("  CSP Curve25519 Public Key (Base64):", km.getCspKeyPair().publicKeyBase64);
    console.log("  Default Work Username:", config.defaultWorkUsername);
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
