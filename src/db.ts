import { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "./config.js";
import { hashPassword } from "./crypto/primitives.js";

export function createPrismaClient(databaseUrl?: string): PrismaClient {
  return new PrismaClient(
    databaseUrl
      ? {
          datasources: {
            db: { url: databaseUrl }
          }
        }
      : undefined
  );
}

export async function configureDatabaseConnection(
  prisma: PrismaClient,
  databaseUrl?: string
): Promise<void> {
  const url = (databaseUrl ?? process.env.DATABASE_URL ?? "").trim().toLowerCase();
  if (url.startsWith("file:")) {
    await prisma.$queryRawUnsafe("PRAGMA journal_mode = WAL;");
    await prisma.$queryRawUnsafe("PRAGMA busy_timeout = 5000;");
    await prisma.$queryRawUnsafe("PRAGMA synchronous = NORMAL;");
    await prisma.$queryRawUnsafe("PRAGMA foreign_keys = ON;");
  } else {
    await prisma.$queryRaw`SELECT 1`;
  }
}

export const configureSqlitePragmas = configureDatabaseConnection;

export async function seedDefaults(prisma: PrismaClient, config: ServerConfig): Promise<void> {
  await prisma.workMdmConfig.upsert({
    where: { id: "default" },
    create: {
      id: "default",
      override: false,
      paramsJson: "{}",
      directoryEnabled: true,
      categoriesJson: "{}",
      orgName: config.orgName,
      support: config.supportText,
      checkInterval: 86400,
      remoteSecretEnabled: config.remoteSecretEnabled
    },
    update: {}
  });

  const existingAccounts = await prisma.workAccount.count();
  if (existingAccounts === 0) {
    await prisma.workAccount.create({
      data: {
        username: config.defaultWorkUsername,
        passwordHash: hashPassword(config.defaultWorkPassword),
        enabled: true
      }
    });
  } else {
    const defaultAccount = await prisma.workAccount.findUnique({
      where: { username: config.defaultWorkUsername }
    });
    if (defaultAccount) {
      if (defaultAccount.firstName === "Demo" && defaultAccount.lastName === "User") {
        await prisma.workAccount.update({
          where: { id: defaultAccount.id },
          data: {
            firstName: null,
            lastName: null,
            jobTitle: null,
            department: null
          }
        });
      }
      await prisma.identity.updateMany({
        where: { workAccountId: null },
        data: { workAccountId: defaultAccount.id }
      });
    }
  }
}
