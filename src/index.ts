import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import type net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { WebSocketServer } from "ws";
import { loadConfig, type ServerConfig } from "./config.js";
import { configureSqlitePragmas, createPrismaClient, seedDefaults } from "./db.js";
import { KeyManager } from "./crypto/keyManager.js";
import { computeCertSpkiSha256Base64 } from "./crypto/tlsCert.js";
import { createOppfRouter } from "./routes/oppf.js";
import { createDirectoryRouter } from "./routes/directory.js";
import { createBlobRouter } from "./routes/blob.js";
import { createWorkRouter } from "./routes/work.js";
import { createAvatarRouter } from "./routes/avatar.js";
import { createSafeRouter } from "./routes/safe.js";
import { createAdminRouter } from "./routes/admin.js";
import { CspRouter } from "./csp/session.js";
import { createCspTcpServer } from "./csp/server.js";
import { D2mMediatorServer } from "./d2m/mediator.js";
import { RendezvousServer } from "./rendezvous/server.js";
import { TurnServer } from "./turn/server.js";
import { createLogger, resolveLogLevel } from "./logger.js";
import {
  HousekeepingScheduler,
  runHousekeeping,
  type HousekeepingStats
} from "./maintenance/sweeper.js";
import { createRateLimiter } from "./middleware/rateLimit.js";

export interface OnPremServerHandle {
  config: ServerConfig;
  keyManager: KeyManager;
  prisma: ReturnType<typeof createPrismaClient>;
  cspRouter: CspRouter;
  mediator: D2mMediatorServer;
  rendezvous: RendezvousServer;
  runCleanup: () => Promise<HousekeepingStats>;
  start: () => Promise<{
    httpPort: number;
    cspPort: number;
    turnPort: number;
    turnExternalIp: string;
    httpOrigin: string;
    wsOrigin: string;
  }>;
  stop: () => Promise<void>;
  getAddresses: () => {
    httpPort: number;
    cspPort: number;
    turnPort: number;
    turnExternalIp: string;
    httpOrigin: string;
    wsOrigin: string;
  };
}

export function createServer(overrides: Partial<ServerConfig> = {}): OnPremServerHandle {
  const config = loadConfig(overrides);
  if (config.logLevel && !process.env.LOG_LEVEL) {
    process.env.LOG_LEVEL = config.logLevel;
  }
  const httpLog = createLogger("HTTP");
  const wsLog = createLogger("WS");
  const tlsLog = createLogger("TLS");
  const srvLog = createLogger("Server");

  const prisma = createPrismaClient(config.databaseUrl);
  const keyManager = new KeyManager(prisma, config);
  const cspRouter = new CspRouter();
  const mediator = new D2mMediatorServer(prisma, keyManager, cspRouter);
  const rendezvous = new RendezvousServer();

  let boundHttpPort = config.httpPort;
  let boundCspPort = config.cspPort;
  let boundTurnPort = config.turnEnabled ? config.turnPort : 0;
  let turnExternalIp = config.turnExternalIp || config.turnHost;
  let turnServer: TurnServer | undefined;

  const runCleanup = () =>
    runHousekeeping(prisma, {
      blobStorageDir: config.blobStorageDir,
      blobTtlHours: config.blobTtlHours
    });

  const scheduler = new HousekeepingScheduler(
    prisma,
    config.housekeepingIntervalMinutes * 60_000,
    {
      blobStorageDir: config.blobStorageDir,
      blobTtlHours: config.blobTtlHours
    }
  );

  const getTurnSecret = (): string =>
    config.turnSecret.trim() ||
    crypto
      .createHash("sha256")
      .update("threema-onprem-turn:")
      .update(keyManager.getCspKeyPair().privateKey)
      .digest("hex");

  const getRuntimeHttpOrigin = (): string => {
    if (overrides.publicHttpOrigin) return overrides.publicHttpOrigin;
    if (overrides.httpPort === 0 || config.httpPort === 0) {
      const scheme = config.tlsEnabled ? "https" : "http";
      return `${scheme}://127.0.0.1:${boundHttpPort}`;
    }
    return config.publicHttpOrigin;
  };

  const getRuntimeWsOrigin = (): string => {
    if (overrides.publicWsOrigin) return overrides.publicWsOrigin;
    if (overrides.httpPort === 0 || config.httpPort === 0) {
      const scheme = config.tlsEnabled ? "wss" : "ws";
      return `${scheme}://127.0.0.1:${boundHttpPort}`;
    }
    return config.publicWsOrigin;
  };

  const app = express();
  app.disable("x-powered-by");

  const logRequests = resolveLogLevel(config.logLevel) !== "silent" && process.env.LOG_REQUESTS !== "false";
  if (logRequests) {
    app.use((req, res, next) => {
      res.on("finish", () => {
        const fwdHost = req.header("x-forwarded-host");
        const hostVal = req.header("host") ?? "-";
        const hostInfo = fwdHost ? `${hostVal} (xfh=${fwdHost})` : hostVal;
        httpLog.info(`${req.method} ${req.originalUrl} host=${hostInfo} -> ${res.statusCode}`);
      });
      next();
    });
  }

  const allowedCorsSet = new Set(config.corsAllowedOrigins);
  app.use((req, res, next) => {
    const origin = req.header("origin");
    if (allowedCorsSet.size > 0) {
      if (origin && allowedCorsSet.has(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
      }
    } else if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    } else {
      res.setHeader("Access-Control-Allow-Origin", "*");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS");

    const baseAllowedHeaders = [
      "Authorization",
      "Content-Type",
      "Accept",
      "Cache-Control",
      "If-None-Match",
      "X-Admin-Key",
      "X-Threema-App-Identifier"
    ];
    const requestedHeadersRaw = req.header("access-control-request-headers");
    const allowHeaders = [...baseAllowedHeaders];
    if (requestedHeadersRaw) {
      const seen = new Set(baseAllowedHeaders.map((h) => h.toLowerCase()));
      for (const h of requestedHeadersRaw.split(",")) {
        const trimmed = h.trim();
        if (trimmed && !seen.has(trimmed.toLowerCase())) {
          seen.add(trimmed.toLowerCase());
          allowHeaders.push(trimmed);
        }
      }
    }
    res.setHeader("Access-Control-Allow-Headers", allowHeaders.join(", "));
    res.setHeader(
      "Access-Control-Expose-Headers",
      "Content-Length, Content-Type, ETag, Last-Modified"
    );
    res.setHeader("Access-Control-Max-Age", "86400");

    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }
    next();
  });

  app.get("/health", (_req, res) => {
    res.json({ ok: true });
  });

  const makeRl = (keyPrefix: string) =>
    createRateLimiter({
      enabled: config.rateLimitEnabled,
      windowMs: config.rateLimitWindowMs,
      maxRequests: config.rateLimitMaxRequests,
      keyPrefix
    });

  app.use(
    "/",
    createOppfRouter(prisma, config, keyManager, () => ({
      httpOrigin: getRuntimeHttpOrigin(),
      wsOrigin: getRuntimeWsOrigin(),
      cspHost: config.cspHost,
      cspPort: boundCspPort,
      tlsSpkiPin
    }))
  );

  const dirSensitiveRl = makeRl("dir-auth");
  app.use("/directory/check_license", dirSensitiveRl);
  app.use("/directory/identity/create", dirSensitiveRl);
  app.use("/directory/identity/ws/revoke", dirSensitiveRl);
  app.use(
    "/directory",
    createDirectoryRouter(
      prisma,
      config,
      getRuntimeHttpOrigin,
      () => ({
        host: config.turnHost,
        port: boundTurnPort,
        secret: getTurnSecret()
      }),
      cspRouter
    )
  );
  app.use("/blob", createBlobRouter(prisma, "usual", config.blobStorageDir));
  app.use("/mediator-blob", createBlobRouter(prisma, "mirror", config.blobStorageDir));
  app.use("/work", makeRl("work"), createWorkRouter(prisma, getRuntimeHttpOrigin));
  app.use("/avatar", createAvatarRouter(prisma));
  app.use("/safe", createSafeRouter(prisma));

  const getAddresses = () => ({
    httpPort: boundHttpPort,
    cspPort: boundCspPort,
    turnPort: boundTurnPort,
    turnExternalIp,
    httpOrigin: getRuntimeHttpOrigin(),
    wsOrigin: getRuntimeWsOrigin()
  });

  app.use(
    "/admin",
    makeRl("admin"),
    createAdminRouter({
      prisma,
      config,
      keyManager,
      cspRouter,
      mediator,
      rendezvous,
      getTurnStats: () =>
        turnServer
          ? turnServer.getStats()
          : {
              enabled: config.turnEnabled,
              port: boundTurnPort,
              externalIp: turnExternalIp,
              activeAllocations: 0,
              activeTcpSockets: 0
            },
      getAddresses,
      runCleanup
    })
  );

  // Express 4-arg error handler (malformed JSON, multer size overflow, unexpected errors)
  app.use(
    (
      err: unknown,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction
    ): void => {
      if (res.headersSent) return;
      const errObj = err as { type?: string; status?: number; code?: string; message?: string };
      if (errObj?.type === "entity.parse.failed" || (err instanceof SyntaxError && errObj.status === 400)) {
        res.status(400).json({ error: "Invalid JSON body" });
        return;
      }
      if (errObj?.code === "LIMIT_FILE_SIZE") {
        res.status(413).json({ error: "Payload too large" });
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      srvLog.error(`unhandled HTTP error: ${msg}`);
      res.status(500).json({ error: "Internal server error" });
    }
  );

  let tlsSpkiPin: string | undefined;
  let httpServer: http.Server | https.Server;
  if (config.tlsEnabled) {
    if (!config.tlsCertPath || !config.tlsKeyPath) {
      throw new Error("TLS_ENABLED=true requires TLS_CERT_PATH and TLS_KEY_PATH");
    }
    const certPath = path.resolve(config.tlsCertPath);
    const keyPath = path.resolve(config.tlsKeyPath);
    const certPem = fs.readFileSync(certPath, "utf8");
    const keyPem = fs.readFileSync(keyPath, "utf8");
    tlsSpkiPin = computeCertSpkiSha256Base64(certPem);
    httpServer = https.createServer(
      {
        cert: certPem,
        key: keyPem
      },
      app
    );
  } else {
    httpServer = http.createServer(app);
  }

  if (config.tlsEnabled && "on" in httpServer) {
    (httpServer as https.Server).on("tlsClientError", (err, tlsSocket) => {
      tlsLog.error(`handshake error from ${tlsSocket.remoteAddress ?? "unknown"}: ${err.message}`);
    });
  }

  const wss = new WebSocketServer({ noServer: true });
  httpServer.on("upgrade", (req, socket, head) => {
    socket.on("error", () => undefined);
    const pathname = new URL(req.url || "/", "http://localhost").pathname;
    wsLog.info(`upgrade ${pathname} host=${req.headers.host ?? "-"} origin=${req.headers.origin ?? "-"}`);
    if (pathname.startsWith("/mediator/")) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        mediator.handleConnection(ws, pathname);
      });
      return;
    }
    if (pathname.startsWith("/rendezvous/")) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        rendezvous.handleConnection(ws, pathname);
      });
      return;
    }
    wsLog.warn(`rejected upgrade path: ${pathname}`);
    socket.destroy();
  });

  const cspServer: net.Server = createCspTcpServer(prisma, keyManager, cspRouter);

  const listenDualStackOrFallback = (
    srv: http.Server | https.Server | net.Server,
    port: number,
    host: string
  ): Promise<number> => {
    const attempt = (bindHost: string, ipv6Only?: boolean): Promise<number> =>
      new Promise((resolve, reject) => {
        const onListening = () => {
          srv.off("error", onError);
          const addr = srv.address();
          resolve(addr && typeof addr === "object" ? addr.port : port);
        };
        const onError = (err: NodeJS.ErrnoException) => {
          srv.off("listening", onListening);
          reject(err);
        };
        srv.once("listening", onListening);
        srv.once("error", onError);
        if (ipv6Only === false) {
          srv.listen({ port, host: bindHost, ipv6Only: false });
        } else {
          srv.listen({ port, host: bindHost });
        }
      });

    if (host === "0.0.0.0") {
      return attempt("::", false).catch((err: NodeJS.ErrnoException) => {
        if (
          err.code === "EAFNOSUPPORT" ||
          err.code === "EADDRNOTAVAIL" ||
          err.code === "EINVAL"
        ) {
          return attempt("0.0.0.0");
        }
        throw err;
      });
    }
    return attempt(host);
  };

  const start = async () => {
    await configureSqlitePragmas(prisma, config.databaseUrl);
    await seedDefaults(prisma, config);
    await keyManager.init();
    fs.mkdirSync(path.resolve(config.blobStorageDir), { recursive: true });

    boundHttpPort = await listenDualStackOrFallback(httpServer, config.httpPort, config.host);
    boundCspPort = await listenDualStackOrFallback(cspServer, config.cspPort, config.host);

    if (config.turnEnabled) {
      turnServer = new TurnServer({
        host: config.host,
        port: config.turnPort,
        turnHost: config.turnHost,
        externalIp: config.turnExternalIp,
        realm: config.turnRealm,
        getSecret: getTurnSecret,
        minPort: config.turnMinPort,
        maxPort: config.turnMaxPort,
        logEnabled: logRequests
      });
      const startedTurn = await turnServer.start();
      boundTurnPort = startedTurn.port;
      turnExternalIp = startedTurn.externalIp;
    }

    scheduler.start();

    return getAddresses();
  };

  const stop = async () => {
    scheduler.stop();
    mediator.closeAll();
    rendezvous.closeAll();
    cspRouter.closeAll();
    if (turnServer) {
      await turnServer.stop();
      turnServer = undefined;
    }

    for (const client of wss.clients) {
      client.terminate();
    }

    await new Promise<void>((resolve) => {
      wss.close(() => resolve());
    });
    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
      httpServer.closeAllConnections();
    });
    await new Promise<void>((resolve) => {
      cspServer.close(() => resolve());
    });
    await prisma.$disconnect();
  };

  return {
    config,
    keyManager,
    prisma,
    cspRouter,
    mediator,
    rendezvous,
    runCleanup,
    start,
    stop,
    getAddresses
  };
}

const isMain =
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]).toLowerCase() ===
    path.resolve(fileURLToPath(import.meta.url)).toLowerCase();
if (isMain) {
  const server = createServer();
  let shuttingDown = false;
  const shutdown = (sig: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`Received ${sig}, shutting down gracefully...`);
    server
      .stop()
      .then(() => process.exit(0))
      .catch((err) => {
        console.error("Error during shutdown:", err);
        process.exit(1);
      });
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  server
    .start()
    .then((addrs) => {
      console.log(`Threema OnPrem Node.js server listening:`);
      console.log(`  HTTP/WS: ${addrs.httpOrigin} (port ${addrs.httpPort})`);
      console.log(`  Admin UI: ${addrs.httpOrigin}/admin/ui`);
      console.log(`  CSP TCP: ${server.config.cspHost}:${addrs.cspPort}`);
      if (server.config.turnEnabled) {
        console.log(
          `  TURN/STUN: ${server.config.turnHost}:${addrs.turnPort} (UDP+TCP, externalIp=${addrs.turnExternalIp})`
        );
      }
      console.log(`  OPPF URL: ${addrs.httpOrigin}/config.oppf`);
      console.log(`  OPPF Ed25519 Public Key: ${server.keyManager.getOppfPublicKeyBase64()}`);
      console.log(`  CSP Curve25519 Public Key: ${server.keyManager.getCspKeyPair().publicKeyBase64}`);
    })
    .catch((err) => {
      console.error("Failed to start server:", err);
      process.exit(1);
    });
}
