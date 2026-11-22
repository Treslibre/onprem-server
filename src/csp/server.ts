import net from "node:net";
import type { PrismaClient } from "@prisma/client";
import type { KeyManager } from "../crypto/keyManager.js";
import { createLogger } from "../logger.js";
import { CspRouter, CspSessionHandler } from "./session.js";

const log = createLogger("CSP");

export function createCspTcpServer(
  prisma: PrismaClient,
  keyManager: KeyManager,
  router: CspRouter
): net.Server {
  const server = net.createServer((socket) => {
    socket.setNoDelay(true);
    const remoteLabel = `${socket.remoteAddress ?? "unknown"}:${socket.remotePort ?? 0}`;
    log.info(`tcp connect from ${remoteLabel}`);
    const session = new CspSessionHandler(
      prisma,
      keyManager,
      router,
      {
        sendBytes: (data) => {
          if (!socket.destroyed) {
            socket.write(Buffer.from(data));
          }
        },
        close: () => {
          if (!socket.destroyed) {
            socket.end();
            socket.destroy();
          }
        }
      },
      { transportKind: "tcp", remoteLabel }
    );

    socket.on("data", (chunk) => {
      session.feedBytes(new Uint8Array(chunk));
    });
    socket.on("close", () => {
      session.close();
    });
    socket.on("error", () => {
      session.close();
    });
  });

  return server;
}
