import fs from "node:fs";
import express from "express";
import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "../config.js";
import type { KeyManager } from "../crypto/keyManager.js";
import { requireWorkBasicAuth } from "../auth/workAuth.js";

export interface RuntimeEndpoints {
  httpOrigin: string;
  wsOrigin: string;
  cspHost: string;
  cspPort: number;
  tlsSpkiPin?: string;
}

export function createOppfRouter(
  prisma: PrismaClient,
  config: ServerConfig,
  keyManager: KeyManager,
  getEndpoints: () => RuntimeEndpoints
): express.Router {
  const router = express.Router();

  const resolveRequestEndpoints = (req: express.Request) => {
    const ep = getEndpoints();
    if (config.publicOriginStatic) {
      return { httpOrigin: ep.httpOrigin, wsOrigin: ep.wsOrigin, cspHost: ep.cspHost, ep };
    }

    const rawProto = req.header("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
    const isEncrypted =
      Boolean((req.socket as { encrypted?: boolean }).encrypted) || config.tlsEnabled;
    const forwardedProto =
      rawProto === "https" || rawProto === "http" ? rawProto : isEncrypted ? "https" : "http";
    const wsProto = forwardedProto === "https" ? "wss" : "ws";

    const rawForwardedHost = req.header("x-forwarded-host")?.split(",")[0]?.trim();
    const effectiveHost = rawForwardedHost || req.header("host")?.trim();
    if (!effectiveHost) {
      return { httpOrigin: ep.httpOrigin, wsOrigin: ep.wsOrigin, cspHost: ep.cspHost, ep };
    }

    try {
      const parsedUrl = new URL(`${forwardedProto}://${effectiveHost}`);
      const derivedHttpOrigin = `${forwardedProto}://${parsedUrl.host}`;
      const derivedWsOrigin = `${wsProto}://${parsedUrl.host}`;
      const derivedCspHost = ep.cspHost === "localhost" ? parsedUrl.hostname : ep.cspHost;
      return {
        httpOrigin: derivedHttpOrigin,
        wsOrigin: derivedWsOrigin,
        cspHost: derivedCspHost,
        ep
      };
    } catch {
      return { httpOrigin: ep.httpOrigin, wsOrigin: ep.wsOrigin, cspHost: ep.cspHost, ep };
    }
  };

  const buildOppf = async (req: express.Request): Promise<string> => {
    if (config.staticOppfPath && fs.existsSync(config.staticOppfPath)) {
      return fs.readFileSync(config.staticOppfPath, "utf8");
    }

    const resolved = resolveRequestEndpoints(req);
    const ep = resolved.ep;
    const httpBase = resolved.httpOrigin.replace(/\/+$/, "");
    const wsBase = resolved.wsOrigin.replace(/\/+$/, "");

    const mdm = await prisma.workMdmConfig
      .findUnique({
        where: { id: "default" },
        select: { remoteSecretEnabled: true }
      })
      .catch(() => null);
    const remoteSecretEnabled = Boolean(config.remoteSecretEnabled || mdm?.remoteSecretEnabled);

    const payload: Record<string, unknown> = {
      version: "1.0",
      refresh: 86400,
      license: {
        id: config.licenseId,
        expires: config.licenseExpires,
        count: config.licenseCount
      },
      ...(remoteSecretEnabled ? { features: { remoteSecret: {} } } : {}),
      chat: {
        hostname: resolved.cspHost,
        ports: config.cspPublicPorts.length > 0 ? config.cspPublicPorts : [ep.cspPort],
        publicKey: keyManager.getCspKeyPair().publicKeyBase64
      },
      directory: {
        url: `${httpBase}/directory/`
      },
      blob: {
        uploadUrl: `${httpBase}/blob/upload`,
        downloadUrl: `${httpBase}/blob/{blobId}`,
        doneUrl: `${httpBase}/blob/{blobId}/done`
      },
      work: {
        url: `${httpBase}/work/`
      },
      avatar: {
        url: `${httpBase}/avatar/`
      },
      safe: {
        url: `${httpBase}/safe/`
      },
      mediator: {
        url: `${wsBase}/mediator/`,
        blob: {
          uploadUrl: `${httpBase}/mediator-blob/upload`,
          downloadUrl: `${httpBase}/mediator-blob/{blobId}`,
          doneUrl: `${httpBase}/mediator-blob/{blobId}/done`
        }
      },
      rendezvous: {
        url: `${wsBase}/rendezvous/`
      },
      updates: {
        desktop: {
          autoUpdate: false
        }
      },
      // Desktop calls `updatePublicKeyPins(oppfFile.parsed.domains?.rules)` and reads `.length`
      domains: {
        rules:
          config.tlsEnabled && config.tlsPinSpki && ep.tlsSpkiPin
            ? [
                {
                  fqdn: new URL(httpBase).hostname,
                  matchMode: "exact",
                  spkis: [{ algorithm: "sha256", value: ep.tlsSpkiPin }]
                }
              ]
            : []
      }
    };

    return keyManager.signOppfPayload(payload);
  };

  const sendOppf = async (req: express.Request, res: express.Response): Promise<void> => {
    const body = await buildOppf(req);
    const byteLen = Buffer.byteLength(body, "utf8");
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Length", String(byteLen));
    res.status(200);
    if (req.method === "HEAD") {
      res.end();
    } else {
      res.end(body);
    }
  };

  // Fallback OPPF is unauthenticated (verified in OnPremConfigFetcher.java)
  router.get(/^\/.+\.fallback\.oppf$/, (req, res, next) => {
    sendOppf(req, res).catch(next);
  });

  // Regular OPPF requires Work Basic Auth
  router.get(/^\/.+\.oppf$/, requireWorkBasicAuth(prisma), (req, res, next) => {
    sendOppf(req, res).catch(next);
  });

  return router;
}
