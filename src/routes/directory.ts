import express from "express";
import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "../config.js";
import type { CspRouter } from "../csp/session.js";
import { requireWorkBasicAuth } from "../auth/workAuth.js";
import {
  registerAuthenticatedCredentialRoutes,
  registerUnauthenticatedCredentialRoutes
} from "./directory/credentials.js";
import {
  registerAuthenticatedIdentityRoutes,
  registerUnauthenticatedIdentityRoutes
} from "./directory/identity.js";
import { registerMatchingRoutes } from "./directory/matching.js";
import { registerReportRoutes } from "./directory/reports.js";
import type { DirectoryRouterDeps, DirectoryTurnConfig } from "./directory/shared.js";

export type { DirectoryTurnConfig };

export function createDirectoryRouter(
  prisma: PrismaClient,
  config: ServerConfig,
  getHttpOrigin: () => string,
  getTurnConfig?: () => DirectoryTurnConfig,
  cspRouter?: CspRouter
): express.Router {
  const router = express.Router();
  router.use(
    express.json({
      limit: "2mb",
      type: (req) => {
        const ct = req.headers["content-type"]?.toLowerCase();
        return !ct || ct.includes("json") || ct.startsWith("text/plain");
      }
    })
  );

  const deps: DirectoryRouterDeps = {
    prisma,
    config,
    getHttpOrigin,
    getTurnConfig,
    cspRouter
  };

  // Routes callable without Work Basic Auth must stay BEFORE requireWorkBasicAuth
  registerUnauthenticatedIdentityRoutes(router, deps);
  registerUnauthenticatedCredentialRoutes(router, deps);

  // All remaining directory routes require Work Basic Auth
  router.use(requireWorkBasicAuth(prisma));

  registerAuthenticatedIdentityRoutes(router, deps);
  registerMatchingRoutes(router, deps);
  registerAuthenticatedCredentialRoutes(router, deps);
  registerReportRoutes(router, deps);

  return router;
}
