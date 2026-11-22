import dotenv from "dotenv";

export interface ServerConfig {
  databaseUrl: string;
  host: string;
  httpPort: number;
  cspPort: number;
  publicHttpOrigin: string;
  publicWsOrigin: string;
  publicOriginStatic: boolean;
  cspHost: string;
  cspPublicPorts: number[];
  tlsEnabled: boolean;
  tlsCertPath: string;
  tlsKeyPath: string;
  tlsPinSpki: boolean;
  tlsSans: string[];
  staticOppfPath: string;
  oppfEd25519PrivateKeyB64: string;
  cspCurve25519PrivateKeyB64: string;
  licenseId: string;
  licenseExpires: string;
  licenseCount: number;
  orgName: string;
  supportText: string;
  defaultWorkUsername: string;
  defaultWorkPassword: string;
  adminApiKey: string;
  turnUrls: string[];
  turnEnabled: boolean;
  turnPort: number;
  turnHost: string;
  turnExternalIp: string;
  turnRealm: string;
  turnSecret: string;
  turnMinPort: number;
  turnMaxPort: number;
  sfuBaseUrl: string;
  blobStorageDir: string;
  blobTtlHours: number;
  housekeepingIntervalMinutes: number;
  corsAllowedOrigins: string[];
  rateLimitEnabled: boolean;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  remoteSecretEnabled: boolean;
  logLevel: string;
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export function loadConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  dotenv.config({ quiet: true } as dotenv.DotenvConfigOptions);

  const env = process.env;
  const httpPort = overrides.httpPort ?? parseInt(env.HTTP_PORT || "8443", 10);
  const cspPort = overrides.cspPort ?? parseInt(env.CSP_PORT || "5222", 10);
  const tlsEnabled = overrides.tlsEnabled ?? env.TLS_ENABLED === "true";
  const tlsPinSpki = overrides.tlsPinSpki ?? env.TLS_PIN_SPKI === "true";
  const publicOriginStatic =
    overrides.publicOriginStatic ?? env.PUBLIC_ORIGIN_STATIC === "true";

  const turnUrlsEnv = env.TURN_URLS
    ? env.TURN_URLS.split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  const tlsSansEnv = env.TLS_SANS
    ? env.TLS_SANS.split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  const cspPublicPortsEnv = env.CSP_PUBLIC_PORTS
    ? env.CSP_PUBLIC_PORTS.split(",")
        .map((s) => parseInt(s.trim(), 10))
        .filter((n) => Number.isInteger(n) && n > 0)
    : [];

  const corsAllowedOriginsEnv = env.CORS_ALLOWED_ORIGINS
    ? env.CORS_ALLOWED_ORIGINS.split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  const cspHost = overrides.cspHost ?? (env.CSP_HOST || "localhost");
  const turnPort = overrides.turnPort ?? parseInt(env.TURN_PORT || "3478", 10);
  const turnMinPort = overrides.turnMinPort ?? parseInt(env.TURN_MIN_PORT || "49152", 10);
  const turnMaxPort = overrides.turnMaxPort ?? parseInt(env.TURN_MAX_PORT || "49252", 10);

  return {
    databaseUrl:
      overrides.databaseUrl ??
      (env.DATABASE_URL ||
        "postgresql://postgres:postgres@localhost:5432/threema_onprem?schema=public"),
    host: overrides.host ?? (env.HOST || "0.0.0.0"),
    httpPort,
    cspPort,
    publicHttpOrigin:
      overrides.publicHttpOrigin ??
      (env.PUBLIC_HTTP_ORIGIN || `${tlsEnabled ? "https" : "http"}://localhost:${httpPort}`),
    publicWsOrigin:
      overrides.publicWsOrigin ??
      (env.PUBLIC_WS_ORIGIN || `${tlsEnabled ? "wss" : "ws"}://localhost:${httpPort}`),
    publicOriginStatic,
    cspHost,
    cspPublicPorts: overrides.cspPublicPorts ?? cspPublicPortsEnv,
    tlsEnabled,
    tlsCertPath: overrides.tlsCertPath ?? (env.TLS_CERT_PATH || ""),
    tlsKeyPath: overrides.tlsKeyPath ?? (env.TLS_KEY_PATH || ""),
    tlsPinSpki,
    tlsSans: overrides.tlsSans ?? tlsSansEnv,
    staticOppfPath: overrides.staticOppfPath ?? (env.STATIC_OPPF_PATH || ""),
    oppfEd25519PrivateKeyB64:
      overrides.oppfEd25519PrivateKeyB64 ?? (env.OPPF_ED25519_PRIVATE_KEY_B64 || ""),
    cspCurve25519PrivateKeyB64:
      overrides.cspCurve25519PrivateKeyB64 ?? (env.CSP_CURVE25519_PRIVATE_KEY_B64 || ""),
    licenseId: overrides.licenseId ?? (env.LICENSE_ID || "onprem-dev-001"),
    licenseExpires: overrides.licenseExpires ?? (env.LICENSE_EXPIRES || "2030-12-31"),
    licenseCount: overrides.licenseCount ?? parseInt(env.LICENSE_COUNT || "100", 10),
    orgName: overrides.orgName ?? (env.ORG_NAME || "OnPrem Organization"),
    supportText: overrides.supportText ?? (env.SUPPORT_TEXT || "support@onprem.local"),
    defaultWorkUsername: overrides.defaultWorkUsername ?? (env.DEFAULT_WORK_USERNAME || "demo"),
    defaultWorkPassword:
      overrides.defaultWorkPassword ?? (env.DEFAULT_WORK_PASSWORD || "demo-password"),
    adminApiKey: overrides.adminApiKey ?? (env.ADMIN_API_KEY || "dev-admin-key"),
    turnUrls: overrides.turnUrls ?? turnUrlsEnv,
    turnEnabled: overrides.turnEnabled ?? env.TURN_ENABLED !== "false",
    turnPort,
    turnHost: overrides.turnHost ?? (env.TURN_HOST || cspHost),
    turnExternalIp: overrides.turnExternalIp ?? (env.TURN_EXTERNAL_IP || ""),
    turnRealm: overrides.turnRealm ?? (env.TURN_REALM || "threema-onprem"),
    turnSecret: overrides.turnSecret ?? (env.TURN_SECRET || ""),
    turnMinPort,
    turnMaxPort,
    sfuBaseUrl: overrides.sfuBaseUrl ?? (env.SFU_BASE_URL || ""),
    blobStorageDir: overrides.blobStorageDir ?? (env.BLOB_STORAGE_DIR || "./data/blobs"),
    blobTtlHours: overrides.blobTtlHours ?? parsePositiveInt(env.BLOB_TTL_HOURS, 336),
    housekeepingIntervalMinutes:
      overrides.housekeepingIntervalMinutes ??
      parsePositiveInt(env.HOUSEKEEPING_INTERVAL_MINUTES, 10),
    corsAllowedOrigins: overrides.corsAllowedOrigins ?? corsAllowedOriginsEnv,
    rateLimitEnabled: overrides.rateLimitEnabled ?? env.RATE_LIMIT_ENABLED !== "false",
    rateLimitWindowMs:
      overrides.rateLimitWindowMs ?? parsePositiveInt(env.RATE_LIMIT_WINDOW_MS, 60_000),
    rateLimitMaxRequests:
      overrides.rateLimitMaxRequests ?? parsePositiveInt(env.RATE_LIMIT_MAX_REQUESTS, 240),
    remoteSecretEnabled: overrides.remoteSecretEnabled ?? env.REMOTE_SECRET_ENABLED === "true",
    logLevel: overrides.logLevel ?? (env.LOG_LEVEL || "")
  };
}
