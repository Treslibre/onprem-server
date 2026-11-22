export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 50
};

export function resolveLogLevel(explicit?: string): LogLevel {
  const raw = (explicit ?? process.env.LOG_LEVEL ?? "").trim().toLowerCase();
  if (raw === "debug" || raw === "info" || raw === "warn" || raw === "error" || raw === "silent") {
    return raw;
  }
  if (process.env.LOG_REQUESTS === "false") {
    return "warn";
  }
  return "info";
}

export interface Logger {
  debug: (msg: string) => void;
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
}

export function createLogger(component: string, explicitLevel?: string): Logger {
  const shouldLog = (target: LogLevel): boolean => {
    const active = resolveLogLevel(explicitLevel);
    return LEVEL_RANK[target] >= LEVEL_RANK[active];
  };

  const format = (msg: string): string => `${new Date().toISOString()} [${component}] ${msg}`;

  return {
    debug: (msg) => {
      if (shouldLog("debug")) console.debug(format(msg));
    },
    info: (msg) => {
      if (shouldLog("info")) console.log(format(msg));
    },
    warn: (msg) => {
      if (shouldLog("warn")) console.warn(format(msg));
    },
    error: (msg) => {
      if (shouldLog("error")) console.error(format(msg));
    }
  };
}
