import type express from "express";

export interface RateLimitOptions {
  enabled: boolean;
  windowMs: number;
  maxRequests: number;
  keyPrefix?: string;
}

interface Bucket {
  timestamps: number[];
}

const MAX_TRACKED_KEYS = 10_000;

function extractClientIp(req: express.Request): string {
  const cfIp = req.header("cf-connecting-ip")?.trim();
  if (cfIp) return cfIp;
  const xff = req.header("x-forwarded-for")?.split(",")[0]?.trim();
  if (xff) return xff;
  return req.ip || req.socket.remoteAddress || "unknown";
}

/**
 * Lightweight in-memory sliding-window rate limiter with lazy pruning and bounded key table
 * (no background timers required).
 */
export function createRateLimiter(opts: RateLimitOptions): express.RequestHandler {
  const buckets = new Map<string, Bucket>();

  return (req, res, next) => {
    if (!opts.enabled || opts.maxRequests <= 0 || opts.windowMs <= 0) {
      next();
      return;
    }

    const now = Date.now();
    const cutoff = now - opts.windowMs;
    const key = `${opts.keyPrefix ?? "rl"}:${extractClientIp(req)}`;

    let bucket = buckets.get(key);
    if (bucket) {
      bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);
      // Refresh LRU insertion order
      buckets.delete(key);
      buckets.set(key, bucket);
    } else {
      if (buckets.size >= MAX_TRACKED_KEYS) {
        const oldestKey = buckets.keys().next().value;
        if (oldestKey !== undefined) {
          buckets.delete(oldestKey);
        }
      }
      bucket = { timestamps: [] };
      buckets.set(key, bucket);
    }

    if (bucket.timestamps.length >= opts.maxRequests) {
      const retryAfterSec = Math.max(
        1,
        Math.ceil((bucket.timestamps[0] + opts.windowMs - now) / 1000)
      );
      res.setHeader("Retry-After", String(retryAfterSec));
      res.status(429).json({
        success: false,
        error: "Rate limit exceeded"
      });
      return;
    }

    bucket.timestamps.push(now);
    next();
  };
}
