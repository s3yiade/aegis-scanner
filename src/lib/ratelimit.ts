import { Ratelimit } from '@upstash/ratelimit';
import crypto from 'node:crypto';
import { getRedis } from '@/lib/redis';

/**
 * Named rate-limit buckets, each with its own hourly + daily cap. Routes
 * pick a bucket by what they're actually protecting:
 *
 *   - "scan" (default): the original shared bucket. scan/lead/monitor/
 *     consult/checkout intentionally all draw from this one pool so none
 *     of them can be used to sidestep the others' abuse controls.
 *   - "lookup": dedicated, tighter bucket for /api/my-scans. Deliberately
 *     separate from "scan" so looking up your own scan history doesn't
 *     eat into someone's scan quota — but tighter than "scan" because the
 *     key being guessed (an email) is far lower-entropy than a scan
 *     target, so it's worth capping harder against enumeration.
 *
 * Uses Upstash Redis when configured (required for serverless deployments
 * where instances don't share memory); falls back to an in-process Map for
 * local dev, which is NOT safe for a multi-instance production deployment.
 */

interface BucketConfig {
  hourlyLimit: number;
  dailyLimit: number;
}

const BUCKETS: Record<string, BucketConfig> = {
  scan: { hourlyLimit: 5, dailyLimit: 20 },
  lookup: { hourlyLimit: 8, dailyLimit: 25 },
};

export type RateLimitBucket = keyof typeof BUCKETS;

const redis = getRedis();

const hourlyLimiters = new Map<string, Ratelimit>();
const dailyLimiters = new Map<string, Ratelimit>();

function getLimiters(bucket: RateLimitBucket): { hourly: Ratelimit; daily: Ratelimit } | null {
  if (!redis) return null;
  if (!hourlyLimiters.has(bucket)) {
    const cfg = BUCKETS[bucket];
    hourlyLimiters.set(
      bucket,
      new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(cfg.hourlyLimit, '1 h'), prefix: `aegis:rl:${bucket}:hour` })
    );
    dailyLimiters.set(
      bucket,
      new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(cfg.dailyLimit, '1 d'), prefix: `aegis:rl:${bucket}:day` })
    );
  }
  return { hourly: hourlyLimiters.get(bucket)!, daily: dailyLimiters.get(bucket)! };
}

// --- In-memory fallback (dev only) ---
const memoryStores = new Map<string, Map<string, number[]>>();

function memoryStore(bucket: string, window: 'hour' | 'day'): Map<string, number[]> {
  const key = `${bucket}:${window}`;
  if (!memoryStores.has(key)) memoryStores.set(key, new Map());
  return memoryStores.get(key)!;
}

function checkMemory(store: Map<string, number[]>, key: string, limit: number, windowMs: number) {
  const now = Date.now();
  const timestamps = (store.get(key) ?? []).filter((t) => now - t < windowMs);
  const success = timestamps.length < limit;
  if (success) timestamps.push(now);
  store.set(key, timestamps);
  return { success, remaining: Math.max(0, limit - timestamps.length) };
}

/** Hashes an identifier (IP or email) before it's ever logged or stored. */
export function hashIp(ip: string): string {
  const salt = process.env.CAPTCHA_HMAC_SECRET || 'dev-only-salt';
  return crypto.createHmac('sha256', salt).update(ip).digest('hex').slice(0, 32);
}
export const hashIdentifier = hashIp;

export interface RateLimitDecision {
  allowed: boolean;
  reason?: 'hourly' | 'daily';
  remainingHourly: number;
  remainingDaily: number;
}

export async function checkRateLimit(ip: string, bucket: RateLimitBucket = 'scan'): Promise<RateLimitDecision> {
  const cfg = BUCKETS[bucket];
  const key = hashIdentifier(`${bucket}:${ip}`);
  const limiters = getLimiters(bucket);

  if (limiters) {
    try {
      const [hourly, daily] = await Promise.all([limiters.hourly.limit(key), limiters.daily.limit(key)]);
      if (!daily.success) {
        return { allowed: false, reason: 'daily', remainingHourly: hourly.remaining, remainingDaily: 0 };
      }
      if (!hourly.success) {
        return { allowed: false, reason: 'hourly', remainingHourly: 0, remainingDaily: daily.remaining };
      }
      return { allowed: true, remainingHourly: hourly.remaining, remainingDaily: daily.remaining };
    } catch (err) {
      // Upstash unreachable/misconfigured shouldn't take the whole endpoint
      // down — fall through to the in-memory limiter below rather than
      // letting this throw bubble up as an unhandled 500. This makes the
      // outage a quieter, temporary loosening of the rate limit (each
      // serverless instance gets its own counter) instead of a hard
      // failure for every visitor.
      console.error(`Upstash rate limiter unreachable for bucket "${bucket}", falling back to in-memory limiting`, err);
    }
  }

  // In-memory fallback
  const hourly = checkMemory(memoryStore(bucket, 'hour'), key, cfg.hourlyLimit, 60 * 60 * 1000);
  const daily = checkMemory(memoryStore(bucket, 'day'), key, cfg.dailyLimit, 24 * 60 * 60 * 1000);
  if (!daily.success) {
    return { allowed: false, reason: 'daily', remainingHourly: hourly.remaining, remainingDaily: 0 };
  }
  if (!hourly.success) {
    return { allowed: false, reason: 'hourly', remainingHourly: 0, remainingDaily: daily.remaining };
  }
  return { allowed: true, remainingHourly: hourly.remaining, remainingDaily: daily.remaining };
}

/**
 * Secondary limiter keyed by (normalized, hashed) email rather than IP —
 * specifically for /api/my-scans. IP-based limiting alone caps how many
 * emails one IP can try; it doesn't cap how many times a single email can
 * be looked up if an attacker rotates IPs. This closes that gap: a given
 * email can only be looked up a handful of times a day regardless of
 * which IP is asking.
 */
export async function checkEmailRateLimit(email: string, bucket: RateLimitBucket = 'lookup'): Promise<RateLimitDecision> {
  return checkRateLimit(`email:${email.trim().toLowerCase()}`, bucket);
}

/** Extracts the caller's IP from standard proxy headers (Vercel/most PaaS). */
export function getClientIp(headers: Headers): string {
  const forwarded = headers.get('x-forwarded-for');
  if (forwarded) return (forwarded.split(',')[0] ?? forwarded).trim();
  const realIp = headers.get('x-real-ip');
  if (realIp) return realIp;
  return '0.0.0.0';
}
