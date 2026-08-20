import { Redis } from '@upstash/redis';

const hasRedis = Boolean(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);

let client: Redis | null = null;
if (hasRedis) {
  client = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL!,
    token: process.env.UPSTASH_REDIS_REST_TOKEN!,
  });
}

/** Returns the shared Upstash client, or null when Redis isn't configured
 * (local dev) — every caller is expected to fall back to an in-memory
 * strategy in that case, same pattern as lib/ratelimit.ts. */
export function getRedis(): Redis | null {
  return client;
}
