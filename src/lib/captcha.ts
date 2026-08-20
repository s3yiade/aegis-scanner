import crypto from 'node:crypto';
import { z } from 'zod';
import { getRedis } from '@/lib/redis';

/**
 * Two captcha modes:
 *
 *  - "turnstile" (primary): Cloudflare Turnstile — real bot detection,
 *    free, privacy-respecting. Selected automatically as soon as
 *    TURNSTILE_SECRET_KEY and NEXT_PUBLIC_TURNSTILE_SITE_KEY are both
 *    set; this is what should be running in production.
 *
 *  - "self" (fallback, zero config): used only when Turnstile isn't
 *    configured, so local dev and fresh deploys still work out of the
 *    box. Upgraded from a single two-operand sum/product to:
 *      - a 3-term expression (wider answer distribution, harder to
 *        blind-guess than a 1-in-~40 arithmetic problem),
 *      - a small proof-of-work the client must solve (cheap — tens of
 *        milliseconds in a browser — but turns "script one HTTP request
 *        per guess" into real, non-trivial compute per attempt, which is
 *        the actual point of a self-hosted fallback captcha),
 *      - bound to the requesting IP and single-use, so a solved token
 *        can't be farmed once and replayed from many bot IPs.
 *    It still won't stop a determined scripted attacker the way Turnstile
 *    does — it raises the floor for the zero-config path, it isn't a
 *    substitute for actually enabling Turnstile before a public launch.
 */

const explicitProvider = process.env.CAPTCHA_PROVIDER;
const turnstileConfigured = Boolean(process.env.TURNSTILE_SECRET_KEY && process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY);

const provider: 'self' | 'turnstile' =
  explicitProvider === 'self' ? 'self' : explicitProvider === 'turnstile' || turnstileConfigured ? 'turnstile' : 'self';

export const captchaProvider = provider;

function getSecret(): string {
  const secret = process.env.CAPTCHA_HMAC_SECRET;
  if (!secret || secret === 'change-me-to-a-long-random-string') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('CAPTCHA_HMAC_SECRET must be set to a real secret in production');
    }
    return 'dev-only-secret';
  }
  return secret;
}

/** Shared zod fragment for the captcha portion of a request body — import
 * this in every route instead of redeclaring the shape, so a future field
 * (like selfPowNonce below) only needs to be added once. */
export const CaptchaInputSchema = z.object({
  selfToken: z.string().optional(),
  selfAnswer: z.number().optional(),
  selfPowNonce: z.string().optional(),
  turnstileToken: z.string().optional(),
});
export type CaptchaInput = z.infer<typeof CaptchaInputSchema>;

export interface SelfChallenge {
  question: string;
  token: string; // signed: base64(payload).hmac
  powDifficulty: number; // required leading zero bits of sha256(token + ':' + nonce)
}

const POW_DIFFICULTY_BITS = 14; // ~ a few thousand hashes on average, sub-second client-side
const CHALLENGE_TTL_MS = 3 * 60 * 1000;

/** Builds a 3-term expression (e.g. "(6 + 9) * 3 - 4 = ?") that's evaluated
 * strictly left-to-right in the order shown, so the displayed parentheses
 * always match how the answer was actually computed. Operands and the
 * running total are kept non-negative and within a sane range. */
function buildExpression(): { question: string; answer: number } {
  const a = crypto.randomInt(3, 25);
  const b = crypto.randomInt(3, 25);
  const c = crypto.randomInt(3, 25);
  const ops = ['+', '-', '*'] as const;
  const op1 = ops[crypto.randomInt(0, ops.length)];
  const op2 = ops[crypto.randomInt(0, ops.length)];

  function apply(x: number, op: (typeof ops)[number], y: number): number {
    if (op === '+') return x + y;
    if (op === '*') return x * y;
    return x - y; // '-'
  }

  // Avoid negative intermediate/final results — flip subtraction to
  // addition rather than reject-and-retry, keeps generation O(1).
  const usedOp1 = op1 === '-' && a - b < 0 ? '+' : op1;
  const step1 = apply(a, usedOp1, b);

  const usedOp2 = op2 === '-' && step1 - c < 0 ? '+' : op2;
  const final = apply(step1, usedOp2, c);

  return {
    question: `(${a} ${usedOp1} ${b}) ${usedOp2} ${c} = ?`,
    answer: final,
  };
}

export function generateSelfChallenge(clientIp: string): SelfChallenge {
  const { question, answer } = buildExpression();
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;

  const payload = JSON.stringify({
    answer,
    expiresAt,
    ipHash: hashForToken(clientIp),
    nonce: crypto.randomBytes(8).toString('hex'),
  });
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', getSecret()).update(payloadB64).digest('base64url');

  return {
    question,
    token: `${payloadB64}.${sig}`,
    powDifficulty: POW_DIFFICULTY_BITS,
  };
}

function hashForToken(value: string): string {
  return crypto.createHmac('sha256', getSecret()).update(value).digest('hex');
}

function hasLeadingZeroBits(buf: Buffer, bits: number): boolean {
  let remaining = bits;
  for (const byte of buf) {
    if (remaining <= 0) break;
    if (remaining >= 8) {
      if (byte !== 0) return false;
      remaining -= 8;
    } else {
      if (byte >> (8 - remaining) !== 0) return false;
      remaining = 0;
    }
  }
  return true;
}

// Marks a token signature as spent so it can't be answered twice — closes
// the gap where the old design let one solved token be retried forever.
// Redis-backed (shared across serverless instances) with an in-memory
// fallback for local dev only.
const memoryUsedTokens = new Map<string, number>();

async function markTokenUsed(sig: string, ttlMs: number): Promise<boolean> {
  const redis = getRedis();
  if (redis) {
    try {
      // NX = only set if not already present -> atomic "claim" of this token.
      const ok = await redis.set(`aegis:captcha:used:${sig}`, '1', { nx: true, px: Math.max(ttlMs, 1000) });
      return ok === 'OK' || ok === true;
    } catch (err) {
      // Same resilience pattern as lib/ratelimit.ts: a misconfigured or
      // permission-restricted Redis token (e.g. missing SET/SCRIPT) must
      // not crash the whole captcha check — fall through to the
      // in-memory fallback below rather than letting this throw bubble up
      // as an unhandled 500 for every visitor.
      console.error('Upstash unreachable for captcha token tracking, falling back to in-memory tracking', err);
    }
  }
  const now = Date.now();
  for (const [k, exp] of memoryUsedTokens) if (exp < now) memoryUsedTokens.delete(k);
  if (memoryUsedTokens.has(sig)) return false;
  memoryUsedTokens.set(sig, now + ttlMs);
  return true;
}

async function verifySelfChallenge(
  token: string,
  userAnswer: number,
  powNonce: string | undefined,
  clientIp: string
): Promise<boolean> {
  const [payloadB64, sig] = token.split('.');
  if (!payloadB64 || !sig) return false;

  const expectedSig = crypto.createHmac('sha256', getSecret()).update(payloadB64).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  let answer: number, expiresAt: number, ipHash: string;
  try {
    ({ answer, expiresAt, ipHash } = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()));
  } catch {
    return false;
  }

  if (Date.now() > expiresAt) return false;
  if (ipHash !== hashForToken(clientIp)) return false; // solved-elsewhere token replay
  if (answer !== userAnswer) return false;

  if (!powNonce) return false;
  const digest = crypto.createHash('sha256').update(`${token}:${powNonce}`).digest();
  if (!hasLeadingZeroBits(digest, POW_DIFFICULTY_BITS)) return false;

  // Single-use: claim the token only once every other check has passed,
  // so a wrong guess doesn't burn the (still-valid) token.
  const remainingTtl = expiresAt - Date.now();
  return markTokenUsed(sig, remainingTtl);
}

async function verifyTurnstile(responseToken: string, remoteIp: string): Promise<boolean> {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) throw new Error('TURNSTILE_SECRET_KEY not configured');

  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret, response: responseToken, remoteip: remoteIp }),
  });
  const data = await res.json();
  return Boolean(data.success);
}

export async function verifyCaptcha(input: CaptchaInput & { clientIp: string }): Promise<boolean> {
  if (provider === 'turnstile') {
    if (!input.turnstileToken) return false;
    return verifyTurnstile(input.turnstileToken, input.clientIp);
  }
  if (!input.selfToken || input.selfAnswer === undefined) return false;
  return verifySelfChallenge(input.selfToken, input.selfAnswer, input.selfPowNonce, input.clientIp);
}
