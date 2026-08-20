import crypto from 'node:crypto';
import { Resend } from 'resend';
import { getSupabaseAdmin } from '@/lib/supabase';

/**
 * Passwordless admin login: a 24-digit one-time code, emailed to a single
 * hardcoded ADMIN_EMAIL (never any address the caller supplies — that's
 * what makes /api/admin/request-code safe to leave unauthenticated: it
 * can't be used to spam or probe arbitrary addresses, only to trigger a
 * login attempt for the one admin identity).
 *
 * "Secured TCP handshake" for the email delivery itself is just TLS — the
 * Resend API is called over HTTPS, which *is* a secured TCP handshake
 * (TLS negotiates over the underlying TCP connection). There's no
 * additional protocol to build here; using a real email API over HTTPS
 * already satisfies this.
 *
 * "Rotates": requesting a new code immediately invalidates any previous
 * unused one (see requestAdminCode) — only the most recently issued code
 * is ever valid, and each is single-use + time-limited (10 minutes).
 *
 * The code itself is never stored in plaintext — only a salted hash,
 * checked with a constant-time comparison.
 */

const CODE_LENGTH = 24;
const CODE_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // admin session, separate from the one-time code's lifetime
export const ADMIN_SESSION_COOKIE = 'aegis_admin_session';

function getSecret(): string {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret || secret === 'change-me-to-a-long-random-string') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('ADMIN_SESSION_SECRET must be set to a real secret in production');
    }
    return 'dev-only-admin-secret';
  }
  return secret;
}

function generateNumericCode(length: number): string {
  let code = '';
  for (let i = 0; i < length; i++) code += crypto.randomInt(0, 10).toString();
  return code;
}

function hashCode(code: string): string {
  return crypto.createHmac('sha256', getSecret()).update(code).digest('hex');
}

/** Generates a new code, invalidates any previous unused code, stores only
 * the hash, and emails the plaintext code to ADMIN_EMAIL. Safe to call
 * without authentication — it never accepts a destination address, always
 * ADMIN_EMAIL from env. */
export async function requestAdminCode(): Promise<{ sent: boolean }> {
  const adminEmail = process.env.ADMIN_EMAIL;
  if (!adminEmail || !process.env.RESEND_API_KEY || !process.env.DIGEST_FROM_EMAIL) {
    throw new Error('Admin login is not configured (ADMIN_EMAIL/RESEND_API_KEY/DIGEST_FROM_EMAIL)');
  }

  const supabase = getSupabaseAdmin();
  // Rotation: invalidate every previously unused code before issuing a new
  // one, so only the most recently sent code can ever succeed.
  await supabase.from('admin_login_codes').update({ used: true }).eq('used', false);
  // Housekeeping: this table is tiny and login attempts are rare, but there's
  // no reason to let used/expired rows accumulate forever — piggyback the
  // cleanup on the one write path that already touches this table.
  await supabase.from('admin_login_codes').delete().or(`used.eq.true,expires_at.lt.${new Date().toISOString()}`);

  const code = generateNumericCode(CODE_LENGTH);
  const expiresAt = new Date(Date.now() + CODE_TTL_MS).toISOString();

  const { error } = await supabase.from('admin_login_codes').insert({ code_hash: hashCode(code), expires_at: expiresAt });
  if (error) throw error;

  const resend = new Resend(process.env.RESEND_API_KEY);
  const { error: sendError } = await resend.emails.send({
    from: process.env.DIGEST_FROM_EMAIL,
    to: adminEmail,
    subject: 'Your Aegis admin login code',
    text: `Your one-time admin login code (valid for 10 minutes):\n\n${code}\n\nIf you didn't request this, ignore it — the code expires on its own and nothing happens without it.`,
  });
  // Resend's SDK does not throw on API-level failures (unverified sending
  // domain, rejected recipient, etc.) — it resolves with { error } instead.
  // Without this check, a rejected send still reported { sent: true } to
  // the caller with nothing ever arriving in the inbox.
  if (sendError) throw new Error(`Resend rejected the admin login code email: ${sendError.message}`);

  return { sent: true };
}

/** Verifies a submitted code against the most recent unused, unexpired
 * hash — constant-time comparison, marks it used on success so it can
 * never be replayed. Returns a signed session token on success. */
export async function verifyAdminCode(submittedCode: string): Promise<string | null> {
  if (!/^\d{24}$/.test(submittedCode)) return null;

  const supabase = getSupabaseAdmin();
  const { data: candidates } = await supabase
    .from('admin_login_codes')
    .select('id, code_hash, expires_at, used')
    .eq('used', false)
    .gte('expires_at', new Date().toISOString())
    .order('created_at', { ascending: false })
    .limit(1);

  const candidate = candidates?.[0];
  if (!candidate) return null;

  const submittedHash = hashCode(submittedCode);
  const a = Buffer.from(submittedHash);
  const b = Buffer.from(candidate.code_hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  await supabase.from('admin_login_codes').update({ used: true }).eq('id', candidate.id);

  return createSessionToken();
}

function createSessionToken(): string {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = Buffer.from(JSON.stringify({ expiresAt })).toString('base64url');
  const sig = crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

/** Verifies a session token from the admin session cookie. */
export function verifyAdminSession(token: string | undefined | null): boolean {
  if (!token) return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;

  const expectedSig = crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  try {
    const { expiresAt } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return Date.now() < expiresAt;
  } catch {
    return false;
  }
}

/** Convenience wrapper for route handlers — reads the session cookie from
 * a request and verifies it in one call. isAdmin supersedes every other
 * gate (captcha, rate limit, disposable-email checks, and payment) across
 * every route that checks it — see each route's own comments for exactly
 * what it bypasses there. Origin/CSRF checking is deliberately NOT
 * bypassed for admin sessions — a forged cross-site request riding on the
 * admin's own authenticated cookie is exactly the scenario Origin
 * checking exists to catch, so admin status should never weaken it.
 */
export function isAdminRequest(req: { cookies: { get(name: string): { value: string } | undefined } }): boolean {
  return verifyAdminSession(req.cookies.get(ADMIN_SESSION_COOKIE)?.value);
}
