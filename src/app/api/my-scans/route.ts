import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkRateLimit, checkEmailRateLimit, getClientIp } from '@/lib/ratelimit';
import { verifyCaptcha, CaptchaInputSchema } from '@/lib/captcha';
import { isSameOrigin } from '@/lib/originCheck';
import { isAdminRequest } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const MyScansSchema = z.object({
  email: z.string().trim().email().max(320),
  captcha: CaptchaInputSchema,
});

const MAX_RESULTS = 50;

/**
 * Given an email, returns the domains that email has previously unlocked
 * a report for — i.e. every scan with a matching row in `leads`. This is
 * a convenience lookup, not a new access grant: `/api/report/[id]` is
 * still gated purely by possession of the scanId link plus "at least one
 * lead exists for this scan" (see that route) — the same trust level any
 * of these scanIds already carry. This endpoint just helps someone find
 * links they already have rights to, without them having to keep the
 * original unlock email around.
 *
 * Scoped strictly to that one email's own domains: an account here isn't
 * "one email owns everything" — someone can (and reasonably will) scan
 * several domains from the same email, or the same domain from several
 * emails. Every scan this returns is tied to the exact email submitted,
 * nothing broader. Any paid feature (fix guide, consult, clone watch) is
 * a separate purchase scoped to the individual scanId regardless of what
 * shows up here — this list is purely "which reports can I get back to",
 * not an entitlements list.
 *
 * Because an email is far lower-entropy than a scanId (guessable/
 * enumerable, unlike a UUID), this is hardened harder than a typical
 * lead-capture endpoint:
 *   - its own dedicated, tighter Redis-backed rate-limit bucket ("lookup"
 *     — see lib/ratelimit.ts) instead of sharing the scan/lead/monitor/
 *     consult pool, so it can't be tightened or loosened by traffic on
 *     those and vice versa;
 *   - a SECOND limiter keyed on the hashed email itself, not just the
 *     caller's IP — caps how many times any single email can be looked
 *     up per day regardless of how many IPs try it, which plain IP
 *     limiting can't do;
 *   - captcha (Turnstile primary / self-hosted PoW fallback — see
 *     lib/captcha.ts) same as every other public write/read endpoint.
 * It only ever returns metadata (hostname/score/grade/date), never
 * findings or fix procedures, even though it's hardened as if it were
 * more sensitive than that.
 */
export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  let body: z.infer<typeof MyScansSchema>;
  try {
    body = MyScansSchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }

  const isAdmin = isAdminRequest(req);
  const clientIp = getClientIp(req.headers);

  if (!isAdmin) {
    const [ipLimit, emailLimit] = await Promise.all([
      checkRateLimit(clientIp, 'lookup'),
      checkEmailRateLimit(body.email, 'lookup'),
    ]);
    if (!ipLimit.allowed || !emailLimit.allowed) {
      return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
    }

    const captchaOk = await verifyCaptcha({ ...body.captcha, clientIp });
    if (!captchaOk) {
      return NextResponse.json({ error: 'Captcha verification failed' }, { status: 400 });
    }
  }

  const supabase = getSupabaseAdmin();

  const { data: leadRows, error: leadError } = await supabase
    .from('leads')
    .select('scan_id, created_at')
    .eq('email', body.email)
    .order('created_at', { ascending: false })
    .limit(MAX_RESULTS);

  if (leadError) {
    console.error('Failed to look up leads for my-scans', leadError);
    return NextResponse.json({ error: 'Could not load your scans. Please try again.' }, { status: 500 });
  }

  const scanIds = Array.from(new Set((leadRows ?? []).map((r) => r.scan_id).filter(Boolean)));
  if (scanIds.length === 0) {
    return NextResponse.json({ scans: [] });
  }

  const { data: scans, error: scanError } = await supabase
    .from('scans')
    .select('id, hostname, target_url, score, grade, scanned_at, clone_candidate_count')
    .in('id', scanIds)
    .order('scanned_at', { ascending: false });

  if (scanError) {
    console.error('Failed to load scans for my-scans', scanError);
    return NextResponse.json({ error: 'Could not load your scans. Please try again.' }, { status: 500 });
  }

  return NextResponse.json({ scans: scans ?? [] });
}
