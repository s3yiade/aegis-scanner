import { NextRequest, NextResponse } from 'next/server';
import { generateSelfChallenge, captchaProvider } from '@/lib/captcha';
import { getClientIp } from '@/lib/ratelimit';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

/** Issues captcha setup info for whichever provider is active. Shared by
 * every form that needs one (scan, lead-unlock, monitor signup, consult,
 * clone watch, my-scans lookup) so each gated action gets its own
 * proof-of-interaction rather than relying on one solved at page load.
 *
 * For "turnstile" (primary in production), this just hands back the
 * public site key so the client can render Cloudflare's widget — no
 * server-side state, Cloudflare owns verification.
 *
 * For "self" (zero-config fallback), the challenge token is bound to the
 * requesting IP, so it's generated here where that IP is available. */
export async function GET(req: NextRequest) {
  if (captchaProvider !== 'self') {
    return NextResponse.json({ provider: captchaProvider, siteKey: process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY ?? null });
  }
  const clientIp = getClientIp(req.headers);
  return NextResponse.json({ provider: 'self', ...generateSelfChallenge(clientIp) });
}
