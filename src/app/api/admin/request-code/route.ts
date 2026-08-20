import { NextRequest, NextResponse } from 'next/server';
import { requestAdminCode } from '@/lib/adminAuth';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { isSameOrigin } from '@/lib/originCheck';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

/** Unauthenticated by design (you don't have a session yet — that's the
 * point of this route) but safe: it never accepts a destination address,
 * only ever emails the single hardcoded ADMIN_EMAIL. Rate-limited to stop
 * someone spamming the admin's inbox with login-code emails. */
export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  const clientIp = getClientIp(req.headers);
  const rl = await checkRateLimit(clientIp);
  if (!rl.allowed) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  }

  try {
    await requestAdminCode();
    return NextResponse.json({ sent: true });
  } catch (err) {
    console.error('Admin code request failed', err);
    return NextResponse.json({ error: 'Could not send login code. Check ADMIN_EMAIL/RESEND_API_KEY configuration.' }, { status: 500 });
  }
}
