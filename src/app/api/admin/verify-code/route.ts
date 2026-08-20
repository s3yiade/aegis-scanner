import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { verifyAdminCode, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { isSameOrigin } from '@/lib/originCheck';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const VerifySchema = z.object({ code: z.string().regex(/^\d{24}$/) });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  const clientIp = getClientIp(req.headers);
  const rl = await checkRateLimit(clientIp);
  if (!rl.allowed) {
    return NextResponse.json({ error: 'Too many attempts' }, { status: 429 });
  }

  let body: z.infer<typeof VerifySchema>;
  try {
    body = VerifySchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid code format' }, { status: 400 });
  }

  const sessionToken = await verifyAdminCode(body.code);
  if (!sessionToken) {
    return NextResponse.json({ error: 'Invalid or expired code' }, { status: 401 });
  }

  const res = NextResponse.json({ authenticated: true });
  res.cookies.set(ADMIN_SESSION_COOKIE, sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: 24 * 60 * 60,
  });
  return res;
}
