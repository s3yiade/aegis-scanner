import { NextResponse } from 'next/server';
import { ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

export async function POST() {
  const res = NextResponse.json({ loggedOut: true });
  res.cookies.set(ADMIN_SESSION_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'strict', path: '/', maxAge: 0 });
  return res;
}
