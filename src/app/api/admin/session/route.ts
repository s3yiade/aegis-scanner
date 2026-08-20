import { NextRequest, NextResponse } from 'next/server';
import { verifyAdminSession, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

/**
 * Lets client-side JS learn "am I an authenticated admin?" without ever
 * reading the session cookie itself (it's httpOnly by design — that's
 * what stops XSS from stealing it, so it must stay unreadable to JS).
 *
 * This route is the safe indirection: the browser can't inspect the
 * cookie, but it CAN ask the server to check it and report back a single
 * boolean (+ the admin's own configured email, so forms can prefill it
 * instead of the admin re-typing it every time — that's not a leak,
 * since it's only ever returned to a request that already proved it holds
 * a valid admin session).
 *
 * Deliberately returns only `{ isAdmin, email }` — never findings, scan
 * data, or anything else — so this route can be called freely from any
 * page on mount without becoming a data-exposure surface itself. No rate
 * limit needed: worst case is a session-validity check, which is cheap
 * and reveals nothing to a non-admin caller beyond "you are not admin".
 */
export async function GET(req: NextRequest) {
  const isAdmin = verifyAdminSession(req.cookies.get(ADMIN_SESSION_COOKIE)?.value);
  if (!isAdmin) {
    return NextResponse.json({ isAdmin: false });
  }
  return NextResponse.json({ isAdmin: true, email: process.env.ADMIN_EMAIL ?? null });
}
