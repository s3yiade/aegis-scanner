import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Unsubscribe from a dormant-domain watch, linked from clone-watch alert
 * emails. GET because email links always navigate via GET — same reasoning
 * as the monitors unsubscribe endpoint. */
export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get('token');
  if (!token) return NextResponse.json({ error: 'Missing token' }, { status: 400 });

  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from('clone_watch_subscriptions')
    .update({ active: false })
    .eq('unsubscribe_token', token)
    .select('hostname')
    .maybeSingle();

  if (error || !data) {
    return new NextResponse(
      '<html><body style="font-family: sans-serif; padding: 40px;">Invalid or expired unsubscribe link.</body></html>',
      { status: 400, headers: { 'Content-Type': 'text/html' } }
    );
  }

  return new NextResponse(
    `<html><body style="font-family: sans-serif; padding: 40px;">You've been unsubscribed from clone-domain watching for <strong>${escapeHtml(data.hostname)}</strong>.</body></html>`,
    { headers: { 'Content-Type': 'text/html' } }
  );
}
