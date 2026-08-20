import { NextRequest, NextResponse } from 'next/server';
import { verifyAdminSession, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';
import { getSupabaseAdmin } from '@/lib/supabase';
import { getClientIp, hashIp } from '@/lib/ratelimit';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

/** Lists past scans for the admin dashboard. `scope=mine` (default)
 * filters to scans whose recorded IP hash matches the admin's current
 * request IP — i.e. your own test scans. `scope=all` shows every scan
 * (useful for reviewing real prospect activity, not just your own). */
export async function GET(req: NextRequest) {
  const session = req.cookies.get(ADMIN_SESSION_COOKIE)?.value;
  if (!verifyAdminSession(session)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const scope = req.nextUrl.searchParams.get('scope') === 'all' ? 'all' : 'mine';
  const supabase = getSupabaseAdmin();

  let query = supabase
    .from('scans')
    .select('id, hostname, target_url, score, grade, scanned_at, clone_candidate_count')
    .order('scanned_at', { ascending: false })
    .limit(100);

  if (scope === 'mine') {
    const myIpHash = hashIp(getClientIp(req.headers));
    query = query.eq('ip_address', myIpHash);
  }

  const { data, error } = await query;
  if (error) {
    return NextResponse.json({ error: 'Failed to load scans' }, { status: 500 });
  }

  return NextResponse.json({ scans: data, scope });
}
