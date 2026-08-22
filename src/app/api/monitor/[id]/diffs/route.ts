import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/**
 * Diff history for a Pro-tier monitor, linked from every diff alert email
 * (see lib/email.ts sendMonitorDiffAlert) and from the report page's
 * "View diff history" link once monitoring is active.
 *
 * Reuses monitors.unsubscribe_token as a view-access token rather than
 * introducing a separate auth system — this app has no user accounts
 * anywhere (every paid/recurring feature is email-link-based, see the
 * monitor unsubscribe flow, the badge route, etc.), and diff-history data
 * is low-stakes (security posture summaries, not credentials), so a
 * possession-of-the-emailed-link model is consistent with the rest of the
 * app rather than a special case. The token itself is a v4 UUID (122 bits
 * of entropy), so brute-forcing it isn't realistic — the rate limit below
 * is defense-in-depth against DB-load abuse, not the primary control.
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const clientIp = getClientIp(req.headers);
  const rl = await checkRateLimit(clientIp, 'lookup');
  if (!rl.allowed) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  }

  const { id } = await params;
  const token = req.nextUrl.searchParams.get('token');
  if (!token) return NextResponse.json({ error: 'Missing token' }, { status: 400 });

  const supabase = getSupabaseAdmin();
  const { data: monitor, error: monitorError } = await supabase
    .from('monitors')
    .select('id, hostname, target_url, tier, frequency, active, last_score, pro_activated_at')
    .eq('id', id)
    .eq('unsubscribe_token', token)
    .maybeSingle();

  if (monitorError || !monitor) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  if (monitor.tier !== 'pro') {
    return NextResponse.json({ error: 'Diff history is a Pro monitoring feature.' }, { status: 403 });
  }

  const { data: diffs, error: diffsError } = await supabase
    .from('monitor_diffs')
    .select('id, previous_scan_id, new_scan_id, score_delta, added_findings, resolved_findings, changed_findings, created_at')
    .eq('monitor_id', monitor.id)
    .order('created_at', { ascending: false })
    .limit(50);

  if (diffsError) {
    return NextResponse.json({ error: 'Could not load diff history.' }, { status: 500 });
  }

  return NextResponse.json({
    monitor: {
      hostname: monitor.hostname,
      targetUrl: monitor.target_url,
      frequency: monitor.frequency,
      active: monitor.active,
      lastScore: monitor.last_score,
      proActivatedAt: monitor.pro_activated_at,
    },
    diffs: (diffs ?? []).map((d) => ({
      id: d.id,
      newScanId: d.new_scan_id,
      scoreDelta: d.score_delta,
      added: d.added_findings,
      resolved: d.resolved_findings,
      changed: d.changed_findings,
      createdAt: d.created_at,
    })),
  });
}
