import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkDomainNowActive } from '@/lib/scanner/cloneDetection';
import { runSimilarityAnalysis } from '@/lib/scanner/similarityOrchestrator';
import { sendCloneWatchAlert } from '@/lib/email';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';
export const maxDuration = 120;

/**
 * Invoke on a schedule with Authorization: Bearer <CRON_SECRET> — same
 * Supabase-primary/Vercel-fallback pattern as api/cron/rescan (see
 * supabase/cron.sql; add a second cron.schedule() entry there for this
 * path, and a second vercel.json cron entry as fallback).
 *
 * For every paid, active watch subscription: re-checks each of the scan's
 * registered-but-dormant lookalike domains to see if any has gone live
 * since the original scan. For any that have, runs the full parallel
 * similarity analysis against the target and — if the score falls within
 * the subscriber's configured range — emails an alert with an escalate
 * link. Deactivates the subscription after firing once (this is a
 * one-time paid alert, not a recurring subscription billing model).
 */
export async function GET(req: NextRequest) {
  return handleCloneWatch(req);
}

export async function POST(req: NextRequest) {
  return handleCloneWatch(req);
}

async function handleCloneWatch(req: NextRequest) {
  if (!isValidCronAuth(req.headers.get('authorization'))) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = getSupabaseAdmin();
  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  const now = new Date();
  const staleThreshold = new Date(now.getTime() - 10 * 60 * 1000).toISOString();

  // Same atomic claim pattern as api/cron/rescan — see that file for the
  // full reasoning on why this needs to be a single UPDATE...RETURNING.
  const { data: claimed, error: claimError } = await supabase
    .from('clone_watch_subscriptions')
    .update({ is_processing: true, processing_started_at: now.toISOString() })
    .eq('active', true)
    .eq('paid', true)
    .or(`is_processing.eq.false,processing_started_at.lt.${staleThreshold}`)
    .select('*')
    .limit(50);

  if (claimError) {
    console.error('Failed to claim watch subscriptions', claimError);
    return NextResponse.json({ error: 'DB error' }, { status: 500 });
  }

  const results = { checked: 0, alerted: 0, failed: 0 };

  for (const sub of claimed ?? []) {
    try {
      const { data: scan } = await supabase
        .from('scans')
        .select('target_url, hostname, clone_candidates')
        .eq('id', sub.scan_id)
        .single();

      if (!scan) {
        await supabase.from('clone_watch_subscriptions').update({ is_processing: false, active: false }).eq('id', sub.id);
        continue;
      }

      const dormantCandidates: { domain: string; registrationStatus: string }[] = (scan.clone_candidates ?? []).filter(
        (c: { registrationStatus: string }) => c.registrationStatus === 'registered_dormant'
      );

      let fired = false;

      for (const candidate of dormantCandidates) {
        const ips = await checkDomainNowActive(candidate.domain);
        if (!ips || ips.length === 0) continue; // still dormant

        const candidateUrl = `https://${candidate.domain}`;
        const analysis = await runSimilarityAnalysis(scan.target_url, [candidateUrl]);
        const comparison = analysis.comparisons[0];
        if (!comparison) continue;

        const similarityPercent = Math.round(comparison.combinedScore * 100);
        if (similarityPercent >= sub.similarity_min && similarityPercent <= sub.similarity_max) {
          const { data: escalation } = await supabase
            .from('consult_requests')
            .insert({
              scan_id: sub.scan_id,
              email: sub.email,
              request_type: 'clone_report',
              message: `Auto-escalated: ${candidate.domain} went live at ${similarityPercent}% similarity (watch subscription).`,
            })
            .select('id')
            .single();

          await sendCloneWatchAlert({
            toEmail: sub.email,
            hostname: scan.hostname,
            cloneDomain: candidate.domain,
            similarityPercent,
            escalateUrl: `${appUrl}/report/${sub.scan_id}${escalation ? `?escalated=${escalation.id}` : ''}`,
            unsubscribeUrl: `${appUrl}/api/clone-watch?token=${sub.unsubscribe_token}`,
          });

          fired = true;
          results.alerted += 1;
          break; // one alert per subscription is enough — deactivating below
        }
      }

      await supabase
        .from('clone_watch_subscriptions')
        .update({ is_processing: false, active: !fired, last_checked_at: now.toISOString() })
        .eq('id', sub.id);

      results.checked += 1;
    } catch (err) {
      results.failed += 1;
      await supabase.from('clone_watch_subscriptions').update({ is_processing: false }).eq('id', sub.id);
      console.error(`Clone watch check failed for subscription ${sub.id}`, err);
    }
  }

  return NextResponse.json(results);
}

/** Fails closed if CRON_SECRET isn't configured (rather than matching a
 * literal "Bearer undefined" string), and compares constant-time since
 * this secret gates an endpoint that runs live scans and sends email on
 * demand. Mirrors api/cron/rescan's helper of the same name. */
function isValidCronAuth(authHeader: string | null): boolean {
  const secret = process.env.CRON_SECRET;
  if (!secret || !authHeader) return false;

  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(authHeader);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
