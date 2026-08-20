import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { getSupabaseAdmin } from '@/lib/supabase';
import { runScan } from '@/lib/scanner';
import { sendMonitorAlert } from '@/lib/email';
import { refreshNicheBenchmark } from '@/lib/scanner/benchmark';
import { SSRFBlockedError } from '@/lib/ssrfGuard';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';
export const maxDuration = 300; // allow room for many sequential scans

/**
 * Invoke on a schedule with:
 *   Authorization: Bearer <CRON_SECRET>
 *
 * Supabase pg_cron (see supabase/cron.sql) is the primary scheduler, hourly.
 * Vercel Cron (vercel.json) stays configured against the same endpoint as a
 * fallback in case pg_cron/pg_net has an outage or the Supabase project is
 * paused. Safe to trigger from both — see the is_processing claim-lock
 * below, which ensures only one trigger actually processes a given due
 * monitor even if both fire close together.
 *
 * For every claimed monitor:
 *   1. Re-scan the target.
 *   2. Store the new scan row (this doubles as the "since your last scan"
 *      history — Part 3 idea #2 — since scans.hostname lets you pull every
 *      prior scan for a domain and diff scores over time).
 *   3. Email the subscriber if the score changed.
 *   4. Advance next_run_at and release the claim.
 * Also refreshes niche benchmark aggregates once per run.
 */
// Vercel Cron issues GET requests with the Authorization header auto-attached
// from CRON_SECRET; POST is kept too for manual/external cron triggers.
export async function GET(req: NextRequest) {
  return handleRescan(req);
}

export async function POST(req: NextRequest) {
  return handleRescan(req);
}

async function handleRescan(req: NextRequest) {
  if (!isValidCronAuth(req.headers.get('authorization'))) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = getSupabaseAdmin();
  const appUrl = process.env.APP_URL || 'http://localhost:3000';

  // Atomic claim: Supabase (primary) and Vercel (fallback) can both trigger
  // this endpoint, sometimes within seconds of each other. A single
  // UPDATE...RETURNING (what supabase-js sends for .update().select()) is
  // how we make sure only one of the two triggers actually claims each due
  // monitor — the second request's WHERE clause re-evaluates after the
  // first commits and no longer matches the now-claimed rows.
  // A lock older than 10 minutes is treated as stale (a prior run crashed
  // mid-flight) and is eligible to be reclaimed rather than stuck forever.
  const now = new Date();
  const staleThreshold = new Date(now.getTime() - 10 * 60 * 1000).toISOString();

  const { data: claimedMonitors, error: claimError } = await supabase
    .from('monitors')
    .update({ is_processing: true, processing_started_at: now.toISOString() })
    .eq('active', true)
    .lte('next_run_at', now.toISOString())
    .or(`is_processing.eq.false,processing_started_at.lt.${staleThreshold}`)
    .select('*')
    .limit(200); // cap per invocation; cron runs frequently enough to drain a backlog

  if (claimError) {
    console.error('Failed to claim monitors', claimError);
    return NextResponse.json({ error: 'DB error' }, { status: 500 });
  }

  const results = { processed: 0, alerted: 0, failed: 0 };

  for (const monitor of claimedMonitors ?? []) {
    try {
      const scanResult = await runScan({ targetUrl: monitor.target_url });

      const { data: inserted } = await supabase
        .from('scans')
        .insert({
          target_url: scanResult.targetUrl,
          hostname: scanResult.hostname,
          target_type: scanResult.targetType,
          score: scanResult.score,
          grade: scanResult.grade,
          findings: scanResult.findings,
          niche: null,
          clone_candidates: scanResult.cloneCandidates,
          clone_candidate_count: scanResult.cloneCandidates.length,
          clone_scan_status: 'complete',
        })
        .select('id')
        .single();

      const intervalDays = monitor.frequency === 'daily' ? 1 : 7;
      const nextRunAt = new Date(Date.now() + intervalDays * 24 * 60 * 60 * 1000).toISOString();

      await supabase
        .from('monitors')
        .update({
          last_scan_id: inserted?.id ?? monitor.last_scan_id,
          last_score: scanResult.score,
          next_run_at: nextRunAt,
          is_processing: false,
        })
        .eq('id', monitor.id);

      if (scanResult.score !== monitor.last_score && inserted) {
        await sendMonitorAlert({
          toEmail: monitor.email,
          hostname: monitor.hostname,
          previousScore: monitor.last_score,
          newScore: scanResult.score,
          grade: scanResult.grade,
          reportUrl: `${appUrl}/report/${inserted.id}`,
          unsubscribeUrl: `${appUrl}/api/monitor?token=${monitor.unsubscribe_token}`,
        });
        results.alerted += 1;
      }

      results.processed += 1;
    } catch (err) {
      results.failed += 1;
      if (err instanceof SSRFBlockedError) {
        // Target became unsafe/unreachable (e.g. now resolves internally) — deactivate rather than retry forever.
        await supabase.from('monitors').update({ active: false, is_processing: false }).eq('id', monitor.id);
      } else {
        // Release the claim so a transient failure (timeout, target down)
        // gets retried on the next scheduled run instead of waiting out
        // the 10-minute stale-lock window.
        await supabase.from('monitors').update({ is_processing: false }).eq('id', monitor.id);
      }
      console.error(`Monitor rescan failed for ${monitor.hostname}`, err);
    }
  }

  // Refresh benchmark aggregates for any niche touched by scans in the last day.
  const { data: activeNiches } = await supabase
    .from('scans')
    .select('niche')
    .not('niche', 'is', null)
    .gte('scanned_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

  const niches = new Set((activeNiches ?? []).map((r) => r.niche as string));
  for (const niche of niches) {
    await refreshNicheBenchmark(niche).catch((err) => console.error(`Benchmark refresh failed for ${niche}`, err));
  }

  return NextResponse.json(results);
}

/** Fails closed if CRON_SECRET isn't configured (rather than matching a
 * literal "Bearer undefined" string), and compares constant-time since
 * this secret gates an endpoint that runs live scans and sends email on
 * demand. */
function isValidCronAuth(authHeader: string | null): boolean {
  const secret = process.env.CRON_SECRET;
  if (!secret || !authHeader) return false;

  const expected = Buffer.from(`Bearer ${secret}`);
  const actual = Buffer.from(authHeader);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
