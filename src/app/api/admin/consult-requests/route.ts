import { NextRequest, NextResponse } from 'next/server';
import { verifyAdminSession, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';
import { getSupabaseAdmin } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

/**
 * The review queue. Three separate paid-API-backed analysis pipelines
 * write into consult_requests — content-similarity title search
 * (contentSimilarity.ts), the JS-rendered deep scan (deepScan.ts), and
 * the DOM/favicon/screenshot/reverse-image similarity comparisons
 * (similarityOrchestrator.ts) — and every lower-precision signal in that
 * pipeline (a DOM-structure match against a shared theme, a title-search
 * hit, a broad reverse-image match) is treated as safe to surface *only*
 * because a human is assumed to look at it before anything gets treated
 * as a confirmed threat. This endpoint (and /admin's Review queue tab)
 * is that lookup surface — without it, that assumption had nothing to
 * act on.
 */
export async function GET(req: NextRequest) {
  const session = req.cookies.get(ADMIN_SESSION_COOKIE)?.value;
  if (!verifyAdminSession(session)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = getSupabaseAdmin();

  const { data, error } = await supabase
    .from('consult_requests')
    .select(
      `id, scan_id, email, name, request_type, message, created_at, contacted, paid,
       content_similarity_status, content_similarity_matches,
       deep_scan_status, deep_scan_findings,
       similarity_status, similarity_results,
       scans ( hostname, target_url, score, grade, clone_candidates )`
    )
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) {
    return NextResponse.json({ error: 'Failed to load review queue' }, { status: 500 });
  }

  return NextResponse.json({ requests: data });
}
