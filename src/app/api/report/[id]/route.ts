import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';
import { getNicheCopy } from '@/lib/scanner/niche';
import { getEndpointCopy } from '@/lib/scanner/endpointNiche';
import { getBenchmark } from '@/lib/scanner/benchmark';
import { verifyAdminSession, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const ParamsSchema = z.object({ id: z.string().uuid() });

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const parsed = ParamsSchema.safeParse(await params);
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid scan id' }, { status: 400 });
  }

  const supabase = getSupabaseAdmin();

  const { data: scan, error } = await supabase
    .from('scans')
    .select('*')
    .eq('id', parsed.data.id)
    .single();

  if (error || !scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const isAdmin = verifyAdminSession(req.cookies.get(ADMIN_SESSION_COOKIE)?.value);

  const { count } = await supabase
    .from('leads')
    .select('id', { count: 'exact', head: true })
    .eq('scan_id', scan.id);

  // Admin sessions auto-unlock every report — no need to go through the
  // email-gate flow to review your own test scans.
  const unlocked = isAdmin || Boolean(count && count > 0);

  if (!unlocked) {
    // Locked: only the teaser-level data, never the findings/recommendations.
    const criticalCount = (scan.findings as { passed: boolean; severity: string }[]).filter(
      (f) => !f.passed && f.severity === 'critical'
    ).length;
    return NextResponse.json({
      unlocked: false,
      hostname: scan.hostname,
      score: scan.score,
      grade: scan.grade,
      criticalCount,
      cloneCandidateCount: scan.clone_candidate_count ?? 0,
    });
  }

  const nicheCopy = getNicheCopy(scan.niche);
  const benchmark = scan.niche ? await getBenchmark(scan.niche) : null;
  const endpointCopy = scan.target_type === 'api' ? getEndpointCopy(scan.endpoint_type) : null;

  return NextResponse.json({
    unlocked: true,
    targetUrl: scan.target_url,
    hostname: scan.hostname,
    targetType: scan.target_type,
    score: scan.score,
    grade: scan.grade,
    findings: scan.findings,
    scannedAt: scan.scanned_at,
    niche: scan.niche,
    nicheCopy,
    endpointType: scan.endpoint_type,
    endpointCopy,
    benchmark,
    // The count is fine to show once the free report is unlocked — it's the
    // domain list itself (and the content-similarity results) that stay
    // behind the consult/paywall gate. See api/consult.
    cloneCandidateCount: scan.clone_candidate_count ?? 0,
  });
}
