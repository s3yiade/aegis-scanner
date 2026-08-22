import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';
import { renderReportPdf } from '@/lib/pdf';
import { getNicheCopy } from '@/lib/scanner/niche';
import { getEndpointCopy } from '@/lib/scanner/endpointNiche';
import { getBenchmark } from '@/lib/scanner/benchmark';
import type { ScanResult } from '@/types/scan';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const ParamsSchema = z.object({ id: z.string().uuid() });

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const parsed = ParamsSchema.safeParse(await params);
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid scan id' }, { status: 400 });
  }

  const supabase = getSupabaseAdmin();

  const { data: scan, error } = await supabase.from('scans').select('*').eq('id', parsed.data.id).single();
  if (error || !scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const { count } = await supabase
    .from('leads')
    .select('id', { count: 'exact', head: true })
    .eq('scan_id', scan.id);

  if (!count || count === 0) {
    return NextResponse.json({ error: 'Report is locked. Submit your email to unlock the full report first.' }, { status: 403 });
  }

  const result: ScanResult = {
    targetUrl: scan.target_url,
    hostname: scan.hostname,
    targetType: scan.target_type,
    score: scan.score,
    grade: scan.grade,
    findings: scan.findings,
    scannedAt: scan.scanned_at,
    niche: scan.niche,
    endpointType: scan.endpoint_type,
    cloneCandidates: scan.clone_candidates ?? [],
  };

  const nicheCopy = getNicheCopy(scan.niche);
  const endpointCopy = scan.target_type === 'api' ? getEndpointCopy(scan.endpoint_type) : null;
  const benchmark = scan.niche ? await getBenchmark(scan.niche) : null;

  const pdfBytes = await renderReportPdf(result, process.env.APP_NAME || 'Aegis', {
    targetType: result.targetType,
    nicheCopy: scan.niche ? nicheCopy : null,
    endpointCopy,
    benchmark,
  });

  return new NextResponse(Buffer.from(pdfBytes), {
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${scan.hostname}-security-report.pdf"`,
      'Cache-Control': 'private, no-store',
    },
  });
}
