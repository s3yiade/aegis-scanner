import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';
import { getFixProcedure } from '@/lib/scanner/fixProcedures';
import { verifyAdminSession, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';
import type { Finding } from '@/types/scan';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const ParamsSchema = z.object({ id: z.string().uuid() });

/**
 * Serves the detailed step-by-step fix procedures — the paid "fix it
 * yourself" unlock. Deliberately a separate endpoint from
 * /api/report/[id]: that route's response must never include this
 * content, paid or not, so there's no risk of it leaking into the free
 * report by a future edit accidentally including the wrong field.
 * Gated on fix_guide_purchases.paid = true, or an admin session
 * (isAdmin supersedes payment — see lib/adminAuth.ts).
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const parsed = ParamsSchema.safeParse(await params);
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid scan id' }, { status: 400 });
  }

  const isAdmin = verifyAdminSession(req.cookies.get(ADMIN_SESSION_COOKIE)?.value);
  const supabase = getSupabaseAdmin();

  if (!isAdmin) {
    const { count } = await supabase
      .from('fix_guide_purchases')
      .select('id', { count: 'exact', head: true })
      .eq('scan_id', parsed.data.id)
      .eq('paid', true);

    if (!count || count === 0) {
      return NextResponse.json({ error: 'Fix guide is locked. Purchase access first.' }, { status: 403 });
    }
  }

  const { data: scan, error } = await supabase.from('scans').select('findings').eq('id', parsed.data.id).single();
  if (error || !scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const failedFindings: Finding[] = (scan.findings ?? []).filter((f: Finding) => !f.passed);
  const procedures = failedFindings.map((f) => ({
    findingId: f.id,
    findingTitle: f.title,
    severity: f.severity,
    procedure: getFixProcedure(f.id),
  }));

  return NextResponse.json({ unlocked: true, procedures });
}
