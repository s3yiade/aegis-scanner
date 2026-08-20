import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const ParamsSchema = z.object({ id: z.string().uuid() });

const GRADE_COLOR: Record<string, string> = {
  A: '#1ea34c',
  B: '#6fbf3f',
  C: '#e0b400',
  D: '#e07b00',
  F: '#d92b2b',
};

/**
 * Embeddable "Scanned by Aegis — Grade: A" SVG badge a business can put on
 * their own site, linking back to the scanner (free backlink/brand
 * exposure per satisfied lead — Part 3 improvement idea).
 * Only exposes the letter grade, never the underlying findings, so it's
 * safe to badge even a locked/un-purchased report.
 */
export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const parsed = ParamsSchema.safeParse(await params);
  if (!parsed.success) {
    return new NextResponse('Invalid scan id', { status: 400 });
  }

  const supabase = getSupabaseAdmin();
  const { data: scan } = await supabase.from('scans').select('grade').eq('id', parsed.data.id).single();

  const grade = scan?.grade ?? '?';
  const color = GRADE_COLOR[grade] ?? '#888';
  const appName = process.env.APP_NAME || 'Aegis';

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="180" height="40" viewBox="0 0 180 40" role="img" aria-label="${appName} security grade ${grade}">
  <rect width="180" height="40" rx="6" fill="#111827"/>
  <rect x="140" width="40" height="40" rx="6" fill="${color}"/>
  <rect x="140" width="6" height="40" fill="${color}"/>
  <text x="12" y="17" fill="#e5e7eb" font-family="Arial, sans-serif" font-size="10">Scanned by</text>
  <text x="12" y="31" fill="#ffffff" font-family="Arial, sans-serif" font-size="13" font-weight="bold">${appName}</text>
  <text x="160" y="25" fill="#ffffff" font-family="Arial, sans-serif" font-size="16" font-weight="bold" text-anchor="middle">${grade}</text>
</svg>`;

  return new NextResponse(svg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
