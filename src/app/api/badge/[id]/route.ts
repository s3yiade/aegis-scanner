import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const ParamsSchema = z.object({ id: z.string().uuid() });
const STALE_AFTER_DAYS = 60;

const GRADE_COLOR: Record<string, string> = {
  A: '#1ea34c',
  B: '#6fbf3f',
  C: '#e0b400',
  D: '#e07b00',
  F: '#d92b2b',
};

const SHIELD_PATH =
  'M12 2 4 5v6c0 5.2 3.4 9.7 8 11 4.6-1.3 8-5.8 8-11V5l-8-3z';

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatMonthYear(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
}

/**
 * Embeddable "Scanned by Aegis" SVG badge a business can put on their own
 * site, linking back to the scanner (free backlink/brand exposure per
 * satisfied lead — Part 3 improvement idea, deepened here). Only exposes
 * the letter grade, numeric score, and scan month — never the underlying
 * findings — so it's safe to badge even a locked/un-purchased report.
 *
 * Two styles:
 *   - default: bigger card — grade, score, and "as of <month>" so a badge
 *     can't be displayed indefinitely without visibly aging. A scan older
 *     than STALE_AFTER_DAYS gets a visibly muted "re-scan due" treatment
 *     instead of a bright pass color — a badge that never expires isn't
 *     trustworthy, and this makes staleness part of the visual itself
 *     rather than something a viewer has to click through to discover.
 *   - ?style=compact: the original small single-row badge, kept for
 *     anyone who already embedded it — this route never breaks an
 *     existing embed's dimensions/shape out from under it.
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const parsed = ParamsSchema.safeParse(await params);
  if (!parsed.success) {
    return new NextResponse('Invalid scan id', { status: 400 });
  }

  const style = req.nextUrl.searchParams.get('style') === 'compact' ? 'compact' : 'detailed';

  const supabase = getSupabaseAdmin();
  const { data: scan } = await supabase.from('scans').select('grade, score, scanned_at').eq('id', parsed.data.id).single();

  const grade = scan?.grade ?? '?';
  const score = scan?.score ?? null;
  const color = GRADE_COLOR[grade] ?? '#888';
  const appName = process.env.APP_NAME || 'Aegis';

  const isStale = scan?.scanned_at ? Date.now() - new Date(scan.scanned_at).getTime() > STALE_AFTER_DAYS * 24 * 60 * 60 * 1000 : false;
  const badgeColor = isStale ? '#5b6478' : color;
  const label = `${appName} security grade ${grade}${score !== null ? `, score ${score}` : ''}${isStale ? ' (re-scan due)' : ''}`;

  const svg = style === 'compact' ? compactSvg({ appName, grade, color: badgeColor, label }) : detailedSvg({ appName, grade, score, color: badgeColor, label, isStale, scannedAt: scan?.scanned_at ?? null });

  return new NextResponse(svg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

function compactSvg({ appName, grade, color, label }: { appName: string; grade: string; color: string; label: string }): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="180" height="40" viewBox="0 0 180 40" role="img" aria-label="${escapeXml(label)}">
  <rect width="180" height="40" rx="6" fill="#111827"/>
  <rect x="140" width="40" height="40" rx="6" fill="${color}"/>
  <rect x="140" width="6" height="40" fill="${color}"/>
  <text x="12" y="17" fill="#e5e7eb" font-family="Arial, sans-serif" font-size="10">Scanned by</text>
  <text x="12" y="31" fill="#ffffff" font-family="Arial, sans-serif" font-size="13" font-weight="bold">${escapeXml(appName)}</text>
  <text x="160" y="25" fill="#ffffff" font-family="Arial, sans-serif" font-size="16" font-weight="bold" text-anchor="middle">${escapeXml(grade)}</text>
</svg>`;
}

function detailedSvg({
  appName,
  grade,
  score,
  color,
  label,
  isStale,
  scannedAt,
}: {
  appName: string;
  grade: string;
  score: number | null;
  color: string;
  label: string;
  isStale: boolean;
  scannedAt: string | null;
}): string {
  const dateLabel = scannedAt ? `as of ${formatMonthYear(scannedAt)}` : '';
  const statusLine = isStale ? 're-scan due' : dateLabel;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="64" viewBox="0 0 220 64" role="img" aria-label="${escapeXml(label)}">
  <rect width="220" height="64" rx="8" fill="#111827" stroke="#1f2937" stroke-width="1"/>
  <path d="${SHIELD_PATH}" transform="translate(14 12) scale(0.9)" fill="none" stroke="${color}" stroke-width="1.6" stroke-linejoin="round"/>
  <text x="42" y="24" fill="#8b93a7" font-family="Arial, sans-serif" font-size="9" letter-spacing="0.5">SCANNED BY</text>
  <text x="42" y="38" fill="#ffffff" font-family="Arial, sans-serif" font-size="14" font-weight="bold">${escapeXml(appName)}</text>
  ${statusLine ? `<text x="42" y="52" fill="${isStale ? '#e0b400' : '#8b93a7'}" font-family="Arial, sans-serif" font-size="9">${escapeXml(statusLine)}</text>` : ''}
  <rect x="160" y="10" width="48" height="44" rx="8" fill="${color}" fill-opacity="0.15" stroke="${color}" stroke-width="1.5"/>
  <text x="184" y="34" fill="${color}" font-family="Arial, sans-serif" font-size="20" font-weight="bold" text-anchor="middle">${escapeXml(grade)}</text>
  ${score !== null ? `<text x="184" y="48" fill="#8b93a7" font-family="Arial, sans-serif" font-size="9" text-anchor="middle">${score}/100</text>` : ''}
</svg>`;
}
