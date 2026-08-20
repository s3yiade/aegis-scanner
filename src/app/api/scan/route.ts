import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { runScan } from '@/lib/scanner';
import { SSRFBlockedError } from '@/lib/ssrfGuard';
import { checkRateLimit, getClientIp, hashIp } from '@/lib/ratelimit';
import { verifyCaptcha, CaptchaInputSchema } from '@/lib/captcha';
import { isSameOrigin } from '@/lib/originCheck';
import { verifyAdminSession, ADMIN_SESSION_COOKIE } from '@/lib/adminAuth';
import { getSupabaseAdmin } from '@/lib/supabase';
import type { TeaserResult } from '@/types/scan';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs'; // needs node:dns, node:tls — not edge-compatible

// URL field is deliberately tight: single line, no control characters, and
// short enough that nobody is legitimately pasting a real target this way.
// This is about attack-surface reduction (no multi-line/oversized payloads
// reaching downstream parsing), not URL correctness — malformed-but-short
// input still gets rejected later by `new URL()` inside the SSRF guard.
const SINGLE_LINE_NO_CONTROL_CHARS = /^[^\x00-\x1F\x7F]+$/;

const ScanRequestSchema = z.object({
  url: z
    .string()
    .trim()
    .min(3)
    .max(300, 'URL is too long')
    .regex(SINGLE_LINE_NO_CONTROL_CHARS, 'URL must be a single line with no control characters'),
  targetType: z.enum(['web', 'api']).optional().default('web'),
  niche: z.string().max(64).optional().nullable(),
  // Zero-trust framing: this checkbox is a legal/audit acknowledgment, not
  // a technical safeguard — the SSRF guard, rate limiting, and captcha are
  // what actually constrain what gets scanned. Requiring explicit
  // acknowledgment (and recording it) still matters for accountability if
  // a scan target ever disputes being scanned without permission.
  // Relaxed to a plain boolean (checked against `true` below, not via the
  // schema) so an authenticated admin session can bypass it for their own
  // test scans — see the isAdmin check in POST.
  ownershipConfirmed: z.boolean(),
  captcha: CaptchaInputSchema,
});

export async function POST(req: NextRequest) {
  // --- 0. Reject cross-origin submissions outright (defense-in-depth; see lib/originCheck) ---
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  const isAdmin = verifyAdminSession(req.cookies.get(ADMIN_SESSION_COOKIE)?.value);

  // --- 1. Parse + validate input shape before doing anything expensive ---
  let body: z.infer<typeof ScanRequestSchema>;
  try {
    body = ScanRequestSchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  if (!isAdmin && !body.ownershipConfirmed) {
    return NextResponse.json({ error: 'You must confirm you own or are authorized to scan this target.' }, { status: 400 });
  }

  const clientIp = getClientIp(req.headers);
  let rateLimitInfo: { remainingHourly: number; remainingDaily: number } | null = null;

  // --- 2. Rate limit (before captcha verification, which costs a request) ---
  // Admin sessions skip both rate limiting and captcha — this is your own
  // authenticated testing, not anonymous public traffic.
  if (!isAdmin) {
    const rl = await checkRateLimit(clientIp);
    if (!rl.allowed) {
      return NextResponse.json(
        {
          error:
            rl.reason === 'daily'
              ? 'Daily scan limit reached. Try again tomorrow.'
              : 'Too many scans — please wait before scanning again.',
        },
        { status: 429, headers: { 'Retry-After': rl.reason === 'daily' ? '86400' : '3600' } }
      );
    }
    rateLimitInfo = { remainingHourly: rl.remainingHourly, remainingDaily: rl.remainingDaily };

    // --- 3. Captcha ---
    const captchaOk = await verifyCaptcha({ ...body.captcha, clientIp });
    if (!captchaOk) {
      return NextResponse.json({ error: 'Captcha verification failed' }, { status: 400 });
    }
  }

  // --- 4. Normalize URL (default to https:// if no scheme given) ---
  const rawUrl = /^https?:\/\//i.test(body.url) ? body.url : `https://${body.url}`;

  // --- 5. Run the scan (SSRF-guarded inside runScan) ---
  let result;
  try {
    result = await runScan({ targetUrl: rawUrl, targetType: body.targetType, niche: body.niche });
  } catch (err) {
    if (err instanceof SSRFBlockedError) {
      // Deliberately vague to avoid confirming internal network layout to a probing user.
      return NextResponse.json({ error: 'This URL cannot be scanned.' }, { status: 400 });
    }
    console.error('Scan failed', err);
    return NextResponse.json({ error: 'Scan failed. Please try again.' }, { status: 500 });
  }

  // --- 6. Persist (findings + score only — never raw response bodies) ---
  const supabase = getSupabaseAdmin();
  const { data: inserted, error: insertError } = await supabase
    .from('scans')
    .insert({
      target_url: result.targetUrl,
      hostname: result.hostname,
      target_type: result.targetType,
      score: result.score,
      grade: result.grade,
      findings: result.findings,
      niche: result.niche,
      ip_address: hashIp(clientIp),
      ownership_acknowledged: body.ownershipConfirmed || isAdmin,
      ownership_ack_at: body.ownershipConfirmed || isAdmin ? new Date().toISOString() : null,
      clone_candidates: result.cloneCandidates,
      clone_candidate_count: result.cloneCandidates.length,
      clone_scan_status: 'complete',
    })
    .select('id')
    .single();

  if (insertError || !inserted) {
    console.error('Failed to store scan', insertError);
    return NextResponse.json({ error: 'Scan completed but could not be saved. Please try again.' }, { status: 500 });
  }

  const criticalCount = result.findings.filter((f) => !f.passed && f.severity === 'critical').length;
  const topIssueCount = result.findings.filter((f) => !f.passed).length;

  const teaser: TeaserResult = {
    hostname: result.hostname,
    score: result.score,
    grade: result.grade,
    headline:
      criticalCount > 0
        ? `${criticalCount} critical issue${criticalCount > 1 ? 's' : ''} found`
        : topIssueCount > 0
        ? `${topIssueCount} issue${topIssueCount > 1 ? 's' : ''} found`
        : 'No major issues found',
    topIssueCount,
    criticalCount,
    scanId: inserted.id,
    cloneCandidateCount: result.cloneCandidates.length,
  };

  return NextResponse.json(teaser, {
    headers: rateLimitInfo
      ? {
          'X-RateLimit-Remaining-Hourly': String(rateLimitInfo.remainingHourly),
          'X-RateLimit-Remaining-Daily': String(rateLimitInfo.remainingDaily),
        }
      : {},
  });
}
