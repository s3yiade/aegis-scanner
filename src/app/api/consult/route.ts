import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { waitUntil } from '@vercel/functions';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { verifyCaptcha, CaptchaInputSchema } from '@/lib/captcha';
import { isSameOrigin } from '@/lib/originCheck';
import { isDisposableEmail, classifyEmailTrust } from '@/lib/emailTrust';
import { notifyConsultRequest } from '@/lib/email';
import { searchForContentClones } from '@/lib/scanner/contentSimilarity';
import { runDeepScan } from '@/lib/scanner/deepScan';
import { isAdminRequest } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';
// Rendering a page via a hosted headless-browser API (see renderPage.ts)
// can take 20-30s on its own, on top of the content-similarity search —
// give the background work (see waitUntil below) real room to finish.
// Note: Vercel's Hobby plan caps function duration at 10s regardless of
// this setting; the background work will simply get cut off on Hobby. Pro
// (or Fluid Compute) is effectively required for this to reliably
// complete.
export const maxDuration = 60;

const SINGLE_LINE_NO_CONTROL_CHARS = /^[^\x00-\x1F\x7F]*$/;

const ConsultSchema = z.object({
  // Optional — the report page's "Book consult" always has a scan behind
  // it, but the Consulting page's general contact form doesn't (someone
  // reaching out before ever running a scan). content_similarity/deep_scan
  // background work below only ever runs for clone_report* types anyway,
  // which always come from a scan-specific flow, so a missing scanId
  // there is a non-issue in practice.
  scanId: z.string().uuid().optional(),
  email: z.string().trim().email().max(320),
  name: z.string().trim().max(200).regex(SINGLE_LINE_NO_CONTROL_CHARS, 'Name must be a single line').optional(),
  message: z.string().trim().max(1000).optional(),
  requestType: z.enum(['clone_report', 'clone_report_paid_interest', 'general']).default('clone_report'),
  captcha: CaptchaInputSchema,
});

/**
 * Gated entry point for the clone-detection deep dive (full lookalike-domain
 * list + content-similarity search + JS-rendered deep scan). Two request
 * types share this endpoint:
 *   - 'clone_report': a plain "contact me" consult request.
 *   - 'clone_report_paid_interest': the paywall-unlock button. No payment
 *     is actually processed here — this captures intent for manual
 *     follow-up/invoicing. Wire in a real payment processor (e.g. Stripe
 *     Checkout) before this button if you want a true self-serve unlock;
 *     this endpoint's job (capture the request, notify you, kick off the
 *     background scans) stays the same either way.
 *
 * Hardened the same way as /api/lead and /api/monitor: captcha, disposable-
 * email block, origin check, shared rate-limit bucket. This is a more
 * expensive action than a plain lead capture (it triggers a paid search API
 * call and/or a paid rendering API call), so those checks matter more
 * here, not less.
 */
export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  let body: z.infer<typeof ConsultSchema>;
  try {
    body = ConsultSchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }

  const isAdmin = isAdminRequest(req);
  const clientIp = getClientIp(req.headers);

  if (!isAdmin) {
    const rl = await checkRateLimit(clientIp);
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
    }

    const captchaOk = await verifyCaptcha({ ...body.captcha, clientIp });
    if (!captchaOk) {
      return NextResponse.json({ error: 'Captcha verification failed' }, { status: 400 });
    }

    if (isDisposableEmail(body.email)) {
      return NextResponse.json({ error: 'Please use a permanent email address.' }, { status: 400 });
    }
  }

  const supabase = getSupabaseAdmin();

  // No scanId (a general inquiry from the Consulting page, not tied to a
  // prior scan) skips the scan lookup and email-domain-trust classification
  // entirely — there's no site to compare the email against.
  let scan: { id: string; hostname: string; target_url: string } | null = null;
  if (body.scanId) {
    const { data, error: scanError } = await supabase
      .from('scans')
      .select('id, hostname, target_url')
      .eq('id', body.scanId)
      .single();
    if (scanError || !data) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    }
    scan = data;
  }

  const emailTrust = scan ? classifyEmailTrust(body.email, scan.hostname) : null;

  const { data: inserted, error: insertError } = await supabase
    .from('consult_requests')
    .insert({
      scan_id: scan?.id ?? null,
      email: body.email,
      name: body.name || null,
      message: body.message || null,
      request_type: body.requestType,
      email_trust: emailTrust,
    })
    .select('id')
    .single();

  if (insertError || !inserted) {
    console.error('Failed to store consult request', insertError);
    return NextResponse.json({ error: 'Could not save your request. Please try again.' }, { status: 500 });
  }

  waitUntil(
    notifyConsultRequest({
      email: body.email,
      name: body.name,
      hostname: scan?.hostname ?? '(no scan — general inquiry)',
      requestType: body.requestType,
      scanId: scan?.id ?? '',
    }).catch((err) => console.error('Consult notification failed', err))
  );

  // Only trigger the paid-API-backed background analysis for clone-
  // detection request types with an actual scan behind them — a
  // 'general' consult (from the Consulting page's contact form, or the
  // report page's plain "Book consult" button) has nothing to do with
  // clone detection and shouldn't burn search/rendering API quota.
  if (scan && (body.requestType === 'clone_report' || body.requestType === 'clone_report_paid_interest')) {
    waitUntil(
      searchForContentClones(scan.target_url)
        .then(({ status, matches }) =>
          supabase
            .from('consult_requests')
            .update({ content_similarity_status: status, content_similarity_matches: matches })
            .eq('id', inserted.id)
        )
        .catch((err) => console.error('Content-similarity search failed', err))
    );

    waitUntil(
      runDeepScan(scan.target_url)
        .then(({ status, findings }) =>
          supabase
            .from('consult_requests')
            .update({ deep_scan_status: status, deep_scan_findings: findings })
            .eq('id', inserted.id)
        )
        .catch((err) => console.error('Deep scan failed', err))
    );
  }

  return NextResponse.json({ submitted: true });
}
