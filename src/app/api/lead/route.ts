import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { waitUntil } from '@vercel/functions';
import { getSupabaseAdmin } from '@/lib/supabase';
import { notifyNewLead } from '@/lib/email';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { verifyCaptcha, CaptchaInputSchema } from '@/lib/captcha';
import { isSameOrigin } from '@/lib/originCheck';
import { isDisposableEmail, classifyEmailTrust } from '@/lib/emailTrust';
import { isAdminRequest } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const SINGLE_LINE_NO_CONTROL_CHARS = /^[^\x00-\x1F\x7F]*$/;
const MAX_LEADS_PER_SCAN = 5; // allow a couple of email typo corrections without opening this up to spam

const LeadSchema = z.object({
  scanId: z.string().uuid(),
  email: z.string().trim().email().max(320),
  name: z
    .string()
    .trim()
    .max(200)
    .regex(SINGLE_LINE_NO_CONTROL_CHARS, 'Name must be a single line')
    .optional(),
  businessType: z.string().max(64).optional(),
  captcha: CaptchaInputSchema,
});

export async function POST(req: NextRequest) {
  // --- 0. Reject cross-origin submissions (see lib/originCheck) ---
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  let body: z.infer<typeof LeadSchema>;
  try {
    body = LeadSchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }

  const isAdmin = isAdminRequest(req);
  const clientIp = getClientIp(req.headers);

  // Admin sessions supersede every gate below except origin checking (see
  // lib/adminAuth.ts) — this is your own authenticated testing, not
  // anonymous public traffic.
  if (!isAdmin) {
    // Lead submission shares the scan rate limit bucket so this endpoint
    // can't be used to sidestep the abuse controls on /api/scan.
    const rl = await checkRateLimit(clientIp);
    if (!rl.allowed) {
      return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
    }

    // Captcha — this route is a non-gated (no scan-cost) endpoint, so it
    // gets its own proof-of-interaction rather than riding on the scan's.
    const captchaOk = await verifyCaptcha({ ...body.captcha, clientIp });
    if (!captchaOk) {
      return NextResponse.json({ error: 'Captcha verification failed' }, { status: 400 });
    }

    // Disposable/throwaway addresses are hard-blocked — they can't
    // meaningfully back an ownership claim and they're a common spam
    // vector for "unlock the report" flows.
    if (isDisposableEmail(body.email)) {
      return NextResponse.json({ error: 'Please use a permanent email address.' }, { status: 400 });
    }
  }

  const supabase = getSupabaseAdmin();
  const { data: scan, error: scanError } = await supabase
    .from('scans')
    .select('id, hostname, score, grade')
    .eq('id', body.scanId)
    .single();

  if (scanError || !scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const { count: existingLeadCount } = await supabase
    .from('leads')
    .select('id', { count: 'exact', head: true })
    .eq('scan_id', scan.id);

  if (!isAdmin && (existingLeadCount ?? 0) >= MAX_LEADS_PER_SCAN) {
    return NextResponse.json({ error: 'Too many submissions for this scan.' }, { status: 429 });
  }

  const emailTrust = classifyEmailTrust(body.email, scan.hostname);

  const { error: insertError } = await supabase.from('leads').insert({
    scan_id: scan.id,
    name: body.name || null,
    email: body.email,
    business_type: body.businessType ?? null,
    email_trust: emailTrust,
  });

  if (insertError) {
    console.error('Failed to store lead', insertError);
    return NextResponse.json({ error: 'Could not save your info. Please try again.' }, { status: 500 });
  }

  if (body.businessType) {
    await supabase.from('scans').update({ niche: body.businessType }).eq('id', scan.id);
  }

  // Wrapped in waitUntil() rather than a bare fire-and-forget promise — on
  // Vercel the function instance can be frozen shortly after the response
  // is sent, so an un-awaited promise isn't guaranteed to finish. See
  // api/consult for the fuller explanation.
  waitUntil(
    notifyNewLead({
      email: body.email,
      name: body.name,
      hostname: scan.hostname,
      score: scan.score,
      grade: scan.grade,
      scanId: scan.id,
    }).catch((err) => console.error('Lead notification failed', err))
  );

  return NextResponse.json({ unlocked: true, scanId: scan.id });
}
