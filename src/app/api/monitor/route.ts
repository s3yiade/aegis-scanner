import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { verifyCaptcha, CaptchaInputSchema } from '@/lib/captcha';
import { isSameOrigin } from '@/lib/originCheck';
import { isDisposableEmail, classifyEmailTrust } from '@/lib/emailTrust';
import { isAdminRequest } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const MonitorSchema = z.object({
  scanId: z.string().uuid(),
  email: z.string().trim().email().max(320),
  frequency: z.enum(['weekly', 'daily']).optional().default('weekly'),
  captcha: CaptchaInputSchema,
});

/**
 * Opt in to recurring re-scans with email alerts on score change — a
 * free-tier version of the Monitor retainer that keeps leads warm without
 * manual follow-up (Part 3 improvement idea #3). Hardened the same way as
 * /api/lead: captcha, disposable-email block, origin check — this endpoint
 * sends recurring email to an address the caller supplies, so it's a more
 * attractive spam target than a one-time unlock.
 */
export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  let body: z.infer<typeof MonitorSchema>;
  try {
    body = MonitorSchema.parse(await req.json());
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
  const { data: scan, error: scanError } = await supabase
    .from('scans')
    .select('id, hostname, target_url, score')
    .eq('id', body.scanId)
    .single();

  if (scanError || !scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const emailTrust = classifyEmailTrust(body.email, scan.hostname);
  const intervalDays = body.frequency === 'daily' ? 1 : 7;
  const nextRunAt = new Date(Date.now() + intervalDays * 24 * 60 * 60 * 1000).toISOString();

  const { error: upsertError } = await supabase
    .from('monitors')
    .upsert(
      {
        hostname: scan.hostname,
        target_url: scan.target_url,
        email: body.email,
        frequency: body.frequency,
        active: true,
        last_scan_id: scan.id,
        last_score: scan.score,
        next_run_at: nextRunAt,
        email_trust: emailTrust,
      },
      { onConflict: 'hostname,email' }
    );

  if (upsertError) {
    console.error('Failed to create monitor', upsertError);
    return NextResponse.json({ error: 'Could not set up monitoring. Please try again.' }, { status: 500 });
  }

  return NextResponse.json({ subscribed: true, frequency: body.frequency });
}

/**
 * Unsubscribe via token, linked from every monitor alert email. Email
 * clients always send GET when a link is clicked — DELETE was kept for API
 * callers, but GET is what the actual email link needs, with a plain HTML
 * confirmation page since this is opened directly in a browser.
 */
export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get('token');
  if (!token) return NextResponse.json({ error: 'Missing token' }, { status: 400 });

  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from('monitors')
    .update({ active: false })
    .eq('unsubscribe_token', token)
    .select('hostname')
    .maybeSingle();

  if (error || !data) {
    return new NextResponse(
      '<html><body style="font-family: sans-serif; padding: 40px;">Invalid or expired unsubscribe link.</body></html>',
      { status: 400, headers: { 'Content-Type': 'text/html' } }
    );
  }

  return new NextResponse(
    `<html><body style="font-family: sans-serif; padding: 40px;">You've been unsubscribed from monitoring for <strong>${escapeHtml(data.hostname)}</strong>.</body></html>`,
    { headers: { 'Content-Type': 'text/html' } }
  );
}

/** Kept for programmatic/API callers; the email link itself uses GET above. */
export async function DELETE(req: NextRequest) {
  const token = req.nextUrl.searchParams.get('token');
  if (!token) return NextResponse.json({ error: 'Missing token' }, { status: 400 });

  const supabase = getSupabaseAdmin();
  const { error } = await supabase.from('monitors').update({ active: false }).eq('unsubscribe_token', token);

  if (error) return NextResponse.json({ error: 'Invalid token' }, { status: 400 });
  return NextResponse.json({ unsubscribed: true });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
