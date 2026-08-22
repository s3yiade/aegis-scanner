import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getStripe } from '@/lib/stripe';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { verifyCaptcha, CaptchaInputSchema } from '@/lib/captcha';
import { isSameOrigin } from '@/lib/originCheck';
import { isDisposableEmail, classifyEmailTrust } from '@/lib/emailTrust';
import { isAdminRequest } from '@/lib/adminAuth';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';

const CheckoutSchema = z.object({
  scanId: z.string().uuid(),
  product: z.enum(['clone_report_unlock', 'domain_watch_subscription', 'fix_guide_unlock', 'saas_monitor_pro']),
  email: z.string().trim().email().max(320),
  name: z.string().trim().max(200).optional(),
  // Only used for domain_watch_subscription — the range within which an
  // alert fires once a dormant lookalike domain goes live. Defaults match
  // the schema's column defaults.
  similarityMin: z.number().min(0).max(100).optional().default(70),
  similarityMax: z.number().min(0).max(100).optional().default(90),
  // Only used for saas_monitor_pro — how often the paid re-scan+diff runs.
  frequency: z.enum(['weekly', 'daily']).optional().default('daily'),
  captcha: CaptchaInputSchema,
});

/**
 * Creates a Stripe Checkout Session for any of the three paid features and
 * returns the redirect URL. Payment is only ever confirmed by the webhook
 * (api/stripe/webhook) — this route never marks anything as paid itself,
 * since a client can hit "success" without actually completing payment
 * (closed tab, back button, etc.) — EXCEPT for an authenticated admin
 * session, which supersedes payment entirely (see the isAdmin branch
 * below): the underlying row is marked paid directly and no Stripe
 * session is created at all, since the admin shouldn't have to pay
 * themselves to access their own paid features.
 *
 * Hardened the same as every other gated route for non-admin callers:
 * captcha, disposable-email block, origin check, rate limit.
 */
export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  let body: z.infer<typeof CheckoutSchema>;
  try {
    body = CheckoutSchema.parse(await req.json());
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
    .select('id, hostname, target_url, target_type, niche, endpoint_type')
    .eq('id', body.scanId)
    .single();

  if (scanError || !scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  // Continuous monitoring + diff reports is a SaaS/API-tier feature — a
  // website-only scan still gets the free "email me if my score changes"
  // monitor (api/monitor), just not this one. Enforced server-side rather
  // than only hidden client-side, same as every other gate in this route.
  if (body.product === 'saas_monitor_pro' && scan.target_type !== 'api') {
    return NextResponse.json(
      { error: 'Continuous monitoring with diff reports is available for SaaS/API scans. Use the free monitor for website scans.' },
      { status: 400 }
    );
  }

  const emailTrust = classifyEmailTrust(body.email, scan.hostname);
  const appUrl = process.env.APP_URL;

  // --- Admin direct-grant path: bypass Stripe entirely ---
  if (isAdmin) {
    if (body.product === 'clone_report_unlock') {
      const { data: inserted, error: insertError } = await supabase
        .from('consult_requests')
        .insert({
          scan_id: scan.id,
          email: body.email,
          name: body.name || null,
          request_type: 'clone_report_paid_interest',
          email_trust: emailTrust,
          paid: true, // admin session supersedes payment — see lib/adminAuth.ts
        })
        .select('id')
        .single();
      if (insertError || !inserted) {
        return NextResponse.json({ error: 'Could not grant access.' }, { status: 500 });
      }
      return NextResponse.json({ adminGranted: true });
    }

    if (body.product === 'domain_watch_subscription') {
      const { data: inserted, error: insertError } = await supabase
        .from('clone_watch_subscriptions')
        .insert({
          scan_id: scan.id,
          hostname: scan.hostname,
          email: body.email,
          email_trust: emailTrust,
          similarity_min: body.similarityMin,
          similarity_max: body.similarityMax,
          paid: true,
          active: true,
        })
        .select('id')
        .single();
      if (insertError || !inserted) {
        return NextResponse.json({ error: 'Could not grant access.' }, { status: 500 });
      }
      return NextResponse.json({ adminGranted: true });
    }

    if (body.product === 'saas_monitor_pro') {
      const nextRunAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // pick up on next hourly cron tick
      const { error: upgradeError } = await supabase.from('monitor_pro_upgrades').insert({
        scan_id: scan.id,
        hostname: scan.hostname,
        target_url: scan.target_url,
        target_type: scan.target_type,
        niche: scan.niche,
        endpoint_type: scan.endpoint_type,
        email: body.email,
        email_trust: emailTrust,
        frequency: body.frequency,
        paid: true,
      });
      if (upgradeError) {
        return NextResponse.json({ error: 'Could not grant access.' }, { status: 500 });
      }
      const { error: monitorError } = await supabase.from('monitors').upsert(
        {
          hostname: scan.hostname,
          target_url: scan.target_url,
          target_type: scan.target_type,
          niche: scan.niche,
          endpoint_type: scan.endpoint_type,
          email: body.email,
          email_trust: emailTrust,
          frequency: body.frequency,
          active: true,
          tier: 'pro',
          pro_activated_at: new Date().toISOString(),
          next_run_at: nextRunAt,
        },
        { onConflict: 'hostname,email' }
      );
      if (monitorError) {
        return NextResponse.json({ error: 'Could not grant access.' }, { status: 500 });
      }
      return NextResponse.json({ adminGranted: true });
    }

    // fix_guide_unlock
    const { error: insertError } = await supabase.from('fix_guide_purchases').insert({
      scan_id: scan.id,
      email: body.email,
      email_trust: emailTrust,
      paid: true,
    });
    if (insertError) {
      return NextResponse.json({ error: 'Could not grant access.' }, { status: 500 });
    }
    return NextResponse.json({ adminGranted: true });
  }

  // --- Normal (non-admin) path: real Stripe Checkout ---
  const priceId =
    body.product === 'clone_report_unlock'
      ? process.env.STRIPE_PRICE_ID_CLONE_REPORT
      : body.product === 'domain_watch_subscription'
      ? process.env.STRIPE_PRICE_ID_DOMAIN_WATCH
      : body.product === 'saas_monitor_pro'
      ? process.env.STRIPE_PRICE_ID_SAAS_MONITOR
      : process.env.STRIPE_PRICE_ID_FIX_GUIDE;

  if (!process.env.STRIPE_SECRET_KEY || !priceId || !appUrl) {
    return NextResponse.json({ error: 'Payment is not configured yet. Please use "Request consultation" instead.' }, { status: 503 });
  }

  try {
    const stripe = getStripe();

    if (body.product === 'clone_report_unlock') {
      const { data: inserted, error: insertError } = await supabase
        .from('consult_requests')
        .insert({
          scan_id: scan.id,
          email: body.email,
          name: body.name || null,
          request_type: 'clone_report_paid_interest',
          email_trust: emailTrust,
        })
        .select('id')
        .single();

      if (insertError || !inserted) {
        return NextResponse.json({ error: 'Could not start checkout. Please try again.' }, { status: 500 });
      }

      const session = await stripe.checkout.sessions.create({
        mode: 'payment',
        line_items: [{ price: priceId, quantity: 1 }],
        customer_email: body.email,
        success_url: `${appUrl}/report/${scan.id}?unlock=success`,
        cancel_url: `${appUrl}/report/${scan.id}?unlock=cancelled`,
        metadata: { type: 'clone_report_unlock', consultRequestId: inserted.id, scanId: scan.id },
      });

      await supabase.from('consult_requests').update({ stripe_session_id: session.id }).eq('id', inserted.id);

      return NextResponse.json({ checkoutUrl: session.url });
    }

    if (body.product === 'domain_watch_subscription') {
      const { data: inserted, error: insertError } = await supabase
        .from('clone_watch_subscriptions')
        .insert({
          scan_id: scan.id,
          hostname: scan.hostname,
          email: body.email,
          email_trust: emailTrust,
          similarity_min: body.similarityMin,
          similarity_max: body.similarityMax,
        })
        .select('id')
        .single();

      if (insertError || !inserted) {
        return NextResponse.json({ error: 'Could not start checkout. Please try again.' }, { status: 500 });
      }

      const session = await stripe.checkout.sessions.create({
        mode: 'payment',
        line_items: [{ price: priceId, quantity: 1 }],
        customer_email: body.email,
        success_url: `${appUrl}/report/${scan.id}?watch=success`,
        cancel_url: `${appUrl}/report/${scan.id}?watch=cancelled`,
        metadata: { type: 'domain_watch_subscription', subscriptionId: inserted.id, scanId: scan.id },
      });

      await supabase.from('clone_watch_subscriptions').update({ stripe_session_id: session.id }).eq('id', inserted.id);

      return NextResponse.json({ checkoutUrl: session.url });
    }

    if (body.product === 'saas_monitor_pro') {
      const { data: inserted, error: insertError } = await supabase
        .from('monitor_pro_upgrades')
        .insert({
          scan_id: scan.id,
          hostname: scan.hostname,
          target_url: scan.target_url,
          target_type: scan.target_type,
          niche: scan.niche,
          endpoint_type: scan.endpoint_type,
          email: body.email,
          email_trust: emailTrust,
          frequency: body.frequency,
        })
        .select('id')
        .single();

      if (insertError || !inserted) {
        return NextResponse.json({ error: 'Could not start checkout. Please try again.' }, { status: 500 });
      }

      // Real recurring billing — STRIPE_PRICE_ID_SAAS_MONITOR must be a
      // recurring (monthly) Price in Stripe, not a one-time Price. Unlike
      // the other three products here (one-time payment/unlock, mirroring
      // domain_watch_subscription's existing "billed once" pattern), Pro
      // monitoring is an ongoing service and bills monthly until the
      // subscriber cancels — see the webhook's handling of
      // customer.subscription.deleted/updated for what happens then, and
      // api/stripe/portal for how a subscriber actually cancels.
      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        line_items: [{ price: priceId, quantity: 1 }],
        customer_email: body.email,
        success_url: `${appUrl}/report/${scan.id}?monitor=success`,
        cancel_url: `${appUrl}/report/${scan.id}?monitor=cancelled`,
        metadata: { type: 'saas_monitor_pro', upgradeId: inserted.id, scanId: scan.id },
        subscription_data: { metadata: { type: 'saas_monitor_pro', upgradeId: inserted.id, scanId: scan.id } },
      });

      await supabase.from('monitor_pro_upgrades').update({ stripe_session_id: session.id }).eq('id', inserted.id);

      return NextResponse.json({ checkoutUrl: session.url });
    }

    // fix_guide_unlock
    const { data: inserted, error: insertError } = await supabase
      .from('fix_guide_purchases')
      .insert({ scan_id: scan.id, email: body.email, email_trust: emailTrust })
      .select('id')
      .single();

    if (insertError || !inserted) {
      return NextResponse.json({ error: 'Could not start checkout. Please try again.' }, { status: 500 });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      customer_email: body.email,
      success_url: `${appUrl}/report/${scan.id}?fixguide=success`,
      cancel_url: `${appUrl}/report/${scan.id}?fixguide=cancelled`,
      metadata: { type: 'fix_guide_unlock', purchaseId: inserted.id, scanId: scan.id },
    });

    await supabase.from('fix_guide_purchases').update({ stripe_session_id: session.id }).eq('id', inserted.id);

    return NextResponse.json({ checkoutUrl: session.url });
  } catch (err) {
    console.error('Stripe checkout session creation failed', err);
    return NextResponse.json({ error: 'Could not start checkout. Please try again.' }, { status: 500 });
  }
}
