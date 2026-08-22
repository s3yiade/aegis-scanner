import { NextRequest, NextResponse } from 'next/server';
import type Stripe from 'stripe';
import { waitUntil } from '@vercel/functions';
import { getStripe } from '@/lib/stripe';
import { getSupabaseAdmin } from '@/lib/supabase';
import { runSimilarityAnalysis } from '@/lib/scanner/similarityOrchestrator';

export const dynamic = 'force-dynamic';

export const runtime = 'nodejs';
// Runs the full parallel similarity analysis (DOM + visual + reverse
// image, across several candidate domains) synchronously-ish via
// waitUntil after a confirmed payment — give it real room. Same Hobby-
// plan caveat as api/consult: this reliably completes on Pro/Fluid
// Compute, not on Hobby's 10s ceiling.
export const maxDuration = 120;

// Bounds cost/time on what is now a paid feature: only the highest-
// priority candidates get the full (paid-API-backed) similarity analysis,
// not every single lookalike domain ever found.
const SIMILARITY_ANALYSIS_CANDIDATE_LIMIT = 10;

/**
 * Stripe webhook — the ONLY place any paid feature is ever marked as
 * paid. Never trust a client-side "success" redirect for this: a browser
 * can hit the success_url without payment actually completing (closed
 * tab, browser back button after a failed card, replayed URL, etc.).
 * Signature verification (constructEvent) is what makes this
 * trustworthy — it proves the event actually came from Stripe.
 */
export async function POST(req: NextRequest) {
  const signature = req.headers.get('stripe-signature');
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!signature || !webhookSecret) {
    return NextResponse.json({ error: 'Webhook not configured' }, { status: 400 });
  }

  // Signature verification needs the exact raw request body — do not
  // parse as JSON first, or the signature check will fail.
  const rawBody = await req.text();

  let event: Stripe.Event;
  try {
    event = getStripe().webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch (err) {
    console.error('Stripe webhook signature verification failed', err);
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 });
  }

  if (!['checkout.session.completed', 'customer.subscription.deleted', 'customer.subscription.updated'].includes(event.type)) {
    return NextResponse.json({ received: true });
  }

  const supabase = getSupabaseAdmin();

  if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.updated') {
    const subscription = event.data.object as Stripe.Subscription;
    if (subscription.metadata?.type !== 'saas_monitor_pro') return NextResponse.json({ received: true });

    // Cancelled, or payment failed and it lapsed past Stripe's retry
    // schedule ('unpaid'/'incomplete_expired') — either way, downgrade to
    // the free tier rather than deactivating the monitor entirely. They
    // keep the free weekly "your score changed" email; they lose Pro's
    // daily/weekly diff reports until they resubscribe. Deliberately not
    // punitive (no data deleted, monitoring doesn't just stop) — the goal
    // is graceful downgrade, not lockout.
    const stillActive = subscription.status === 'active' || subscription.status === 'trialing';

    await supabase
      .from('monitors')
      .update(
        stillActive
          ? { tier: 'pro' } // e.g. recovered from past_due — make sure it's back to pro
          : { tier: 'free' }
      )
      .eq('stripe_subscription_id', subscription.id);

    return NextResponse.json({ received: true });
  }

  const session = event.data.object as Stripe.Checkout.Session;
  const type = session.metadata?.type;

  if (type === 'clone_report_unlock') {
    const consultRequestId = session.metadata?.consultRequestId;
    const scanId = session.metadata?.scanId;
    if (!consultRequestId || !scanId) return NextResponse.json({ received: true });

    await supabase
      .from('consult_requests')
      .update({ paid: true, stripe_session_id: session.id })
      .eq('id', consultRequestId);

    waitUntil(runPaidSimilarityAnalysis(scanId, consultRequestId));
  } else if (type === 'domain_watch_subscription') {
    const subscriptionId = session.metadata?.subscriptionId;
    if (!subscriptionId) return NextResponse.json({ received: true });

    await supabase
      .from('clone_watch_subscriptions')
      .update({ paid: true, active: true, stripe_session_id: session.id })
      .eq('id', subscriptionId);
  } else if (type === 'fix_guide_unlock') {
    const purchaseId = session.metadata?.purchaseId;
    if (!purchaseId) return NextResponse.json({ received: true });

    await supabase
      .from('fix_guide_purchases')
      .update({ paid: true, stripe_session_id: session.id })
      .eq('id', purchaseId);
  } else if (type === 'saas_monitor_pro') {
    const upgradeId = session.metadata?.upgradeId;
    if (!upgradeId) return NextResponse.json({ received: true });

    const { data: upgrade } = await supabase.from('monitor_pro_upgrades').select('*').eq('id', upgradeId).single();
    if (!upgrade) return NextResponse.json({ received: true });

    await supabase.from('monitor_pro_upgrades').update({ paid: true, stripe_session_id: session.id }).eq('id', upgradeId);

    // session.subscription/session.customer are populated because checkout
    // was created with mode: 'subscription' (see api/stripe/checkout) —
    // stored so the subscription.deleted/updated handler above can find
    // this monitor later, and so api/stripe/portal can open a billing
    // portal session for this subscriber to manage/cancel.
    const subscriptionId = typeof session.subscription === 'string' ? session.subscription : session.subscription?.id ?? null;
    const customerId = typeof session.customer === 'string' ? session.customer : session.customer?.id ?? null;

    // Upserts into the actual live `monitors` row — creating it if this is
    // a brand-new monitor, or upgrading it in place if a free monitor for
    // the same hostname/email already existed (see the unique index on
    // monitors(hostname, email)). next_run_at is set to ~now so the pro
    // tier kicks in on the next hourly cron tick rather than waiting out
    // whatever cadence was already scheduled.
    await supabase.from('monitors').upsert(
      {
        hostname: upgrade.hostname,
        target_url: upgrade.target_url,
        target_type: upgrade.target_type,
        niche: upgrade.niche,
        endpoint_type: upgrade.endpoint_type,
        email: upgrade.email,
        email_trust: upgrade.email_trust,
        frequency: upgrade.frequency,
        active: true,
        tier: 'pro',
        pro_activated_at: new Date().toISOString(),
        next_run_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        stripe_subscription_id: subscriptionId,
        stripe_customer_id: customerId,
      },
      { onConflict: 'hostname,email' }
    );
  }

  return NextResponse.json({ received: true });
}

async function runPaidSimilarityAnalysis(scanId: string, consultRequestId: string) {
  const supabase = getSupabaseAdmin();
  try {
    const { data: scan } = await supabase.from('scans').select('target_url, clone_candidates').eq('id', scanId).single();
    if (!scan) return;

    const candidates: { domain: string }[] = scan.clone_candidates ?? [];
    const candidateUrls = candidates.slice(0, SIMILARITY_ANALYSIS_CANDIDATE_LIMIT).map((c) => `https://${c.domain}`);

    if (candidateUrls.length === 0) {
      await supabase.from('consult_requests').update({ similarity_status: 'complete', similarity_results: [] }).eq('id', consultRequestId);
      return;
    }

    const result = await runSimilarityAnalysis(scan.target_url, candidateUrls);

    await supabase
      .from('consult_requests')
      .update({ similarity_status: 'complete', similarity_results: result })
      .eq('id', consultRequestId);
  } catch (err) {
    console.error('Paid similarity analysis failed', err);
    await supabase.from('consult_requests').update({ similarity_status: 'failed' }).eq('id', consultRequestId);
  }
}
