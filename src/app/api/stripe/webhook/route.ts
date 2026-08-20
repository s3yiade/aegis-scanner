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
 * Stripe webhook — the ONLY place either paid feature is ever marked as
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

  if (event.type !== 'checkout.session.completed') {
    return NextResponse.json({ received: true });
  }

  const session = event.data.object as Stripe.Checkout.Session;
  const type = session.metadata?.type;
  const supabase = getSupabaseAdmin();

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
