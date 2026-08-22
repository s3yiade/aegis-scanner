import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getStripe } from '@/lib/stripe';
import { getSupabaseAdmin } from '@/lib/supabase';
import { checkRateLimit, getClientIp } from '@/lib/ratelimit';
import { isSameOrigin } from '@/lib/originCheck';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const BodySchema = z.object({
  monitorId: z.string().uuid(),
  token: z.string().min(10),
});

/**
 * Opens a Stripe billing portal session so a Pro monitor subscriber can
 * manage or cancel their subscription — required for a real recurring
 * charge (see api/stripe/checkout's mode: 'subscription'); there's no
 * account/login system in this app, so this reuses the same
 * unsubscribe_token possession model as the diff-history route
 * (api/monitor/[id]/diffs) rather than introducing a separate auth path.
 */
export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: 'Invalid request origin' }, { status: 403 });
  }

  const clientIp = getClientIp(req.headers);
  // 'lookup' bucket, not 'scan': this creates a real Stripe API call per
  // request, worth its own tighter cap independent of scan quota, same
  // reasoning as /api/my-scans and the diffs route above.
  const rl = await checkRateLimit(clientIp, 'lookup');
  if (!rl.allowed) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  }

  let body: z.infer<typeof BodySchema>;
  try {
    body = BodySchema.parse(await req.json());
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }

  const supabase = getSupabaseAdmin();
  const { data: monitor, error } = await supabase
    .from('monitors')
    .select('id, stripe_customer_id, tier')
    .eq('id', body.monitorId)
    .eq('unsubscribe_token', body.token)
    .maybeSingle();

  if (error || !monitor) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  if (!monitor.stripe_customer_id) {
    // Either never subscribed, already downgraded, or an admin-granted
    // Pro monitor (which has no real Stripe subscription behind it — see
    // the admin branch in api/stripe/checkout — so there's nothing to
    // manage here).
    return NextResponse.json({ error: 'No active billing subscription found for this monitor.' }, { status: 400 });
  }

  const appUrl = process.env.APP_URL || req.nextUrl.origin;

  try {
    const portalSession = await getStripe().billingPortal.sessions.create({
      customer: monitor.stripe_customer_id,
      return_url: `${appUrl}/monitor/${monitor.id}?token=${body.token}`,
    });
    return NextResponse.json({ portalUrl: portalSession.url });
  } catch (err) {
    console.error('Could not create billing portal session', err);
    return NextResponse.json({ error: 'Could not open billing portal. Please try again.' }, { status: 500 });
  }
}
