import Stripe from 'stripe';

let stripeClient: Stripe | null = null;

/** Lazily initialized so the app doesn't crash on import if
 * STRIPE_SECRET_KEY isn't set yet — routes that need Stripe check for it
 * explicitly and return a clear error instead. */
export function getStripe(): Stripe {
  if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('STRIPE_SECRET_KEY is not configured');
  }
  if (!stripeClient) {
    stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2025-02-24.acacia' });
  }
  return stripeClient;
}
