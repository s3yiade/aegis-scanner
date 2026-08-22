/**
 * Same pattern as niche.ts, but for the *kind of endpoint* being scanned
 * rather than the business behind it — only relevant when targetType is
 * 'api'. Picking "Billing endpoint" vs "Admin endpoint" vs "Profile
 * endpoint" does two things:
 *   1. Tailors "why this matters" report copy (a reachable billing endpoint
 *      and a reachable admin endpoint are both bad, but for different
 *      reasons a reader should hear about specifically).
 *   2. Adds a short list of endpoint-appropriate paths to the
 *      unauthenticated-access-surface probe in recon.ts, on top of the
 *      generic path list that always runs — e.g. selecting "billing" tries
 *      /api/billing, /api/invoices, etc. in addition to the baseline set.
 * Purely additive and optional: leaving this unset just runs the generic
 * recon path list with generic copy, same as today.
 */

export type EndpointType =
  | 'billing'
  | 'auth_profile'
  | 'admin'
  | 'webhook'
  | 'internal_service'
  | 'public_data';

interface EndpointCopy {
  label: string;
  whyItMatters: string;
  probePaths: string[];
}

const ENDPOINT_COPY: Record<EndpointType, EndpointCopy> = {
  billing: {
    label: 'Billing / payments endpoint',
    whyItMatters:
      'A billing endpoint sits directly on top of subscription state, invoices, and often payment-method metadata — reachable-without-auth here doesn\'t just leak data, it can mean someone can view or manipulate another customer\'s subscription or invoice.',
    probePaths: ['/api/billing', '/api/invoices', '/api/subscription', '/api/subscriptions', '/api/payment-methods', '/billing', '/api/checkout'],
  },
  auth_profile: {
    label: 'Auth / profile endpoint',
    whyItMatters:
      'Profile and account endpoints are the classic broken-access-control target — if one user\'s session can pull another user\'s profile by changing an ID, that\'s a direct account-data leak affecting your entire user base, not a one-off bug.',
    probePaths: ['/api/me', '/api/profile', '/api/user', '/api/account', '/api/users/me', '/api/session'],
  },
  admin: {
    label: 'Admin endpoint',
    whyItMatters:
      'An admin endpoint reachable without authentication is close to a full platform compromise — admin surfaces typically have the broadest read/write access in the system, so this is the single highest-value target a threat actor doing recon on your app would look for first.',
    probePaths: ['/api/admin', '/admin', '/api/admin/users', '/api/admin/dashboard', '/api/admin/settings'],
  },
  webhook: {
    label: 'Webhook / event receiver',
    whyItMatters:
      'Webhook receivers are built to trust their caller (usually verified by a signature, not a login) — the specific risk here is signature verification being missing or misconfigured, which lets anyone forge events (fake payments, fake status updates) rather than just reading data.',
    probePaths: ['/api/webhook', '/api/webhooks', '/webhook', '/webhooks', '/api/stripe/webhook', '/api/events'],
  },
  internal_service: {
    label: 'Internal / microservice endpoint',
    whyItMatters:
      'Internal endpoints are usually built assuming only other internal services can reach them — when one is actually reachable from the public internet, it often skips the auth/validation a public-facing endpoint would have, since it was never meant to face untrusted traffic.',
    probePaths: ['/api/internal', '/internal', '/actuator', '/actuator/health', '/actuator/env', '/debug', '/metrics'],
  },
  public_data: {
    label: 'Public / data API',
    whyItMatters:
      'Even an intentionally public API benefits from checking what\'s reachable beyond the documented surface — undocumented routes, verbose error output, or a missing rate limit here are usually the first things an unfamiliar caller (automated or not) will find while poking around.',
    probePaths: ['/api/v1', '/api/data', '/api/export', '/api/search'],
  },
};

export function getEndpointCopy(endpointType?: string | null): EndpointCopy | null {
  if (endpointType && endpointType in ENDPOINT_COPY) return ENDPOINT_COPY[endpointType as EndpointType];
  return null;
}

export function listEndpointTypes(): { value: EndpointType; label: string }[] {
  return (Object.keys(ENDPOINT_COPY) as EndpointType[]).map((value) => ({ value, label: ENDPOINT_COPY[value].label }));
}
