/**
 * Reuses the niche-specific interpretation already developed for direct
 * outreach (see areas/market-outreach) so a scan result speaks to what a
 * given business type actually cares about, instead of generic security
 * jargon. Keyed by a coarse business-type slug the lead selects at scan
 * time; falls back to a generic explanation if none is given.
 *
 * Split into two "kinds" so the scan form can show a different, more
 * relevant list depending on which page the person is on:
 *   - 'general' — the standard/website page (local & professional
 *     businesses: legal/accounting, healthcare, retail, trades, ...).
 *   - 'saas'    — the SaaS/web-app page (multi-tenant software businesses:
 *     fintech, devtools, martech, ...), where the risk framing is about
 *     customer data blast radius and platform trust, not a single
 *     storefront or office.
 * `getNicheCopy` doesn't care which kind a niche belongs to — a scan row's
 * stored niche value is looked up the same way regardless — the kind split
 * only drives which options the form offers.
 */

export type Niche =
  // general / website niches
  | 'jewelry'
  | 'ecommerce'
  | 'professional_services'
  | 'healthcare'
  | 'contractor_trades'
  | 'restaurant_hospitality'
  // SaaS / web-app niches
  | 'fintech_payments'
  | 'healthtech_saas'
  | 'hr_people_ops'
  | 'martech_adtech'
  | 'devtools_infra'
  | 'ecommerce_platform'
  | 'collab_productivity'
  | 'vertical_b2b_saas'
  | 'generic';

interface NicheCopy {
  label: string;
  kind: 'general' | 'saas';
  whyItMatters: string;
  exposureFraming: string; // used specifically for the exposed-path/data findings
}

const NICHE_COPY: Record<Niche, NicheCopy> = {
  jewelry: {
    label: 'Jewelry / high-value retail',
    kind: 'general',
    whyItMatters:
      'Customer records for a jewelry business often include purchase history and special orders that map directly to who owns valuable items and when — a data exposure here isn\'t just a compliance problem, it\'s a physical security risk for your customers.',
    exposureFraming:
      'An exposed config or database credential could let someone pull customer + purchase records — effectively a shopping list of who owns what.',
  },
  ecommerce: {
    label: 'E-commerce',
    kind: 'general',
    whyItMatters:
      'Every gap here is a potential path to customer payment data, order history, or account takeover — the kind of incident that shows up in chargebacks and lost repeat customers, not just a scary email.',
    exposureFraming:
      'Exposed credentials or admin panels are a direct line to customer and payment data.',
  },
  professional_services: {
    label: 'Professional services (legal, accounting, consulting)',
    kind: 'general',
    whyItMatters:
      'Client files and correspondence are the business — a breach here is a confidentiality and liability problem before it\'s a technical one.',
    exposureFraming:
      'An exposed config file or admin panel could expose client communications or case/engagement files.',
  },
  healthcare: {
    label: 'Healthcare / clinic',
    kind: 'general',
    whyItMatters:
      'Patient information carries specific regulatory obligations (and specific penalties) on top of the reputational damage of a breach — this isn\'t optional hardening, it\'s compliance-adjacent. Note: this is a website/infrastructure security scan, not a HIPAA/PHIPA compliance assessment — a passing grade here doesn\'t mean this practice is compliant, since compliance covers policies, access controls, and handling practices this scan can\'t see.',
    exposureFraming:
      'Any exposed credential or panel here is a potential patient-data incident, which triggers disclosure obligations most clinics aren\'t staffed to handle.',
  },
  contractor_trades: {
    label: 'Contractor / trades',
    kind: 'general',
    whyItMatters:
      'Your booking and customer contact system is often the only thing standing between "business running" and "no way to schedule a job" — these gaps are as much an uptime risk as a data risk.',
    exposureFraming:
      'An exposed panel or credential could let someone take your booking system offline or reroute customer inquiries.',
  },
  restaurant_hospitality: {
    label: 'Restaurant / hospitality',
    kind: 'general',
    whyItMatters:
      'Reservation systems and any stored payment or loyalty data are the target here — and a defaced or offline site during peak hours has an immediate revenue cost.',
    exposureFraming:
      'Exposed admin access could mean a defaced site or altered reservation data during your busiest hours.',
  },

  // --- SaaS / web-app niches ---
  fintech_payments: {
    label: 'Fintech / payments SaaS',
    kind: 'saas',
    whyItMatters:
      'You\'re holding transaction data, account/routing or card metadata, and often a direct integration into money movement — regulators, banking partners, and card networks all expect a specific security bar, and a single misconfigured endpoint here is a wire-fraud or PCI incident, not just a support ticket.',
    exposureFraming:
      'An exposed credential, admin panel, or unauthenticated billing/payments endpoint is a direct path to transaction data or the ability to move money.',
  },
  healthtech_saas: {
    label: 'Healthtech / digital health SaaS',
    kind: 'saas',
    whyItMatters:
      'Multi-tenant health platforms carry PHI for every customer\'s patients at once, so one platform-level gap becomes a breach notification for all of them simultaneously. Note: this is an infrastructure/security scan, not a HIPAA compliance assessment — a passing grade doesn\'t certify BAAs, access controls, or handling practices this scan can\'t see.',
    exposureFraming:
      'An exposed admin, profile, or billing endpoint on a shared platform is potentially every tenant\'s patient data at once, not just one.',
  },
  hr_people_ops: {
    label: 'HR / people-ops SaaS',
    kind: 'saas',
    whyItMatters:
      'HR platforms sit on SSNs/national IDs, salary data, background checks, and immigration documents across every customer they serve — this is exactly the profile identity-theft and social-engineering campaigns target, and it\'s cross-tenant by design.',
    exposureFraming:
      'An exposed admin or profile endpoint here is a route to employee PII across every company using the platform, not just one workforce.',
  },
  martech_adtech: {
    label: 'Martech / ad-tech SaaS',
    kind: 'saas',
    whyItMatters:
      'These platforms typically hold customer contact lists, campaign/audience data, and often OAuth tokens into other ad and CRM accounts — a leak here cascades into every connected account, and CORS/API gaps are the most common way that data walks out.',
    exposureFraming:
      'A CORS misconfiguration or exposed billing/admin endpoint can expose customer contact lists or the connected-account tokens tied to them.',
  },
  devtools_infra: {
    label: 'Developer tools / infrastructure SaaS',
    kind: 'saas',
    whyItMatters:
      'Your customers hand you API keys, deploy credentials, and often direct access to their own infrastructure — a gap in your platform is a supply-chain foothold into every customer environment you touch, which is why this niche gets extra scrutiny on secrets, source maps, and admin/internal endpoint exposure.',
    exposureFraming:
      'An exposed admin, internal, or webhook endpoint here is a plausible pivot point into customer infrastructure, not just your own.',
  },
  ecommerce_platform: {
    label: 'E-commerce platform / plugin',
    kind: 'saas',
    whyItMatters:
      'As a platform rather than a single store, a gap here multiplies across every merchant running on you — payment data, order history, and storefront admin access for many businesses at once, which is a different blast radius than a single online store.',
    exposureFraming:
      'An exposed billing or admin endpoint could touch payment/order data across every merchant on the platform, not one storefront.',
  },
  collab_productivity: {
    label: 'Collaboration / productivity SaaS',
    kind: 'saas',
    whyItMatters:
      'Documents, messages, and file storage across every connected workspace is the product — an auth or CORS gap doesn\'t leak "a page," it leaks other people\'s internal company communications and files.',
    exposureFraming:
      'A CORS gap or exposed profile/admin endpoint can expose one workspace\'s internal files and messages to another.',
  },
  vertical_b2b_saas: {
    label: 'Vertical B2B SaaS (other)',
    kind: 'saas',
    whyItMatters:
      'Multi-tenant B2B software concentrates many customers\' operational data behind the same codebase — the usual framing of "a breach affects one business" doesn\'t apply; it affects everyone on the platform at once.',
    exposureFraming:
      'An exposed admin, billing, or profile endpoint here is cross-tenant exposure, not a single customer\'s incident.',
  },

  generic: {
    label: 'General business',
    kind: 'general',
    whyItMatters:
      'These findings translate to real risk: customer trust, downtime, and in some cases direct financial exposure if credentials or customer data are reachable.',
    exposureFraming: 'Exposed credentials or admin panels are one of the most common paths to a full breach.',
  },
};

export function getNicheCopy(niche?: string | null): NicheCopy {
  if (niche && niche in NICHE_COPY) return NICHE_COPY[niche as Niche];
  return NICHE_COPY.generic;
}

/**
 * @param kind Restrict to 'general' (standard/website page) or 'saas' (SaaS
 * page) niches. Omit to get every niche (used by admin/reporting contexts
 * that need the full set regardless of which page a scan came from).
 */
export function listNiches(kind?: 'general' | 'saas'): { value: Niche; label: string }[] {
  return (Object.keys(NICHE_COPY) as Niche[])
    .filter((n) => n !== 'generic')
    .filter((n) => !kind || NICHE_COPY[n].kind === kind)
    .map((value) => ({ value, label: NICHE_COPY[value].label }));
}
