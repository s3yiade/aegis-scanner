/**
 * Reuses the niche-specific interpretation already developed for direct
 * outreach (see areas/market-outreach) so a scan result speaks to what a
 * given business type actually cares about, instead of generic security
 * jargon. Keyed by a coarse business-type slug the lead selects at report
 * unlock time; falls back to a generic explanation if none is given.
 */

export type Niche =
  | 'jewelry'
  | 'ecommerce'
  | 'professional_services'
  | 'healthcare'
  | 'contractor_trades'
  | 'restaurant_hospitality'
  | 'generic';

interface NicheCopy {
  label: string;
  whyItMatters: string;
  exposureFraming: string; // used specifically for the exposed-path/data findings
}

const NICHE_COPY: Record<Niche, NicheCopy> = {
  jewelry: {
    label: 'Jewelry / high-value retail',
    whyItMatters:
      'Customer records for a jewelry business often include purchase history and special orders that map directly to who owns valuable items and when — a data exposure here isn\'t just a compliance problem, it\'s a physical security risk for your customers.',
    exposureFraming:
      'An exposed config or database credential could let someone pull customer + purchase records — effectively a shopping list of who owns what.',
  },
  ecommerce: {
    label: 'E-commerce',
    whyItMatters:
      'Every gap here is a potential path to customer payment data, order history, or account takeover — the kind of incident that shows up in chargebacks and lost repeat customers, not just a scary email.',
    exposureFraming:
      'Exposed credentials or admin panels are a direct line to customer and payment data.',
  },
  professional_services: {
    label: 'Professional services (legal, accounting, consulting)',
    whyItMatters:
      'Client files and correspondence are the business — a breach here is a confidentiality and liability problem before it\'s a technical one.',
    exposureFraming:
      'An exposed config file or admin panel could expose client communications or case/engagement files.',
  },
  healthcare: {
    label: 'Healthcare / clinic',
    whyItMatters:
      'Patient information carries specific regulatory obligations (and specific penalties) on top of the reputational damage of a breach — this isn\'t optional hardening, it\'s compliance-adjacent. Note: this is a website/infrastructure security scan, not a HIPAA/PHIPA compliance assessment — a passing grade here doesn\'t mean this practice is compliant, since compliance covers policies, access controls, and handling practices this scan can\'t see.',
    exposureFraming:
      'Any exposed credential or panel here is a potential patient-data incident, which triggers disclosure obligations most clinics aren\'t staffed to handle.',
  },
  contractor_trades: {
    label: 'Contractor / trades',
    whyItMatters:
      'Your booking and customer contact system is often the only thing standing between "business running" and "no way to schedule a job" — these gaps are as much an uptime risk as a data risk.',
    exposureFraming:
      'An exposed panel or credential could let someone take your booking system offline or reroute customer inquiries.',
  },
  restaurant_hospitality: {
    label: 'Restaurant / hospitality',
    whyItMatters:
      'Reservation systems and any stored payment or loyalty data are the target here — and a defaced or offline site during peak hours has an immediate revenue cost.',
    exposureFraming:
      'Exposed admin access could mean a defaced site or altered reservation data during your busiest hours.',
  },
  generic: {
    label: 'General business',
    whyItMatters:
      'These findings translate to real risk: customer trust, downtime, and in some cases direct financial exposure if credentials or customer data are reachable.',
    exposureFraming: 'Exposed credentials or admin panels are one of the most common paths to a full breach.',
  },
};

export function getNicheCopy(niche?: string | null): NicheCopy {
  if (niche && niche in NICHE_COPY) return NICHE_COPY[niche as Niche];
  return NICHE_COPY.generic;
}

export function listNiches(): { value: Niche; label: string }[] {
  return (Object.keys(NICHE_COPY) as Niche[])
    .filter((n) => n !== 'generic')
    .map((value) => ({ value, label: NICHE_COPY[value].label }));
}
