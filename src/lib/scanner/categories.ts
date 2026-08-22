import type { Finding } from '@/types/scan';

/**
 * Single source of truth for category labels/order, used by both the
 * report page and the PDF renderer so a finding always shows up under the
 * same section name in both places. Order here is the display order:
 * headers/TLS/DNS first (the checks most people recognize), exposure and
 * webapp last (the deeper/more technical ones).
 */
export const CATEGORY_META: Record<Finding['category'], { label: string; blurb: string }> = {
  headers: {
    label: 'HTTP Security Headers',
    blurb: 'Response headers that control how browsers handle the site (HSTS, CSP, clickjacking protection, cookies).',
  },
  tls: {
    label: 'TLS / Certificate',
    blurb: 'Certificate validity, protocol version, and how the site handles encrypted connections.',
  },
  dns: {
    label: 'DNS & Email Security',
    blurb: 'SPF/DMARC/MX configuration, and DNS records left pointing at deprovisioned resources.',
  },
  exposure: {
    label: 'Exposed Files & Paths',
    blurb: 'Well-known paths that commonly get exposed by accident (env files, VCS metadata, debug endpoints).',
  },
  webapp: {
    label: 'Application-Level Checks',
    blurb: 'CORS configuration, API documentation exposure, and client-side code scanned for accidentally-committed secrets.',
  },
  recon: {
    label: 'Attack-Surface Recon',
    blurb: 'Checks framed the way a threat actor doing reconnaissance on a target would run them: allowed HTTP methods, verbose error disclosure, Host header trust, open redirects, and unauthenticated endpoint exposure — tailored to the endpoint type (billing, admin, profile, webhook, ...) when one is given.',
  },
  cicd: {
    label: 'CI/CD & Supply Chain Exposure',
    blurb: 'Checks for publicly reachable build/deploy configuration — GitHub Actions, CircleCI, Jenkins, GitLab CI, Dockerfiles, Terraform state, and similar — that can leak internal infrastructure details or, in the worst case, credentials committed into the pipeline config itself.',
  },
};

export const CATEGORY_ORDER: Finding['category'][] = ['headers', 'tls', 'dns', 'exposure', 'webapp', 'recon', 'cicd'];

/** Groups findings by category, in CATEGORY_ORDER, dropping empty groups. */
export function groupByCategory(findings: Finding[]): { category: Finding['category']; label: string; findings: Finding[] }[] {
  return CATEGORY_ORDER.map((category) => ({
    category,
    label: CATEGORY_META[category].label,
    findings: findings.filter((f) => f.category === category),
  })).filter((group) => group.findings.length > 0);
}
