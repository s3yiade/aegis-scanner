import type { Finding } from '@/types/scan';

/**
 * Queries crt.sh (a public Certificate Transparency log aggregator) for
 * every certificate ever issued covering this domain, to surface
 * subdomains DNS-based discovery misses — forgotten staging environments,
 * old admin panels, anything that had a cert issued once and was never
 * torn down. Purely informational: this reports what's discoverable, it
 * doesn't probe any of the discovered hosts itself (that's meaningfully
 * more request volume than this scan's existing bounded-check philosophy
 * allows for a single informational check).
 *
 * Same reasoning as cloudStorage.ts for using plain fetch instead of
 * pinnedFetch: the destination (crt.sh) is a fixed external service this
 * code chose, not something derived from the scanned target's own
 * DNS/redirects — the registrable domain is passed as a query parameter,
 * not used to build the destination host.
 */

const TIMEOUT_MS = 9000; // crt.sh can be slow under load — worth a longer budget for one request
const MAX_DISPLAYED = 20;
const USER_AGENT = 'AegisScanner/1.0 (+security-scan)';

interface CrtShRecord {
  name_value?: string;
  common_name?: string;
}

export async function checkCertTransparencySubdomains(registrableDomain: string): Promise<Finding[]> {
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${registrableDomain}`)}&output=json`;

  let records: CrtShRecord[];
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
    });
    if (res.status !== 200) {
      return [unreachableFinding(`crt.sh returned HTTP ${res.status}`)];
    }
    const text = await res.text();
    records = text.trim() ? JSON.parse(text) : [];
  } catch {
    return [unreachableFinding('crt.sh was unreachable or timed out (it rate-limits aggressively under load)')];
  }

  const subdomains = new Set<string>();
  for (const record of records) {
    const raw = `${record.name_value ?? ''}\n${record.common_name ?? ''}`;
    for (const line of raw.split('\n')) {
      const name = line.trim().toLowerCase();
      if (!name || !name.endsWith(registrableDomain.toLowerCase())) continue;
      if (name.startsWith('*.')) continue; // wildcard cert entries aren't a real discovered host
      subdomains.add(name);
    }
  }

  const sorted = [...subdomains].sort();

  if (sorted.length === 0) {
    return [
      {
        id: 'ct-log-subdomains',
        category: 'dns',
        title: 'Certificate Transparency subdomain discovery',
        severity: 'info',
        detail: 'No subdomains found in public CT logs for this domain.',
        recommendation: 'Not applicable.',
        passed: true,
      },
    ];
  }

  const shown = sorted.slice(0, MAX_DISPLAYED);
  const remainder = sorted.length - shown.length;

  return [
    {
      id: 'ct-log-subdomains',
      category: 'dns',
      title: 'Subdomains discovered via Certificate Transparency logs',
      severity: 'info',
      detail: `${sorted.length} distinct subdomain(s) have had a certificate issued: ${shown.join(', ')}${remainder > 0 ? `, and ${remainder} more` : ''}.`,
      recommendation:
        'Review this list for anything unexpected — old staging environments, deprecated admin panels, or test deployments that still resolve and are still live. Certificates get issued once and are rarely cleaned up when a subdomain is retired, so this list is attack-surface history, not just current infrastructure.',
      passed: true,
    },
  ];
}

function unreachableFinding(reason: string): Finding {
  return {
    id: 'ct-log-subdomains',
    category: 'dns',
    title: 'Certificate Transparency subdomain discovery',
    severity: 'info',
    detail: `Could not query Certificate Transparency logs: ${reason}.`,
    recommendation: 'Not conclusive either way — this is an external dependency (crt.sh), not a property of the scanned target.',
    passed: true,
  };
}
