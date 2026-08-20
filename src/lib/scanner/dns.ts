import dns from 'node:dns/promises';
import type { Finding } from '@/types/scan';

/**
 * DMARC records are a semicolon-separated tag=value list (RFC 7489 §6.3),
 * e.g. "v=DMARC1; p=reject; sp=quarantine; rua=mailto:...". A naive
 * /p=(\w+)/ regex over the raw string will happily match the "p=" that's
 * a substring of "sp=" (subdomain policy) if that tag happens to appear
 * before the real "p=" tag — misreading a domain's actual policy. This
 * splits on ';' and matches each tag by its exact, trimmed key instead.
 */
function getDmarcTag(record: string | undefined, tag: string): string | undefined {
  if (!record) return undefined;
  for (const part of record.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key?.trim().toLowerCase() === tag) {
      return rest.join('=').trim();
    }
  }
  return undefined;
}

export async function checkDns(hostname: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // SPF (TXT record on the apex domain)
  try {
    const txtRecords = await dns.resolveTxt(hostname);
    const spf = txtRecords.map((r) => r.join('')).find((r) => /^v=spf1(\s|$)/i.test(r));
    findings.push({
      id: 'spf',
      category: 'dns',
      title: 'SPF record',
      severity: spf ? 'pass' : 'medium',
      detail: spf ? `Found: ${spf}` : 'No SPF record found',
      recommendation:
        'Publish an SPF TXT record so receiving mail servers know which servers are authorized to send email for this domain, reducing spoofing risk.',
      passed: Boolean(spf),
    });

    if (spf) {
      // Distinguish an explicit "+all" (or bare "all", which defaults to
      // +all) — a genuinely dangerous "anyone may send as this domain,
      // and receivers should treat it as authorized" — from simply having
      // no all mechanism at all, which is milder (undefined/neutral
      // handling, not an explicit blanket allow). Previously both cases
      // were reported identically at 'low' severity.
      const hasExplicitAll = /(^|\s)\+?all(\s|$)/.test(spf) && !/[~-]all/.test(spf);
      if (hasExplicitAll) {
        findings.push({
          id: 'spf-permissive',
          category: 'dns',
          title: 'SPF explicitly allows any sender',
          severity: 'high',
          detail: 'SPF record ends in (or defaults to) "+all", which explicitly authorizes mail from ANY server to spoof this domain.',
          recommendation: 'Change "+all"/bare "all" to "-all" (hard fail) or at minimum "~all" (soft fail) immediately — "+all" actively defeats the purpose of having SPF at all.',
          passed: false,
        });
      } else if (!/[~-]all/.test(spf)) {
        findings.push({
          id: 'spf-permissive',
          category: 'dns',
          title: 'SPF policy strictness',
          severity: 'low',
          detail: 'SPF record does not end in a strict qualifier (~all or -all) — receivers fall back to neutral handling for unlisted senders.',
          recommendation: 'End the SPF record with "-all" (or at minimum "~all") to reject/flag mail from unauthorized senders.',
          passed: false,
        });
      }
    }
  } catch {
    findings.push({
      id: 'spf',
      category: 'dns',
      title: 'SPF record',
      severity: 'medium',
      detail: 'No TXT records found or lookup failed',
      recommendation: 'Publish an SPF TXT record for this domain.',
      passed: false,
    });
  }

  // DMARC (TXT record on _dmarc subdomain)
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
    const dmarc = dmarcRecords.map((r) => r.join('')).find((r) => /^v=dmarc1(;|\s|$)/i.test(r));
    const policy = getDmarcTag(dmarc, 'p');
    findings.push({
      id: 'dmarc',
      category: 'dns',
      title: 'DMARC record',
      severity: dmarc ? (policy === 'none' ? 'low' : 'pass') : 'high',
      detail: dmarc ? `Found: ${dmarc}` : 'No DMARC record found',
      recommendation: dmarc
        ? policy === 'none'
          ? 'DMARC policy is "none" (monitor-only). Move to "quarantine" or "reject" once you\'ve confirmed legitimate mail passes.'
          : 'Looks good.'
        : 'Publish a DMARC TXT record at _dmarc.<domain> — this is one of the highest-impact, lowest-effort fixes for email spoofing/phishing risk.',
      passed: Boolean(dmarc) && policy !== 'none',
    });
  } catch {
    findings.push({
      id: 'dmarc',
      category: 'dns',
      title: 'DMARC record',
      severity: 'high',
      detail: 'No DMARC record found',
      recommendation: 'Publish a DMARC TXT record at _dmarc.<domain> to protect against email spoofing/phishing using this domain.',
      passed: false,
    });
  }

  // MX
  try {
    const mx = await dns.resolveMx(hostname);
    findings.push({
      id: 'mx',
      category: 'dns',
      title: 'Mail exchange (MX) records',
      severity: 'info',
      detail: mx.length ? `${mx.length} MX record(s) found` : 'No MX records',
      recommendation: 'Informational — confirms whether this domain receives mail directly.',
      passed: true,
    });
  } catch {
    findings.push({
      id: 'mx',
      category: 'dns',
      title: 'Mail exchange (MX) records',
      severity: 'info',
      detail: 'No MX records found (domain may not receive email directly)',
      recommendation: 'Informational only — not a finding if this domain intentionally does not receive mail.',
      passed: true,
    });
  }

  return findings;
}
