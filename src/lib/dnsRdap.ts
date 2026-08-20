/**
 * Checks whether a domain is registered at all, independent of whether it
 * currently resolves via DNS. This is the fix for a real blind spot in
 * DNS-only lookalike-domain detection: a threat actor commonly registers a
 * lookalike domain and sits on it — unconfigured, no DNS records — for
 * days or weeks while the clone site is prepared. During that window a
 * DNS-only check reports "not found," even though the domain is actively
 * held and a live threat is imminent.
 *
 * Uses rdap.org, a public RDAP bootstrap redirector — it looks up which
 * registry's RDAP server is authoritative for a given TLD (per IANA's
 * bootstrap registry) and redirects there, so this doesn't need per-TLD
 * server configuration or ICANN zone-file access. RDAP is the modern,
 * free, standardized WHOIS replacement; ICANN has required it for all
 * gTLD registries since 2019. ccTLD support varies — an inconclusive
 * result is treated as "unknown," never as "not registered."
 */
export async function checkRdapRegistration(asciiDomain: string): Promise<boolean | null> {
  try {
    const res = await fetch(`https://rdap.org/domain/${asciiDomain}`, {
      signal: AbortSignal.timeout(4000),
      headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)', Accept: 'application/rdap+json' },
    });
    if (res.status === 200) return true;
    if (res.status === 404) return false;
    // Rate-limited, unsupported registry, or any other non-definitive
    // response — treat as unknown rather than asserting non-registration.
    return null;
  } catch {
    return null;
  }
}
