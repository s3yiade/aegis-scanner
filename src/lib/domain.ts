import { getDomain } from 'tldts';

/**
 * Returns the registrable domain (eTLD+1) for a hostname, correctly
 * handling multi-part public suffixes — "app.example.co.uk" -> "example.co.uk",
 * not the naive last-two-labels guess ("co.uk"). Backed by tldts' bundled
 * public suffix list, so no network call is made at scan time.
 *
 * Falls back to the raw hostname if tldts can't parse it (e.g. a bare IP
 * literal, or an unrecognized private-use TLD) rather than throwing —
 * callers should treat that as "no further normalization possible".
 */
export function getRegistrableDomain(hostname: string): string {
  const domain = getDomain(hostname, { allowPrivateDomains: true });
  return domain ?? hostname.toLowerCase();
}
