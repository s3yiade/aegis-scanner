import dns from 'node:dns/promises';
import { parse } from 'tldts';
import { checkRdapRegistration } from '@/lib/dnsRdap';
import type { CloneCandidate } from '@/types/scan';

/**
 * Generates plausible typosquat/lookalike variants of a domain (dnstwist-
 * style: omission, transposition, adjacent-key substitution, homoglyph
 * substitution, common confusable pairs, IDN homograph substitution,
 * hyphenation, TLD swap) and checks which ones are actually registered —
 * either actively resolving (DNS) or registered-but-dormant (RDAP, no DNS
 * yet). This runs automatically on every scan since it's bounded and
 * doesn't require a paid API, but the resulting domain list is only ever
 * shown after a consult/paywall gate (see api/consult) — only the count
 * is safe to show for free.
 *
 * Fixes applied vs. the original version:
 *   1. Round-robin candidate generation across categories instead of
 *      depleting one category before the next — a long domain label could
 *      previously exhaust the whole MAX_CANDIDATES budget on early
 *      categories, silently dropping TLD-swap (arguably the single most
 *      realistic pattern) entirely for longer names.
 *   2. Homoglyph coverage expanded, plus a dedicated multi-char confusable-
 *      pair pass (rn->m, vv->w, cl->d, etc.) and a real IDN/Unicode
 *      homograph pass (Cyrillic lookalikes) — the original only covered 8
 *      ASCII digit-lookalike letters and had zero Unicode coverage, which
 *      is the more sophisticated version of this attack in practice.
 *   3. Checks both A and AAAA records — the original was IPv4-only and
 *      would miss an IPv6-only-hosted clone entirely.
 *   4. Retries once on DNS timeout before giving up, to reduce false
 *      negatives from transient network jitter rather than genuine
 *      non-registration.
 *   5. RDAP-checks a bounded subset of non-resolving candidates to catch
 *      registered-but-dormant domains — see registrationStatus on
 *      CloneCandidate and dnsRdap.ts for why this matters.
 */

const MAX_CANDIDATES = 120;
const DNS_TIMEOUT_MS = 4000;
const DNS_RETRY_ATTEMPTS = 2;
const DNS_CONCURRENCY = 20;
// RDAP lookups are a per-domain live query against a real registry server,
// not a cheap local operation like DNS — checking all ~100 non-resolving
// candidates on every free scan would meaningfully slow every scan and
// risks looking like abuse to registries. Bounded, and biased toward the
// highest-signal categories (see prioritizeForRdap below) so the domains
// most worth flagging are the ones actually checked.
const RDAP_CHECK_LIMIT = 25;
const RDAP_CONCURRENCY = 5;

const QWERTY_NEIGHBORS: Record<string, string> = {
  q: 'wa', w: 'qeas', e: 'wrsd', r: 'etdf', t: 'ryfg', y: 'tugh', u: 'yihj',
  i: 'uojk', o: 'ipkl', p: 'ol', a: 'qwsz', s: 'awedxz', d: 'serfcx',
  f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', j: 'huikmn', k: 'jiolm', l: 'kop',
  z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk',
};

const HOMOGLYPHS: Record<string, string[]> = {
  o: ['0'], i: ['1', 'l'], l: ['1', 'i'], e: ['3'], a: ['4'], s: ['5'],
  g: ['9'], b: ['6'], z: ['2'], t: ['7'],
};

// Multi-character visual confusables — the classic typosquat trick of
// combining two letters to mimic a third (rn -> m is the canonical
// example). Single-character homoglyph substitution above can't produce
// these since they change the label length/shape, not just one glyph.
const CONFUSABLE_PAIRS: [string, string][] = [
  ['rn', 'm'], ['vv', 'w'], ['cl', 'd'], ['ii', 'n'], ['m', 'rn'], ['w', 'vv'],
];

// A small set of Cyrillic letters that are visually identical or
// near-identical to their Latin counterparts — the basis of real IDN
// homograph phishing attacks (the resulting domain is a different
// Unicode string that punycode-encodes to a completely different ASCII
// domain, e.g. "аpple.com" with a Cyrillic а is not apple.com at all).
const CYRILLIC_CONFUSABLES: Record<string, string> = {
  a: 'а', e: 'е', o: 'о', p: 'р', c: 'с', x: 'х', y: 'у',
};

const ALT_TLDS = ['com', 'net', 'org', 'co', 'io', 'info', 'biz', 'online', 'xyz', 'shop', 'ca', 'us'];

function omissions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length; i++) out.push(label.slice(0, i) + label.slice(i + 1));
  return out;
}

function transpositions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length - 1; i++) {
    const a = label[i];
    const b = label[i + 1];
    if (a === undefined || b === undefined) continue; // unreachable given the loop bound, but keeps the type checker honest
    out.push(label.slice(0, i) + b + a + label.slice(i + 2));
  }
  return out;
}

function adjacentSubstitutions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length; i++) {
    const char = label[i];
    if (!char) continue;
    const neighbors = QWERTY_NEIGHBORS[char];
    if (!neighbors) continue;
    for (const n of neighbors) out.push(label.slice(0, i) + n + label.slice(i + 1));
  }
  return out;
}

function homoglyphSubstitutions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length; i++) {
    const char = label[i];
    if (!char) continue;
    const subs = HOMOGLYPHS[char];
    if (!subs) continue;
    for (const s of subs) out.push(label.slice(0, i) + s + label.slice(i + 1));
  }
  return out;
}

function confusablePairSubstitutions(label: string): string[] {
  const out: string[] = [];
  for (const [from, to] of CONFUSABLE_PAIRS) {
    if (label.includes(from)) out.push(label.replace(from, to));
  }
  return out;
}

function idnHomographSubstitutions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length; i++) {
    const char = label[i];
    if (!char) continue;
    const sub = CYRILLIC_CONFUSABLES[char];
    if (!sub) continue;
    out.push(label.slice(0, i) + sub + label.slice(i + 1));
  }
  return out;
}

function hyphenations(label: string): string[] {
  const out: string[] = [];
  for (let i = 1; i < label.length; i++) out.push(label.slice(0, i) + '-' + label.slice(i));
  return out;
}

function repetitions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length; i++) {
    const char = label[i];
    if (char === undefined) continue; // unreachable given the loop bound, but keeps the type checker honest
    out.push(label.slice(0, i) + char + label.slice(i));
  }
  return out;
}

interface Permutation {
  domain: string; // human-readable form — may contain Unicode (IDN) chars
  type: string;
}

/** Converts a possibly-Unicode domain label to its ASCII/punycode form for
 * DNS resolution — the WHATWG URL parser applies IDNA processing, which is
 * exactly what's needed here without pulling in a separate punycode lib. */
function toAsciiDomain(domain: string): string | null {
  try {
    return new URL(`http://${domain}`).hostname;
  } catch {
    return null;
  }
}

function generateCandidates(hostname: string): Permutation[] {
  const parsed = parse(hostname);
  const label = parsed.domainWithoutSuffix;
  const suffix = parsed.publicSuffix;
  if (!label || !suffix) return [];

  const realDomain = `${label}.${suffix}`.toLowerCase();

  // Ordered by realistic-abuse value, not alphabetically — this matters
  // now because generation is round-robin (see below): the categories
  // listed first get first priority for a slot on every round, so a
  // small-but-high-signal category can never be crowded out by a large
  // one, no matter how long the domain label is.
  const categoryLists: { type: string; domains: string[] }[] = [
    { type: 'tld-swap', domains: ALT_TLDS.filter((t) => t !== suffix).map((t) => `${label}.${t}`) },
    { type: 'idn-homograph', domains: idnHomographSubstitutions(label).map((l) => `${l}.${suffix}`) },
    { type: 'homoglyph', domains: homoglyphSubstitutions(label).map((l) => `${l}.${suffix}`) },
    { type: 'confusable-pair', domains: confusablePairSubstitutions(label).map((l) => `${l}.${suffix}`) },
    { type: 'transposition', domains: transpositions(label).map((l) => `${l}.${suffix}`) },
    { type: 'hyphenation', domains: hyphenations(label).map((l) => `${l}.${suffix}`) },
    { type: 'omission', domains: omissions(label).map((l) => `${l}.${suffix}`) },
    { type: 'repetition', domains: repetitions(label).map((l) => `${l}.${suffix}`) },
    { type: 'adjacent-substitution', domains: adjacentSubstitutions(label).map((l) => `${l}.${suffix}`) },
  ];

  const seen = new Set<string>([realDomain]);
  const result: Permutation[] = [];
  const indices = categoryLists.map(() => 0);

  let anyRemaining = true;
  while (anyRemaining && result.length < MAX_CANDIDATES) {
    anyRemaining = false;
    for (let c = 0; c < categoryLists.length; c++) {
      const list = categoryLists[c];
      const idx = indices[c];
      if (!list || idx === undefined || idx >= list.domains.length) continue;
      anyRemaining = true;
      const domain = list.domains[idx];
      indices[c] = idx + 1;
      if (domain === undefined) continue;
      const key = domain.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        result.push({ domain, type: list.type });
        if (result.length >= MAX_CANDIDATES) break;
      }
    }
  }

  return result;
}

function resolveWithTimeout(asciiDomain: string): Promise<string[] | null> {
  return Promise.race([
    Promise.allSettled([dns.resolve4(asciiDomain), dns.resolve6(asciiDomain)]).then((results) => {
      const ips = results.flatMap((r) => (r.status === 'fulfilled' ? r.value : []));
      return ips.length > 0 ? ips : null;
    }),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), DNS_TIMEOUT_MS)),
  ]);
}

async function resolveWithRetry(asciiDomain: string): Promise<string[] | null> {
  for (let attempt = 0; attempt < DNS_RETRY_ATTEMPTS; attempt++) {
    const result = await resolveWithTimeout(asciiDomain);
    if (result) return result;
  }
  return null;
}

async function resolveBatch(
  candidates: Permutation[]
): Promise<{ active: CloneCandidate[]; dormantCheckPool: Permutation[] }> {
  const active: CloneCandidate[] = [];
  const notResolved: Permutation[] = [];

  for (let i = 0; i < candidates.length; i += DNS_CONCURRENCY) {
    const batch = candidates.slice(i, i + DNS_CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (c) => {
        const ascii = toAsciiDomain(c.domain);
        if (!ascii) return { c, ips: null };
        return { c, ips: await resolveWithRetry(ascii) };
      })
    );
    for (const { c, ips } of results) {
      if (ips && ips.length > 0) {
        active.push({ domain: c.domain, permutationType: c.type, resolvedIps: ips, registrationStatus: 'active' });
      } else {
        notResolved.push(c);
      }
    }
  }

  return { active, dormantCheckPool: notResolved };
}

/** Prioritizes which non-resolving candidates are worth an RDAP lookup —
 * the small, high-signal categories first, since RDAP checks are bounded
 * by RDAP_CHECK_LIMIT and shouldn't be spent on the largest, lowest-signal
 * category (adjacent-key substitution typos) before the more deliberate
 * ones (TLD swap, homoglyph, IDN homograph, confusable pairs). */
function prioritizeForRdap(candidates: Permutation[]): Permutation[] {
  const priority: Record<string, number> = {
    'tld-swap': 0, 'idn-homograph': 1, 'homoglyph': 2, 'confusable-pair': 3,
    'hyphenation': 4, 'transposition': 5, 'omission': 6, 'repetition': 7, 'adjacent-substitution': 8,
  };
  return [...candidates].sort((a, b) => (priority[a.type] ?? 9) - (priority[b.type] ?? 9));
}

async function checkDormantRegistrations(pool: Permutation[]): Promise<CloneCandidate[]> {
  const toCheck = prioritizeForRdap(pool).slice(0, RDAP_CHECK_LIMIT);
  const dormant: CloneCandidate[] = [];

  for (let i = 0; i < toCheck.length; i += RDAP_CONCURRENCY) {
    const batch = toCheck.slice(i, i + RDAP_CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (c) => {
        const ascii = toAsciiDomain(c.domain) ?? c.domain;
        const registered = await checkRdapRegistration(ascii);
        return { c, registered };
      })
    );
    for (const { c, registered } of results) {
      if (registered === true) {
        dormant.push({ domain: c.domain, permutationType: c.type, resolvedIps: [], registrationStatus: 'registered_dormant' });
      }
    }
  }

  return dormant;
}

/** Re-checks a single domain's DNS activation status — used by the
 * dormant-domain watch cron to see if a previously-dormant candidate has
 * gone live since the original scan. */
export async function checkDomainNowActive(domain: string): Promise<string[] | null> {
  const ascii = toAsciiDomain(domain);
  if (!ascii) return null;
  return resolveWithRetry(ascii);
}

/** Returns domains that are either actively resolving or confirmed
 * registered-but-dormant via RDAP — a live/registered lookalike domain is
 * the meaningful signal, not every permutation tried. See
 * registrationStatus on each result: 'active' domains have a real DNS
 * presence right now; 'registered_dormant' ones are held but not yet
 * pointed anywhere — often exactly the pre-launch window for a phishing
 * clone, per the explanation shown to users on the report page. */
export async function scanForCloneDomains(hostname: string): Promise<CloneCandidate[]> {
  const candidates = generateCandidates(hostname);
  if (candidates.length === 0) return [];

  const { active, dormantCheckPool } = await resolveBatch(candidates);
  const dormant = await checkDormantRegistrations(dormantCheckPool);

  return [...active, ...dormant];
}
