import { getDomainWithoutSuffix } from 'tldts';
import { getRegistrableDomain } from '@/lib/domain';

/**
 * Zero-trust framing: the ownership checkbox on the scan form is a
 * legal/audit acknowledgment, not a technical control — anyone can tick a
 * box. This module is the actual signal layer: does the email used to
 * unlock a report or set up monitoring plausibly belong to whoever owns
 * the scanned domain? It never hard-blocks on a mismatch (huge numbers of
 * legitimate small businesses run their inbox on Gmail/Outlook), but it
 * does hard-block disposable/throwaway addresses, and it records a trust
 * classification on every lead/monitor row so low-confidence submissions
 * are visible for manual review instead of silently trusted.
 */

export type EmailTrust = 'domain_match' | 'fuzzy_match' | 'generic_provider' | 'mismatch';

// Small, deliberately conservative list — false negatives (a disposable
// domain we don't catch) are fine, false positives (blocking a real
// business email) are not.
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com',
  'guerrillamail.com',
  'guerrillamail.info',
  'guerrillamail.biz',
  'guerrillamail.de',
  'guerrillamail.net',
  'guerrillamail.org',
  '10minutemail.com',
  '10minutemail.net',
  'tempmail.com',
  'temp-mail.org',
  'temp-mail.io',
  'throwawaymail.com',
  'yopmail.com',
  'yopmail.net',
  'yopmail.fr',
  'trashmail.com',
  'trashmail.net',
  'getnada.com',
  'fakeinbox.com',
  'sharklasers.com',
  'dispostable.com',
  'maildrop.cc',
  'mintemail.com',
  'mailnesia.com',
  'spamgourmet.com',
  'moakt.com',
  'moakt.cc',
  'mohmal.com',
  'emailondeck.com',
  'fakemailgenerator.com',
  'inboxkitten.com',
  'burnermail.io',
  'mailcatch.com',
  'mail-temp.com',
  'tempmailo.com',
  'tempinbox.com',
  'discard.email',
  'discardmail.com',
  'mytemp.email',
  'crazymailing.com',
  'byom.de',
  'anonaddy.me',
  'luxusmail.org',
  'harakirimail.com',
  'jetable.org',
  'spambog.com',
  'spambox.us',
  'mailslurp.com',
  '33mail.com',
  'not-my-email.com',
  'tmpmail.org',
  'tmpmail.net',
  'tmail.ws',
  'tmail.io',
  'incognitomail.com',
  'mailpoof.com',
]);

const GENERIC_PROVIDERS = new Set([
  'gmail.com',
  'yahoo.com',
  'outlook.com',
  'hotmail.com',
  'icloud.com',
  'aol.com',
  'protonmail.com',
  'proton.me',
  'live.com',
  'msn.com',
  'me.com',
  'gmx.com',
  'zoho.com',
]);

export function isDisposableEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase().trim();
  if (!domain) return true; // malformed — treat conservatively
  return isDisposableDomain(domain);
}

/** Exact match OR a subdomain of a known disposable domain — several
 * disposable providers (mailinator's alternate domains, various
 * temp-mail clones) issue addresses on arbitrary subdomains of their
 * base domain (e.g. random123.mailinator.com-style patterns), which an
 * exact Set.has() would miss entirely. */
function isDisposableDomain(domain: string): boolean {
  if (DISPOSABLE_DOMAINS.has(domain)) return true;
  for (const known of DISPOSABLE_DOMAINS) {
    if (domain.endsWith(`.${known}`)) return true;
  }
  return false;
}

/**
 * Classifies how strongly an email suggests ownership of `hostname`.
 * Comparison is done on normalized registrable-domain labels (strips the
 * public suffix and non-alphanumeric characters) so "aegis-security.com"
 * and "aegissecurity.co" still compare sensibly.
 */
export function classifyEmailTrust(email: string, hostname: string): EmailTrust {
  const emailDomain = email.split('@')[1]?.toLowerCase().trim();
  if (!emailDomain) return 'mismatch';

  if (GENERIC_PROVIDERS.has(emailDomain)) return 'generic_provider';

  const siteRegistrable = getRegistrableDomain(hostname);
  const emailRegistrable = getRegistrableDomain(emailDomain);

  if (siteRegistrable === emailRegistrable) return 'domain_match';

  const siteLabel = normalizeLabel(siteRegistrable);
  const emailLabel = normalizeLabel(emailRegistrable);

  // Fuzzy matching on very short labels is unreliable: a single
  // character edit between two completely unrelated 4-letter brand names
  // ("nike" vs "mike") already crosses a 0.75 similarity threshold purely
  // by chance, since the score is normalized by string length. Below this
  // floor, only an exact match counts — the false-positive cost of a
  // wrong "fuzzy_match" label isn't worth the marginal recall gain on
  // names this short.
  const MIN_LABEL_LENGTH_FOR_FUZZY = 6;
  if (siteLabel.length >= MIN_LABEL_LENGTH_FOR_FUZZY && emailLabel.length >= MIN_LABEL_LENGTH_FOR_FUZZY && similarity(siteLabel, emailLabel) >= 0.75) {
    return 'fuzzy_match';
  }

  return 'mismatch';
}

/** Drops the public suffix (not just the last dot-separated label — a
 * naive split/slice would leave "co" attached for "example.co.uk",
 * comparing "exampleco" against other labels instead of "example") and
 * strips non-alphanumerics so "aegis-security" vs "aegissecurity"
 * compares as near-identical. Backed by the same suffix-aware tldts
 * lookup as getRegistrableDomain, so multi-part suffixes (.co.uk,
 * .com.au, etc.) are handled correctly rather than guessed at. */
function normalizeLabel(registrableDomain: string): string {
  const withoutSuffix = getDomainWithoutSuffix(registrableDomain) ?? registrableDomain.split('.')[0] ?? registrableDomain;
  return withoutSuffix.replace(/[^a-z0-9]/gi, '').toLowerCase();
}

/** Normalized similarity in [0, 1] based on Levenshtein distance. */
function similarity(a: string, b: string): number {
  if (!a || !b) return 0;
  if (a === b) return 1;
  const dist = levenshtein(a, b);
  return 1 - dist / Math.max(a.length, b.length);
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[] = new Array(n + 1).fill(0);
  for (let j = 0; j <= n; j++) dp[j] = j;

  for (let i = 1; i <= m; i++) {
    let prevDiag = dp[0] ?? 0;
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const temp = dp[j] ?? 0;
      const costIfSub = 1 + Math.min(prevDiag, temp, dp[j - 1] ?? 0);
      dp[j] = a[i - 1] === b[j - 1] ? prevDiag : costIfSub;
      prevDiag = temp;
    }
  }
  return dp[n] ?? 0;
}
