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
  '10minutemail.com',
  '10minutemail.net',
  'tempmail.com',
  'temp-mail.org',
  'throwawaymail.com',
  'yopmail.com',
  'trashmail.com',
  'getnada.com',
  'fakeinbox.com',
  'sharklasers.com',
  'dispostable.com',
  'maildrop.cc',
  'mintemail.com',
  'mailnesia.com',
  'spamgourmet.com',
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
  return DISPOSABLE_DOMAINS.has(domain);
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

  if (similarity(siteLabel, emailLabel) >= 0.75) return 'fuzzy_match';

  return 'mismatch';
}

function normalizeLabel(domain: string): string {
  // Drop the suffix (last label) and strip non-alphanumerics so
  // "aegis-security" vs "aegissecurity" compares as near-identical.
  const withoutSuffix = domain.split('.').slice(0, -1).join('') || domain;
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
