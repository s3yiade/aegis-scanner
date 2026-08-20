import crypto from 'node:crypto';

/**
 * Fingerprints a page's DOM *structure* (tag/attribute skeleton, text
 * content stripped) and compares two pages via simhash — a locality-
 * sensitive hash where similar inputs produce hashes with a small Hamming
 * distance, giving a genuine graded similarity percentage rather than a
 * binary match/no-match.
 *
 * This specifically targets how phishing kits actually work: overwhelmingly,
 * they copy the target's HTML/CSS byte-for-byte and only change the login
 * form's submission URL. A structural fingerprint catches that even when
 * visible text has been translated or lightly edited, at zero cost (no
 * external API, no new heavy dependency) — this runs first among the three
 * similarity techniques for exactly that reason.
 */

const SIMHASH_BITS = 64;
const SHINGLE_SIZE = 4; // consecutive tag-path tokens per shingle

// A page reduced to fewer structural tokens than this has too little
// signal for a simhash comparison to mean anything — two completely
// unrelated bare-bones/placeholder pages (e.g. both just a "coming soon"
// wrapper) could otherwise coincidentally land on a near-identical hash
// purely because there's almost nothing there to differentiate them, not
// because either is a copy of the other.
const MIN_TOKENS_FOR_RELIABLE_COMPARISON = 20;

/** Strips text content/comments and reduces each element to
 * "tagname[sorted-attr-names]" — keeps structural shape, discards
 * anything that would make wording differences look like structural ones. */
function canonicalizeStructure(html: string): string[] {
  const tokens: string[] = [];
  const tagRe = /<\/?([a-z][a-z0-9]*)\b([^>]*)>/gi;
  let match: RegExpExecArray | null;
  while ((match = tagRe.exec(html))) {
    const tag = match[1]?.toLowerCase();
    if (!tag) continue;
    if (tag === 'script' || tag === 'style') continue; // content, not structure
    const isClosing = match[0].startsWith('</');
    const attrNames = Array.from((match[2] ?? '').matchAll(/([a-z-]+)\s*=/gi))
      .map((m) => m[1]?.toLowerCase())
      .filter((a): a is string => !!a && a !== 'style' && !a.startsWith('data-')) // skip highly page-specific attrs
      .sort();
    tokens.push(`${isClosing ? '/' : ''}${tag}[${attrNames.join(',')}]`);
  }
  return tokens;
}

function shingles(tokens: string[]): string[] {
  if (tokens.length < SHINGLE_SIZE) return tokens.length ? [tokens.join('|')] : [];
  const out: string[] = [];
  for (let i = 0; i <= tokens.length - SHINGLE_SIZE; i++) {
    out.push(tokens.slice(i, i + SHINGLE_SIZE).join('|'));
  }
  return out;
}

function hashToBits(input: string): boolean[] {
  const digest = crypto.createHash('sha256').update(input).digest();
  const bits: boolean[] = [];
  for (let i = 0; i < SIMHASH_BITS; i++) {
    const byte = digest[Math.floor(i / 8)] ?? 0;
    bits.push(((byte >> i % 8) & 1) === 1);
  }
  return bits;
}

/** Computes a 64-bit simhash of a page's DOM structure, plus the token
 * count it was built from (needed by compareDomStructure's reliability
 * gate below). */
export function computeDomSimhash(html: string): bigint {
  return computeDomSimhashWithCount(html).hash;
}

function computeDomSimhashWithCount(html: string): { hash: bigint; tokenCount: number } {
  const tokens = canonicalizeStructure(html);
  const shingleList = shingles(tokens);
  if (shingleList.length === 0) return { hash: 0n, tokenCount: tokens.length };

  const votes = new Array(SIMHASH_BITS).fill(0);
  for (const shingle of shingleList) {
    const bits = hashToBits(shingle);
    for (let i = 0; i < SIMHASH_BITS; i++) votes[i] += bits[i] ? 1 : -1;
  }

  let hash = 0n;
  for (let i = 0; i < SIMHASH_BITS; i++) {
    if (votes[i] > 0) hash |= 1n << BigInt(i);
  }
  return { hash, tokenCount: tokens.length };
}

function hammingDistance(a: bigint, b: bigint): number {
  let x = a ^ b;
  let count = 0;
  while (x > 0n) {
    count += Number(x & 1n);
    x >>= 1n;
  }
  return count;
}

/** Returns a 0-1 similarity score between two pages' DOM structure. */
export function compareDomStructure(htmlA: string, htmlB: string): number {
  const a = computeDomSimhashWithCount(htmlA);
  const b = computeDomSimhashWithCount(htmlB);
  if (a.hash === 0n || b.hash === 0n) return 0;
  if (a.tokenCount < MIN_TOKENS_FOR_RELIABLE_COMPARISON || b.tokenCount < MIN_TOKENS_FOR_RELIABLE_COMPARISON) return 0;
  const distance = hammingDistance(a.hash, b.hash);
  return 1 - distance / SIMHASH_BITS;
}
