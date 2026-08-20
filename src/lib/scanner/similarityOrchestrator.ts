import { resolveSafeTarget, pinnedFetch } from '@/lib/ssrfGuard';
import { compareDomStructure } from './domFingerprint';
import { compareScreenshots, computeDHash, hammingDistance } from './perceptualHash';
import { reverseImageSearch, type ReverseImageMatch } from './reverseImageSearch';

/**
 * Runs clone-detection techniques in parallel against a target and a set
 * of candidate URLs, combining them into one confidence score per
 * candidate:
 *   - DOM structural fingerprint (free, fast, no API key needed) — catches
 *     verbatim phishing-kit copies directly.
 *   - Favicon perceptual hash (free, fast, no API key needed) — a real
 *     clone almost always copies the favicon along with everything else;
 *     two unrelated stores that merely share a popular Shopify/WooCommerce
 *     theme will not, since each has its own logo/favicon. This is the
 *     single strongest cheap discriminator against the most common false-
 *     positive pattern in this whole approach: DOM structure alone can't
 *     tell "same theme, different business" from "actual clone", because
 *     thousands of unrelated stores share the same handful of popular
 *     themes. Favicon comparison targets exactly that gap.
 *   - Perceptual-hash screenshot comparison (paid rendering API) — catches
 *     visual clones that reworded or restyled the copied structure.
 *   - Reverse image search (paid Vision API) — run once against the
 *     target (it searches the whole web, not per-candidate); any exact/
 *     partial match against a specific candidate boosts that candidate's
 *     score, and any match that ISN'T among the known candidates at all
 *     surfaces as a newly discovered clone the domain-permutation
 *     approach could never have found on its own.
 *
 * Weighting is deliberately not dominated by DOM structure alone anymore
 * (previously 45%, with screenshot dHash at 40% — together 85% of the
 * score from the two signals most prone to coincidental similarity from a
 * shared theme). Favicon match now carries real weight specifically
 * because it's cheap, free, and targets that exact false-positive case.
 *
 * Each technique degrades independently — if the render/Vision API keys
 * aren't configured, the free DOM + favicon comparisons still contribute,
 * rather than the whole analysis failing.
 *
 * `corroborated` on each comparison is true only when at least two
 * independent signal types each scored reasonably high on their own —
 * this is surfaced (not auto-decided) so downstream consumers, and the
 * human doing Phase 2 manual verification, can tell "one signal happens
 * to be high" apart from "multiple independent techniques agree", without
 * this module making that judgment call itself.
 */

export interface SimilarityComparison {
  candidateUrl: string;
  domSimilarity: number | null;
  faviconSimilarity: number | null;
  visualSimilarity: number | null;
  reverseImageMatchType: ReverseImageMatch['matchType'] | null;
  combinedScore: number; // 0-1
  corroborated: boolean;
}

export interface SimilarityRunResult {
  comparisons: SimilarityComparison[];
  additionalCandidatesFromReverseImage: string[];
  status: {
    visual: 'complete' | 'skipped_no_api_key' | 'failed';
    reverseImage: 'complete' | 'skipped_no_api_key' | 'failed';
  };
}

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.hostname.toLowerCase()}${u.pathname.replace(/\/$/, '')}`;
  } catch {
    return url.toLowerCase();
  }
}

async function fetchHtmlSafely(url: string): Promise<string | null> {
  try {
    const target = await resolveSafeTarget(url);
    const res = await pinnedFetch(target, target.originalUrl, {
      signal: AbortSignal.timeout(8000),
      redirect: 'manual',
      headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
    });
    return (await res.text()).slice(0, 2_000_000);
  } catch {
    return null;
  }
}

const FAVICON_MAX_BYTES = 500_000;

/** Fetches /favicon.ico at the site root — covers the large majority of
 * sites (the browser-default fallback location). Doesn't parse the HTML
 * for a <link rel="icon"> pointing elsewhere; that's a real gap for sites
 * that only serve a custom-path favicon, but /favicon.ico alone is cheap
 * and correct often enough to be worth having as a free signal alongside
 * the others rather than skipping favicon comparison entirely. */
async function fetchFaviconBytes(siteUrl: string): Promise<Buffer | null> {
  try {
    const base = new URL(siteUrl);
    const faviconUrl = new URL('/favicon.ico', base).toString();
    const target = await resolveSafeTarget(faviconUrl);
    const res = await pinnedFetch(target, target.originalUrl, {
      signal: AbortSignal.timeout(6000),
      redirect: 'manual',
      headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
    });
    if (!res.ok) return null;
    const contentType = res.headers.get('content-type') ?? '';
    if (contentType && !/image\/|icon/i.test(contentType)) return null; // likely an HTML error page, not a real favicon
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length === 0 || buf.length > FAVICON_MAX_BYTES) return null;
    return buf;
  } catch {
    return null;
  }
}

async function compareFavicons(targetUrl: string, candidateUrl: string): Promise<number | null> {
  const [targetBytes, candidateBytes] = await Promise.all([fetchFaviconBytes(targetUrl), fetchFaviconBytes(candidateUrl)]);
  if (!targetBytes || !candidateBytes) return null;

  const [hashA, hashB] = await Promise.all([computeDHash(targetBytes), computeDHash(candidateBytes)]);
  if (hashA === null || hashB === null) return null;

  return 1 - hammingDistance(hashA, hashB) / 64;
}

export async function runSimilarityAnalysis(
  targetUrl: string,
  candidateUrls: string[]
): Promise<SimilarityRunResult> {
  const reversePromise = reverseImageSearch(targetUrl);

  const comparisonPromises = candidateUrls.map(async (candidateUrl) => {
    const [targetHtml, candidateHtml, visualResult, faviconSimilarity] = await Promise.all([
      fetchHtmlSafely(targetUrl),
      fetchHtmlSafely(candidateUrl),
      compareScreenshots(targetUrl, candidateUrl).catch(
        (): { status: 'failed'; similarity: number } => ({ status: 'failed', similarity: 0 })
      ),
      compareFavicons(targetUrl, candidateUrl).catch(() => null),
    ]);

    const domSimilarity = targetHtml && candidateHtml ? compareDomStructure(targetHtml, candidateHtml) : null;

    return { candidateUrl, domSimilarity, faviconSimilarity, visualResult };
  });

  const [reverseResult, comparisonResults] = await Promise.all([reversePromise, Promise.all(comparisonPromises)]);

  const matchByUrl = new Map(reverseResult.matches.map((m) => [normalizeUrl(m.url), m.matchType]));

  const comparisons: SimilarityComparison[] = comparisonResults.map(
    ({ candidateUrl, domSimilarity, faviconSimilarity, visualResult }) => {
      const reverseImageMatchType = matchByUrl.get(normalizeUrl(candidateUrl)) ?? null;
      const visualSimilarity = visualResult.status === 'complete' ? visualResult.similarity : null;

      const signals: { score: number; weight: number }[] = [];
      if (domSimilarity !== null) signals.push({ score: domSimilarity, weight: 0.3 });
      if (faviconSimilarity !== null) signals.push({ score: faviconSimilarity, weight: 0.3 });
      if (visualSimilarity !== null) signals.push({ score: visualSimilarity, weight: 0.25 });
      if (reverseImageMatchType) {
        signals.push({
          score: reverseImageMatchType === 'full' ? 1 : reverseImageMatchType === 'partial' ? 0.75 : 0.5,
          weight: 0.15,
        });
      }

      const totalWeight = signals.reduce((sum, s) => sum + s.weight, 0);
      const combinedScore = totalWeight > 0 ? signals.reduce((sum, s) => sum + s.score * s.weight, 0) / totalWeight : 0;

      // "Corroborated" — at least two independently-sourced signals each
      // individually scored high, rather than one signal (e.g. DOM
      // structure from a shared theme) carrying the whole score alone.
      const strongSignalCount = signals.filter((s) => s.score >= 0.75).length;
      const corroborated = strongSignalCount >= 2;

      return { candidateUrl, domSimilarity, faviconSimilarity, visualSimilarity, reverseImageMatchType, combinedScore, corroborated };
    }
  );

  const knownUrls = new Set(candidateUrls.map(normalizeUrl));
  const additionalCandidatesFromReverseImage = reverseResult.matches
    .map((m) => m.url)
    .filter((u) => !knownUrls.has(normalizeUrl(u)));

  return {
    comparisons,
    additionalCandidatesFromReverseImage,
    status: {
      visual: comparisonResults[0]?.visualResult.status ?? 'skipped_no_api_key',
      reverseImage: reverseResult.status,
    },
  };
}
