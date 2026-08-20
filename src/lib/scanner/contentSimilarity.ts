import { resolveSafeTarget, pinnedFetch } from '@/lib/ssrfGuard';
import { getRegistrableDomain } from '@/lib/domain';
import type { ContentSimilarityMatch } from '@/types/scan';

/**
 * Searches for other sites carrying the same distinctive page title —
 * a decent low-effort signal for a cloned/mirrored/phishing copy. Uses
 * Google's Programmable Search Engine API (free tier: 100 queries/day,
 * paid beyond that) since it's the most commonly available option; swap
 * the implementation here if you use a different provider.
 *
 * Deliberately never called from the free scan path — only from
 * api/consult, so an anonymous visitor can't burn your search-API quota
 * for free. Gracefully no-ops (returns 'skipped_no_api_key') if the two
 * env vars aren't set, so the rest of the app works without this configured.
 */

// Titles too generic to mean anything as an exact-quote search — an
// un-customized ecommerce/CMS theme's default title, or a bare "Home"/
// "Welcome" page, is shared by thousands of completely unrelated sites.
// Searching for one of these wouldn't find clones; it'd flood the results
// with noise and burn API quota doing it. Checked as substrings since the
// real title is often "Home | Some Store" or "My Shopify Store — Welcome".
const GENERIC_TITLE_MARKERS = [
  'home', 'welcome', 'untitled', 'index', 'new tab', 'coming soon',
  'my store', 'my shopify store', 'my wordpress site', 'my website',
  'wordpress site', 'shopify store', 'squarespace', 'wix.com', 'godaddy',
  'default web site page', 'test page', 'placeholder',
];

/** A title is too generic to search on if, once you strip the site's own
 * distinguishing punctuation/separators, what's left is short and/or
 * matches a known-generic marker. Real business names, product names, and
 * taglines survive this; boilerplate CMS defaults don't. */
function isTooGenericToSearch(title: string): boolean {
  const normalized = title.toLowerCase().trim();
  if (GENERIC_TITLE_MARKERS.some((marker) => normalized === marker || normalized.startsWith(`${marker} |`) || normalized.startsWith(`${marker} -`))) {
    return true;
  }
  // Strip common separators and site-name boilerplate words, then check
  // what's actually left — a title that's ENTIRELY generic words even
  // after splitting on separators (e.g. "Home | Welcome") has nothing
  // distinctive to search on.
  const segments = normalized.split(/[|\-–—:]/).map((s) => s.trim()).filter(Boolean);
  const distinctiveSegments = segments.filter((s) => !GENERIC_TITLE_MARKERS.includes(s) && s.length >= 4);
  return distinctiveSegments.length === 0;
}

export async function searchForContentClones(
  targetUrl: string
): Promise<{ status: 'complete' | 'skipped_no_api_key' | 'skipped_generic_title' | 'failed'; matches: ContentSimilarityMatch[] }> {
  const apiKey = process.env.GOOGLE_CSE_API_KEY;
  const cx = process.env.GOOGLE_CSE_CX;
  if (!apiKey || !cx) {
    return { status: 'skipped_no_api_key', matches: [] };
  }

  try {
    const target = await resolveSafeTarget(targetUrl);
    const res = await pinnedFetch(target, target.originalUrl, {
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
    });
    const html = await res.text();

    const title = html.match(/<title[^>]*>([^<]{5,200})<\/title>/i)?.[1]?.trim();
    if (!title) {
      return { status: 'failed', matches: [] };
    }
    if (isTooGenericToSearch(title)) {
      return { status: 'skipped_generic_title', matches: [] };
    }

    const searchUrl = new URL('https://www.googleapis.com/customsearch/v1');
    searchUrl.searchParams.set('key', apiKey);
    searchUrl.searchParams.set('cx', cx);
    searchUrl.searchParams.set('q', `"${title}"`);
    searchUrl.searchParams.set('num', '10');

    const searchRes = await fetch(searchUrl.toString(), { signal: AbortSignal.timeout(8000) });
    if (!searchRes.ok) {
      return { status: 'failed', matches: [] };
    }
    const searchData = await searchRes.json();

    const ownDomain = getRegistrableDomain(target.hostname);
    const items: { link?: string; title?: string; snippet?: string }[] = searchData.items ?? [];

    const matches: ContentSimilarityMatch[] = items
      .filter((item) => {
        if (!item.link) return false;
        try {
          return getRegistrableDomain(new URL(item.link).hostname) !== ownDomain;
        } catch {
          return false;
        }
      })
      .map((item) => ({
        url: item.link!,
        title: item.title ?? '',
        snippet: item.snippet ?? '',
      }));

    return { status: 'complete', matches };
  } catch (err) {
    console.error('Content-similarity search failed', err);
    return { status: 'failed', matches: [] };
  }
}
