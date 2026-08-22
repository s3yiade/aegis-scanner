import { pinnedFetch, type SafeTarget } from '@/lib/ssrfGuard';

/**
 * Discovers same-origin pages via sitemap.xml (falling back to robots.txt's
 * Sitemap: directive) so client-side checks — secret scanning, source maps,
 * SRI (see webapp.ts) — run across a representative slice of the site
 * instead of just the homepage. A marketing homepage is frequently the
 * *least* likely page to contain a leaked key or an unpinned third-party
 * script; a dashboard, login, or account page is a much more common place
 * to find one, and those are exactly the pages a homepage-only crawl was
 * missing.
 *
 * Deliberately regex-based rather than pulling in an XML parser dependency
 * — <loc>...</loc> extraction is simple and forgiving enough that a real
 * parser isn't worth the added dependency, same tradeoff already made for
 * HTML tag extraction in webapp.ts.
 *
 * Bounded on every axis: page count, sitemap-index fan-out, body size, and
 * per-request timeout — this runs on every scan, so it needs to stay cheap
 * and fast even against a huge sitemap.
 */

const TIMEOUT_MS = 6000;
const MAX_SITEMAP_BYTES = 3_000_000;
const MAX_PAGE_BYTES = 2_000_000;
const MAX_CHILD_SITEMAPS = 3; // if sitemap.xml is itself a sitemap INDEX
const MAX_URLS_FROM_SITEMAP = 200; // cap how many <loc> entries we even parse out
const USER_AGENT = 'AegisScanner/1.0 (+security-scan)';

export interface CrawledPage {
  url: string;
  html: string;
}

export interface CrawlDiscovery {
  source: 'sitemap.xml' | 'robots.txt' | 'none';
  totalUrlsFound: number;
  pagesFetched: CrawledPage[];
}

/**
 * @param homepageUrl The already-fetched homepage URL, so it can be
 * excluded from the discovered set (the caller already has it).
 * @param maxPages How many *additional* pages (beyond the homepage) to
 * actually fetch and return.
 */
export async function discoverAndCrawl(target: SafeTarget, homepageUrl: string, maxPages: number): Promise<CrawlDiscovery> {
  const sitemapUrls = await findSitemapLocations(target);

  for (const { url: sitemapUrl, source } of sitemapUrls) {
    const locs = await fetchSitemapLocs(target, sitemapUrl, 0);
    if (locs.length === 0) continue;

    const sameOrigin = dedupeSameOrigin(locs, target, homepageUrl);
    if (sameOrigin.length === 0) continue;

    const toFetch = sameOrigin.slice(0, maxPages);
    const pagesFetched = await fetchPages(target, toFetch);

    return { source, totalUrlsFound: sameOrigin.length, pagesFetched };
  }

  return { source: 'none', totalUrlsFound: 0, pagesFetched: [] };
}

async function findSitemapLocations(target: SafeTarget): Promise<{ url: string; source: 'sitemap.xml' | 'robots.txt' }[]> {
  const base = `${target.protocol}//${target.hostname}`;
  const candidates: { url: string; source: 'sitemap.xml' | 'robots.txt' }[] = [{ url: `${base}/sitemap.xml`, source: 'sitemap.xml' }];

  // robots.txt's Sitemap: directive is the standard fallback/complement —
  // many sites only declare their sitemap location there, or declare
  // several (e.g. separate sitemaps per section).
  try {
    const res = await pinnedFetch(target, `${base}/robots.txt`, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: 'manual',
      headers: { 'User-Agent': USER_AGENT },
    });
    if (res.status === 200) {
      const body = (await res.text()).slice(0, 200_000);
      const matches = [...body.matchAll(/^\s*sitemap\s*:\s*(\S+)/gim)];
      for (const m of matches) {
        const declared = m[1];
        if (!declared) continue;
        try {
          const resolved = new URL(declared, base);
          if (resolved.hostname.toLowerCase() === target.hostname.toLowerCase()) {
            candidates.push({ url: resolved.toString(), source: 'robots.txt' });
          }
        } catch {
          // malformed URL in robots.txt — skip
        }
      }
    }
  } catch {
    // no robots.txt or unreachable — fine, /sitemap.xml candidate still stands
  }

  return candidates;
}

async function fetchSitemapLocs(target: SafeTarget, url: string, depth: number): Promise<string[]> {
  let body: string;
  try {
    const res = await pinnedFetch(target, url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: 'manual',
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/xml, text/xml' },
    });
    if (res.status !== 200) return [];
    body = (await res.text()).slice(0, MAX_SITEMAP_BYTES);
  } catch {
    return [];
  }

  const locs = [...body.matchAll(/<loc>\s*([^<\s][^<]*?)\s*<\/loc>/gi)].map((m) => decodeXmlEntities(m[1] ?? '')).filter(Boolean);

  if (locs.length === 0) return [];

  // A sitemap INDEX lists other sitemaps, not pages (<sitemapindex> wrapping
  // <sitemap><loc>). Detect it and, one level deep only, fetch a bounded
  // number of the child sitemaps and merge their <loc> entries instead.
  const isIndex = /<sitemapindex[\s>]/i.test(body);
  if (isIndex && depth === 0) {
    const childResults = await Promise.all(
      locs.slice(0, MAX_CHILD_SITEMAPS).map((childUrl) => fetchSitemapLocs(target, childUrl, depth + 1))
    );
    return childResults.flat().slice(0, MAX_URLS_FROM_SITEMAP);
  }

  return locs.slice(0, MAX_URLS_FROM_SITEMAP);
}

function dedupeSameOrigin(locs: string[], target: SafeTarget, homepageUrl: string): string[] {
  const seen = new Set<string>();
  let homepageNormalized: string | null = null;
  try {
    homepageNormalized = normalizePath(new URL(homepageUrl));
  } catch {
    homepageNormalized = null;
  }

  const result: string[] = [];
  for (const loc of locs) {
    let parsed: URL;
    try {
      parsed = new URL(loc);
    } catch {
      continue;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
    if (parsed.hostname.toLowerCase() !== target.hostname.toLowerCase()) continue;

    const normalized = normalizePath(parsed);
    if (normalized === homepageNormalized) continue;
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(parsed.toString());
  }
  return result;
}

function normalizePath(u: URL): string {
  const path = u.pathname.replace(/\/+$/, '') || '/';
  return `${u.hostname.toLowerCase()}${path}`;
}

async function fetchPages(target: SafeTarget, urls: string[]): Promise<CrawledPage[]> {
  const results = await Promise.all(
    urls.map(async (url): Promise<CrawledPage | null> => {
      try {
        const res = await pinnedFetch(target, url, {
          signal: AbortSignal.timeout(TIMEOUT_MS),
          redirect: 'manual',
          headers: { 'User-Agent': USER_AGENT, Accept: 'text/html' },
        });
        if (res.status !== 200) return null;
        const contentType = res.headers.get('content-type') ?? '';
        if (contentType && !/text\/html|application\/xhtml/i.test(contentType)) return null;
        const html = (await res.text()).slice(0, MAX_PAGE_BYTES);
        return { url, html };
      } catch {
        return null;
      }
    })
  );
  return results.filter((p): p is CrawledPage => Boolean(p));
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}
