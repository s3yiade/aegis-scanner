import { renderPageScreenshot } from './renderPage';
import { getRegistrableDomain } from '@/lib/domain';

/**
 * Submits a screenshot of the target to Google Cloud Vision's Web
 * Detection API and returns every other page it finds carrying a visually
 * matching or highly similar image. Unlike the domain-permutation and
 * content-title-search checks, this doesn't require guessing candidate
 * domains at all — it searches by the page's actual visual fingerprint
 * wherever it exists on the web.
 *
 * First 1,000 units/month free, then $3.50/1,000 (Google Cloud Vision
 * pricing as of 2026) — same gating reasoning as everywhere else in this
 * file: only ever triggered from the consult flow, never the free scan.
 * Gracefully no-ops if GOOGLE_VISION_API_KEY isn't configured.
 */

export interface ReverseImageMatch {
  url: string;
  matchType: 'full' | 'partial' | 'similar';
}

export async function reverseImageSearch(
  targetUrl: string
): Promise<{ status: 'complete' | 'skipped_no_api_key' | 'failed'; matches: ReverseImageMatch[] }> {
  const apiKey = process.env.GOOGLE_VISION_API_KEY;
  if (!apiKey) return { status: 'skipped_no_api_key', matches: [] };

  const { status: shotStatus, imageBytes } = await renderPageScreenshot(targetUrl);
  if (shotStatus === 'skipped_no_api_key') return { status: 'skipped_no_api_key', matches: [] };
  if (!imageBytes) return { status: 'failed', matches: [] };

  try {
    const target = await import('@/lib/ssrfGuard').then((m) => m.resolveSafeTarget(targetUrl));
    const ownDomain = getRegistrableDomain(target.hostname);

    const res = await fetch(`https://vision.googleapis.com/v1/images:annotate?key=${apiKey}`, {
      method: 'POST',
      signal: AbortSignal.timeout(15000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        requests: [
          {
            image: { content: imageBytes.toString('base64') },
            features: [{ type: 'WEB_DETECTION', maxResults: 20 }],
          },
        ],
      }),
    });

    if (!res.ok) return { status: 'failed', matches: [] };
    const data = await res.json();
    const webDetection = data.responses?.[0]?.webDetection;
    if (!webDetection) return { status: 'complete', matches: [] };

    const collect = (
      pages: { url?: string }[] | undefined,
      matchType: ReverseImageMatch['matchType']
    ): ReverseImageMatch[] =>
      (pages ?? [])
        .filter((p) => Boolean(p.url))
        .filter((p) => {
          try {
            return getRegistrableDomain(new URL(p.url!).hostname) !== ownDomain;
          } catch {
            return false;
          }
        })
        .map((p) => ({ url: p.url!, matchType }));

    const matches = [
      ...collect(webDetection.fullMatchingImages, 'full'),
      ...collect(webDetection.partialMatchingImages, 'partial'),
      // Deliberately NOT including webDetection.pagesWithMatchingImages
      // ('similar' match type) here: that's Google's broadest
      // classification — any page containing SOME visually similar
      // image, not necessarily the submitted one. Since what's submitted
      // is a full-page screenshot (not a cropped logo), that tier
      // reliably surfaces pages that just happen to share a stock photo,
      // a generic icon, or the same theme-demo screenshot as thousands of
      // other sites on the same template — noise, not clone evidence.
    ];

    // Dedupe by URL, keeping the strongest match type seen for each.
    const strength: Record<ReverseImageMatch['matchType'], number> = { full: 2, partial: 1, similar: 0 };
    const byUrl = new Map<string, ReverseImageMatch>();
    for (const m of matches) {
      const existing = byUrl.get(m.url);
      if (!existing || strength[m.matchType] > strength[existing.matchType]) byUrl.set(m.url, m);
    }

    return { status: 'complete', matches: Array.from(byUrl.values()) };
  } catch (err) {
    console.error('Reverse image search failed', err);
    return { status: 'failed', matches: [] };
  }
}
