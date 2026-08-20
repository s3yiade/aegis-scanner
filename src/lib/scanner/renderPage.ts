import { resolveSafeTarget } from '@/lib/ssrfGuard';

/**
 * Renders a page via a hosted headless-browser API (Browserless.io-
 * compatible /content endpoint by default) and returns the resulting DOM
 * HTML — i.e., what a real browser sees after JavaScript executes, not
 * just the initial HTTP response. This is what lets the deep-scan checks
 * (see deepScan.ts) see scripts/tags a client-rendered SPA injects after
 * load, which the free scan's raw-HTML regex parsing can't.
 *
 * Only ever called from the gated consult flow (api/consult), never the
 * free scan path — rendering is materially slower (seconds, not
 * milliseconds) and costs money per call on a hosted rendering service.
 *
 * The URL is still validated through the same SSRF guard used everywhere
 * else before being handed to the third-party renderer — not because the
 * renderer's own sandboxing can't be trusted, but so an obviously-internal
 * -looking target never gets sent to a third party either.
 *
 * Gracefully no-ops if RENDER_API_KEY isn't configured.
 */
export async function renderPageHtml(
  targetUrl: string
): Promise<{ status: 'complete' | 'skipped_no_api_key' | 'failed'; html: string }> {
  const apiKey = process.env.RENDER_API_KEY;
  if (!apiKey) return { status: 'skipped_no_api_key', html: '' };

  const baseUrl = process.env.RENDER_API_URL || 'https://chrome.browserless.io/content';

  try {
    const target = await resolveSafeTarget(targetUrl);

    const endpoint = new URL(baseUrl);
    endpoint.searchParams.set('token', apiKey);

    const res = await fetch(endpoint.toString(), {
      method: 'POST',
      // Headless rendering (navigate + execute JS + wait for network-idle)
      // is genuinely slow — this needs real room, unlike the ~6s timeouts
      // used for plain HTTP checks elsewhere in the scanner.
      signal: AbortSignal.timeout(30000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: target.originalUrl,
        gotoOptions: { waitUntil: 'networkidle2', timeout: 25000 },
      }),
    });

    if (!res.ok) return { status: 'failed', html: '' };
    const html = await res.text();
    return { status: 'complete', html: html.slice(0, 3_000_000) };
  } catch (err) {
    console.error('Page rendering failed', err);
    return { status: 'failed', html: '' };
  }
}

/**
 * Same rendering service, screenshot endpoint instead of content — used by
 * the perceptual-hash comparison (see perceptualHash.ts). Same gating and
 * SSRF-guard reasoning as renderPageHtml above.
 */
export async function renderPageScreenshot(
  targetUrl: string
): Promise<{ status: 'complete' | 'skipped_no_api_key' | 'failed'; imageBytes: Buffer | null }> {
  const apiKey = process.env.RENDER_API_KEY;
  if (!apiKey) return { status: 'skipped_no_api_key', imageBytes: null };

  const baseUrl = process.env.RENDER_SCREENSHOT_API_URL || 'https://chrome.browserless.io/screenshot';

  try {
    const target = await resolveSafeTarget(targetUrl);

    const endpoint = new URL(baseUrl);
    endpoint.searchParams.set('token', apiKey);

    const res = await fetch(endpoint.toString(), {
      method: 'POST',
      signal: AbortSignal.timeout(30000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: target.originalUrl,
        options: { type: 'png', fullPage: false }, // above-the-fold is what a visitor/victim actually sees first
        gotoOptions: { waitUntil: 'networkidle2', timeout: 25000 },
        viewport: { width: 1280, height: 800 },
      }),
    });

    if (!res.ok) return { status: 'failed', imageBytes: null };
    const arrayBuffer = await res.arrayBuffer();
    return { status: 'complete', imageBytes: Buffer.from(arrayBuffer) };
  } catch (err) {
    console.error('Screenshot rendering failed', err);
    return { status: 'failed', imageBytes: null };
  }
}
