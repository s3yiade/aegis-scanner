import { resolveSafeTarget } from '@/lib/ssrfGuard';
import { renderPageHtml } from './renderPage';
import { checkSourceMapsAndSecrets, checkSRI, checkTrustSignals } from './webapp';
import type { Finding } from '@/types/scan';

export interface DeepScanResult {
  status: 'complete' | 'skipped_no_api_key' | 'failed';
  findings: Finding[];
}

/**
 * Re-runs the DOM-dependent web-app checks (client-side secrets, source
 * maps, SRI, trust signals) against a JS-rendered version of the page
 * instead of the raw HTTP response — catches anything a client-rendered
 * SPA injects after initial load that the free scan's regex-on-raw-HTML
 * approach can't see (see renderPage.ts for why this needs an actual
 * browser rather than a parsing fix).
 *
 * Only ever triggered from api/consult, same reasoning as
 * contentSimilarity.ts — rendering is slow and costs money per call, so it
 * never runs on the free/anonymous scan path.
 */
// A genuinely rendered page — even a sparse one — has a real amount of
// markup once JS has executed. Below this, "complete" more likely means
// the renderer got a mostly-empty error/blank page than that the site
// itself is this thin; treating that as a clean scan would silently
// report "no secrets, no third-party scripts, no exposed maps" from
// having nothing to check, not from having actually checked anything.
const MIN_RENDERED_HTML_BYTES = 500;

export async function runDeepScan(targetUrl: string): Promise<DeepScanResult> {
  const { status, html } = await renderPageHtml(targetUrl);
  if (status !== 'complete') return { status, findings: [] };

  if (html.trim().length < MIN_RENDERED_HTML_BYTES) {
    return { status: 'failed', findings: [] };
  }

  let target;
  try {
    target = await resolveSafeTarget(targetUrl);
  } catch (err) {
    // DNS can genuinely change between the initial scan request and this
    // deferred background call (which may run up to ~30-60s later) — a
    // domain that stops resolving, or starts resolving somewhere the SSRF
    // guard blocks, shouldn't leave the request stuck at 'pending' forever
    // with no way to tell "still running" apart from "silently died".
    console.error('Deep scan target re-resolution failed', err);
    return { status: 'failed', findings: [] };
  }

  const [secrets, sri, trust] = await Promise.all([
    checkSourceMapsAndSecrets(target, html).catch((): Finding[] => []),
    Promise.resolve(checkSRI(html, target)),
    Promise.resolve(checkTrustSignals(html)),
  ]);

  // Tag ids distinctly from the free-scan findings (same checks, different
  // source document — rendered DOM vs. raw HTTP response) so the two are
  // never confused if ever displayed together.
  const findings = [...secrets, ...sri, ...trust].map((f) => ({ ...f, id: `deep-${f.id}` }));

  return { status: 'complete', findings };
}
