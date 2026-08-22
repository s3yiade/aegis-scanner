import type { Finding } from '@/types/scan';
import type { CrawledPage } from './crawler';

/**
 * Flags HTTP-scheme resources referenced from an HTTPS page — modern
 * browsers block "active" mixed content (scripts, stylesheets, iframes)
 * outright, so this is as much a "does the site visibly break" check as a
 * security one, plus a real MITM/tampering surface for whatever does load.
 * Protocol-relative URLs (//cdn.example.com/x.js) are correctly NOT
 * flagged — they inherit the page's own scheme, they're not hardcoded to
 * HTTP.
 *
 * Runs against the already-crawled pages (see crawler.ts) — no extra
 * fetches needed, this is pure HTML parsing.
 */

const ACTIVE_TAGS = ['script', 'link', 'iframe'] as const;
const PASSIVE_TAGS = ['img', 'audio', 'video', 'source'] as const;

function findHttpRefs(html: string, tags: readonly string[]): string[] {
  const found: string[] = [];
  for (const tag of tags) {
    const attr = tag === 'link' ? 'href' : 'src';
    const regex = new RegExp(`<${tag}[^>]+${attr}\\s*=\\s*["'](http://[^"']+)["']`, 'gi');
    for (const m of html.matchAll(regex)) {
      if (m[1]) found.push(m[1]);
    }
  }
  return found;
}

export function checkMixedContent(pages: CrawledPage[], targetProtocol: string): Finding[] {
  if (targetProtocol !== 'https:') {
    return [
      {
        id: 'mixed-content',
        category: 'webapp',
        title: 'Mixed content check',
        severity: 'info',
        detail: "Not applicable — the site itself isn't served over HTTPS (see the separate finding on that).",
        recommendation: 'Not applicable.',
        passed: true,
      },
    ];
  }

  const activeHits = new Set<string>();
  const passiveHits = new Set<string>();

  for (const page of pages) {
    if (!page.html) continue;
    for (const url of findHttpRefs(page.html, ACTIVE_TAGS)) activeHits.add(url);
    for (const url of findHttpRefs(page.html, PASSIVE_TAGS)) passiveHits.add(url);
  }

  if (activeHits.size === 0 && passiveHits.size === 0) {
    return [
      {
        id: 'mixed-content',
        category: 'webapp',
        title: 'Mixed content check',
        severity: 'pass',
        detail: `No HTTP-scheme resources found across ${pages.length} page(s) checked.`,
        recommendation: 'No action needed.',
        passed: true,
      },
    ];
  }

  if (activeHits.size > 0) {
    return [
      {
        id: 'mixed-content',
        category: 'webapp',
        title: 'Active mixed content (scripts/stylesheets/iframes over HTTP)',
        severity: 'high',
        detail: `${activeHits.size} script/stylesheet/iframe reference(s) load over plain HTTP on an HTTPS page: ${[...activeHits]
          .slice(0, 8)
          .join(', ')}${activeHits.size > 8 ? `, and ${activeHits.size - 8} more` : ''}.${
          passiveHits.size > 0 ? ` Also found ${passiveHits.size} passive (image/media) HTTP reference(s).` : ''
        }`,
        recommendation:
          'Modern browsers block active mixed content outright — this likely already breaks visibly for visitors. Change every listed reference to https:// (or a protocol-relative //) and verify the resource is actually reachable over HTTPS at that host.',
        passed: false,
      },
    ];
  }

  return [
    {
      id: 'mixed-content',
      category: 'webapp',
      title: 'Passive mixed content (images/media over HTTP)',
      severity: 'medium',
      detail: `${passiveHits.size} image/media reference(s) load over plain HTTP on an HTTPS page: ${[...passiveHits]
        .slice(0, 8)
        .join(', ')}${passiveHits.size > 8 ? `, and ${passiveHits.size - 8} more` : ''}.`,
      recommendation:
        'Browsers show a "not fully secure" warning for this rather than blocking it, but it\'s still unencrypted and tamperable in transit. Change these references to https://.',
      passed: false,
    },
  ];
}
