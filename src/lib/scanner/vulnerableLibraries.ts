import type { Finding } from '@/types/scan';
import type { CrawledPage } from './crawler';

/**
 * Fingerprints common JS libraries by version markers in their script URL
 * (CDN paths and self-hosted filenames both very commonly embed the exact
 * version — e.g. cdnjs.cloudflare.com/ajax/libs/jquery/1.8.3/jquery.min.js,
 * code.jquery.com/jquery-1.8.3.min.js) against a small curated set of
 * well-known vulnerable version thresholds, retire.js-style but without
 * bundling retire.js's full (large, constantly-updated) vulnerability
 * database — this trades completeness for something that ships and stays
 * accurate without a maintenance story this app doesn't have.
 *
 * URL-based only, deliberately: it doesn't fetch and inspect script
 * contents for a version comment, so a self-hosted bundle where the
 * version isn't visible in the filename (most webpack/vite output, for
 * example) won't be caught. Stated as an explicit limitation in the
 * report copy rather than silently under-covering.
 *
 * Runs against every crawled page's script tags — same-origin AND
 * cross-origin/CDN, since a vulnerable CDN-hosted library is just as real
 * a risk as a self-hosted one, and CDN URLs are exactly where version
 * numbers show up most reliably.
 */

type SemVer = [number, number, number];

interface LibraryHit {
  name: string;
  version: string | null;
  url: string;
  severity: Finding['severity'];
  note: string;
}

interface LibraryRule {
  name: string;
  /** Returns the matched version string (or 'unknown' if the library is
   * detected but no version could be parsed out of the URL), or null if
   * this rule doesn't match the URL at all. */
  detect: (url: string) => string | null;
  assess: (version: string | null) => { severity: Finding['severity']; note: string } | null;
}

function parseSemVer(v: string): SemVer | null {
  const m = v.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function isBelow(v: SemVer, threshold: SemVer): boolean {
  const pairs: [number, number][] = [
    [v[0], threshold[0]],
    [v[1], threshold[1]],
    [v[2], threshold[2]],
  ];
  for (const [a, b] of pairs) {
    if (a !== b) return a < b;
  }
  return false;
}

function versionThresholdRule(
  name: string,
  urlPattern: RegExp,
  excludePattern: RegExp | null,
  threshold: SemVer,
  advisory: string,
  severity: Finding['severity']
): LibraryRule {
  return {
    name,
    detect: (url) => {
      if (excludePattern?.test(url)) return null;
      const m = url.match(urlPattern);
      return m?.[1] ?? null;
    },
    assess: (version) => {
      if (!version) return null;
      const parsed = parseSemVer(version);
      if (!parsed) return null;
      if (!isBelow(parsed, threshold)) return null;
      return { severity, note: advisory };
    },
  };
}

function legacyLibraryRule(name: string, urlPattern: RegExp, note: string): LibraryRule {
  return {
    name,
    detect: (url) => (urlPattern.test(url) ? 'unknown' : null),
    assess: () => ({ severity: 'info', note }),
  };
}

const RULES: LibraryRule[] = [
  versionThresholdRule(
    'jQuery',
    /jquery[.\/-](\d+\.\d+\.\d+)/i,
    /jquery[.-]?(ui|migrate|validate|mobile)/i,
    [3, 5, 0],
    "Versions before 3.5.0 have known XSS issues (e.g. via untrusted HTML passed to jQuery's DOM-manipulation methods).",
    'high'
  ),
  versionThresholdRule(
    'jQuery UI',
    /jquery[.-]?ui[.\/-]?(\d+\.\d+\.\d+)/i,
    null,
    [1, 13, 0],
    'Versions before 1.13.0 have known XSS issues in several widgets (e.g. datepicker).',
    'high'
  ),
  {
    name: 'Bootstrap',
    detect: (url) => url.match(/bootstrap[.\/-](\d+\.\d+\.\d+)/i)?.[1] ?? null,
    assess: (version) => {
      if (!version) return null;
      const parsed = parseSemVer(version);
      if (!parsed) return null;
      const [major] = parsed;
      if (major === 3 && isBelow(parsed, [3, 4, 1])) {
        return { severity: 'high', note: 'Bootstrap 3.x before 3.4.1 has known XSS issues via data attributes (affix, scrollspy, tooltip).' };
      }
      if (major === 4 && isBelow(parsed, [4, 3, 1])) {
        return { severity: 'high', note: 'Bootstrap 4.x before 4.3.1 has known XSS issues via data attributes (tooltip, popover, collapse).' };
      }
      return null;
    },
  },
  {
    name: 'AngularJS',
    detect: (url) => {
      const m = url.match(/angular(?:\.min)?[.\/-](\d+\.\d+\.\d+)/i);
      if (!m) return null;
      // Only classic AngularJS (1.x) — Angular 2+ doesn't ship as a
      // single versioned "angular.js" CDN file with this naming pattern.
      return m[1]?.startsWith('1.') ? m[1] : null;
    },
    assess: (version) => {
      const parsed = version ? parseSemVer(version) : null;
      if (parsed && isBelow(parsed, [1, 8, 0])) {
        return {
          severity: 'high',
          note: 'AngularJS before 1.8.0 has known sandbox-bypass/XSS issues, and the entire 1.x line reached end-of-life in January 2022 with no further patches.',
        };
      }
      return { severity: 'medium', note: 'AngularJS (1.x) reached end-of-life in January 2022 and no longer receives security patches regardless of version.' };
    },
  },
  versionThresholdRule(
    'Lodash',
    /lodash(?:\.min)?[.\/-](\d+\.\d+\.\d+)/i,
    null,
    [4, 17, 21],
    'Versions before 4.17.21 have known prototype-pollution issues.',
    'high'
  ),
  versionThresholdRule(
    'Moment.js',
    /moment(?:\.min)?[.\/-](\d+\.\d+\.\d+)/i,
    /moment-timezone|moment-range/i,
    [2, 29, 4],
    'Versions before 2.29.4 have a known ReDoS (regex denial-of-service) issue in date parsing.',
    'medium'
  ),
  versionThresholdRule(
    'Handlebars',
    /handlebars(?:\.min)?[.\/-](\d+\.\d+\.\d+)/i,
    null,
    [4, 7, 7],
    'Versions before 4.7.7 have known prototype-pollution issues.',
    'high'
  ),
  legacyLibraryRule('Prototype.js', /\bprototype(?:\.min)?\.js\b/i, 'Prototype.js is unmaintained — no security patches are released regardless of version. Consider migrating.'),
  legacyLibraryRule('MooTools', /\bmootools\b/i, 'MooTools is unmaintained — no security patches are released regardless of version. Consider migrating.'),
  legacyLibraryRule('YUI 2', /\byui\/?2[.\/]/i, 'YUI 2 has been end-of-life since 2011 and receives no security patches. Consider migrating.'),
];

const MAX_SCRIPTS_EXAMINED = 60; // pure regex/URL parsing, no network cost — higher ceiling than fetch-bound checks

export function checkVulnerableLibraries(pages: CrawledPage[]): Finding[] {
  const scriptUrls = new Set<string>();
  for (const page of pages) {
    if (!page.html) continue;
    const matches = page.html.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi);
    for (const m of matches) {
      const src = m[1];
      if (!src) continue;
      try {
        scriptUrls.add(new URL(src, page.url).toString());
      } catch {
        // relative URL that didn't resolve cleanly — skip
      }
      if (scriptUrls.size >= MAX_SCRIPTS_EXAMINED) break;
    }
    if (scriptUrls.size >= MAX_SCRIPTS_EXAMINED) break;
  }

  const hits: LibraryHit[] = [];
  for (const url of scriptUrls) {
    for (const rule of RULES) {
      const detected = rule.detect(url);
      if (detected === null) continue;
      const assessment = rule.assess(detected === 'unknown' ? null : detected);
      if (!assessment) continue;
      hits.push({ name: rule.name, version: detected === 'unknown' ? null : detected, url, severity: assessment.severity, note: assessment.note });
      break; // one rule match per script URL is enough
    }
  }

  if (hits.length === 0) {
    return [
      {
        id: 'vulnerable-js-libraries',
        category: 'webapp',
        title: 'Vulnerable/legacy JS library scan',
        severity: 'info',
        detail: `Checked ${scriptUrls.size} script URL(s) across ${pages.length} page(s) against a curated set of known-vulnerable library versions — no matches.`,
        recommendation:
          "No action needed. This check only recognizes libraries with a version visible in the script URL (very common for CDN-hosted libraries) — self-hosted bundles without a version in the filename aren't covered.",
        passed: true,
      },
    ];
  }

  const worstSeverity = hits.some((h) => h.severity === 'high') ? 'high' : hits.some((h) => h.severity === 'medium') ? 'medium' : 'info';
  const lines = hits.map((h) => `${h.name}${h.version ? ` ${h.version}` : ''} — ${h.note} (${h.url})`);

  return [
    {
      id: 'vulnerable-js-libraries',
      category: 'webapp',
      title: `${hits.length} outdated or unmaintained JS librar${hits.length === 1 ? 'y' : 'ies'} detected`,
      severity: worstSeverity,
      detail: lines.join(' | '),
      recommendation:
        'Upgrade the flagged libraries to a current patched version, or migrate off ones that are fully unmaintained. This is a version-fingerprint check against a curated list, not an exhaustive dependency audit — pair it with `npm audit`/Dependabot or similar in your actual build pipeline.',
      passed: false,
    },
  ];
}
