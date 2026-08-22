import { pinnedFetch, fetchFollowingRedirects, type SafeTarget } from '@/lib/ssrfGuard';
import { getRegistrableDomain } from '@/lib/domain';
import { discoverAndCrawl, type CrawledPage } from './crawler';
import { checkVulnerableLibraries } from './vulnerableLibraries';
import { checkMixedContent } from './mixedContent';
import type { Finding } from '@/types/scan';

const SHORT_TIMEOUT_MS = 6000;
const MAX_SCRIPTS_SCANNED = 15; // across ALL crawled pages combined, not per-page
const MAX_SCRIPT_BYTES = 2_000_000; // cap processing, not a hard network limit
const MAX_REDIRECTS = 5;
const MAX_CRAWLED_PAGES = 12; // additional pages beyond the homepage, via sitemap.xml — see crawler.ts

/**
 * Everything here is specific to web apps/SaaS rather than generic
 * "is this server configured well" checks — CORS policy, GraphQL/API doc
 * exposure, secrets shipped in client bundles, source map leakage,
 * third-party supply-chain (SRI), and a couple of informational trust
 * signals. Runs alongside the other check categories in the main scan;
 * failures here are non-fatal to the overall scan (see the try/catch
 * wrapping in each sub-check).
 *
 * Secret/source-map/SRI checks run across every page this scan managed to
 * crawl (homepage + up to MAX_CRAWLED_PAGES sitemap-discovered pages, see
 * crawler.ts) rather than the homepage alone — a marketing homepage is
 * often the least likely page to reference an internal/authenticated
 * bundle; a dashboard or account page found via the sitemap is a much more
 * representative sample.
 */
export async function checkWebApp(target: SafeTarget): Promise<Finding[]> {
  let html = '';
  let homepageUrl = target.originalUrl;
  try {
    // Follows redirects (bounded, re-validated per hop) before reading the
    // body — same reasoning as headers.ts: a plain http->https or
    // apex<->www redirect is extremely common, and evaluating the redirect
    // response's near-empty body instead of the real homepage was silently
    // starving the SRI and trust-signal checks below of any real content.
    const { response } = await fetchFollowingRedirects(
      target,
      { signal: AbortSignal.timeout(SHORT_TIMEOUT_MS), headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' } },
      MAX_REDIRECTS
    );
    html = (await response.text()).slice(0, MAX_SCRIPT_BYTES);
    homepageUrl = response.url || homepageUrl;
  } catch {
    // Homepage fetch already reported as a critical finding by
    // checkHeaders — no need to duplicate that here. HTML-dependent
    // sub-checks below just get an empty string and report accordingly.
  }

  const homepage: CrawledPage = { url: homepageUrl, html };
  const discovery = await discoverAndCrawl(target, homepageUrl, MAX_CRAWLED_PAGES).catch(
    (): Awaited<ReturnType<typeof discoverAndCrawl>> => ({ source: 'none', totalUrlsFound: 0, pagesFetched: [] })
  );
  const pages: CrawledPage[] = [homepage, ...discovery.pagesFetched];

  const [cors, graphqlAndDocs, sourceMapsAndSecrets, sri, trust] = await Promise.all([
    checkCors(target).catch((): Finding[] => []),
    checkGraphQLAndApiDocs(target).catch((): Finding[] => []),
    checkSourceMapsAndSecrets(target, pages).catch((): Finding[] => []),
    Promise.resolve(checkSRI(pages, target)),
    Promise.resolve(checkTrustSignals(html)),
  ]);

  const vulnerableLibraries = checkVulnerableLibraries(pages);
  const mixedContent = checkMixedContent(pages, target.protocol);

  return [
    ...cors,
    ...graphqlAndDocs,
    ...sourceMapsAndSecrets,
    ...sri,
    ...trust,
    ...vulnerableLibraries,
    ...mixedContent,
    crawlCoverageFinding(homepage, discovery),
  ];
}

function crawlCoverageFinding(homepage: CrawledPage, discovery: Awaited<ReturnType<typeof discoverAndCrawl>>): Finding {
  const pagesScanned = 1 + discovery.pagesFetched.length;
  const detail =
    discovery.source === 'none'
      ? `No sitemap found (checked /sitemap.xml and robots.txt) — only the homepage (${homepage.url}) was scanned for secrets, source maps, and SRI.`
      : `Found ${discovery.totalUrlsFound} same-origin URL(s) via ${discovery.source}; scanned ${pagesScanned} page(s) total (homepage + ${discovery.pagesFetched.length} discovered).`;
  return {
    id: 'crawl-coverage',
    category: 'webapp',
    title: 'Site crawl coverage',
    severity: 'info',
    detail,
    recommendation:
      discovery.source === 'none'
        ? 'Publishing a sitemap.xml lets this scan (and search engines) discover more of your site — consider adding one if pages beyond the homepage matter for coverage here.'
        : 'No action needed. This is a coverage disclosure, not a finding about your site — it explains how much of the site the checks below actually looked at.',
    passed: true,
  };
}

// --- CORS ---

async function checkCors(target: SafeTarget): Promise<Finding[]> {
  const probeOrigin = 'https://aegis-cors-probe.invalid';
  const { response: res } = await fetchFollowingRedirects(
    target,
    { signal: AbortSignal.timeout(SHORT_TIMEOUT_MS), headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)', Origin: probeOrigin } },
    MAX_REDIRECTS
  );

  const acao = res.headers.get('access-control-allow-origin');
  const acac = res.headers.get('access-control-allow-credentials') === 'true';

  if (!acao) {
    return [
      {
        id: 'cors',
        category: 'webapp',
        title: 'CORS policy',
        severity: 'pass',
        detail: 'No CORS headers on the homepage (API/app routes may set their own — this checks the main page only).',
        recommendation: 'No action needed for this page.',
        passed: true,
      },
    ];
  }

  const reflectsArbitraryOrigin = acao === '*' || acao === probeOrigin;

  if (reflectsArbitraryOrigin && acac) {
    return [
      {
        id: 'cors',
        category: 'webapp',
        title: 'CORS allows any origin with credentials',
        severity: 'critical',
        detail: `Access-Control-Allow-Origin reflects/allows any origin (${acao}) together with Access-Control-Allow-Credentials: true.`,
        recommendation: 'Never combine a wildcard or reflected-origin CORS policy with credentialed requests — this lets any site make authenticated requests on a logged-in user\'s behalf and read the response. Use an explicit allow-list of trusted origins.',
        passed: false,
      },
    ];
  }

  if (acao === '*') {
    return [
      {
        id: 'cors',
        category: 'webapp',
        title: 'Permissive CORS policy',
        severity: 'medium',
        detail: 'Access-Control-Allow-Origin is set to "*" (no credentials allowed, so lower risk, but any site can read this response).',
        recommendation: 'If this response contains anything non-public, restrict Access-Control-Allow-Origin to a specific allow-list instead of "*".',
        passed: false,
      },
    ];
  }

  return [
    {
      id: 'cors',
      category: 'webapp',
      title: 'CORS policy',
      severity: 'pass',
      detail: `Access-Control-Allow-Origin is restricted (${acao}), not reflecting arbitrary origins.`,
      recommendation: 'No action needed.',
      passed: true,
    },
  ];
}

// --- GraphQL introspection + exposed API docs ---

const GRAPHQL_PATHS = ['/graphql', '/api/graphql'];
const API_DOC_PATHS = ['/swagger.json', '/openapi.json', '/api-docs', '/swagger-ui.html', '/v2/api-docs', '/api/openapi.json'];

async function checkGraphQLAndApiDocs(target: SafeTarget): Promise<Finding[]> {
  const findings: Finding[] = [];

  const graphqlResults = await Promise.all(
    GRAPHQL_PATHS.map(async (path) => {
      const url = new URL(path, `${target.protocol}//${target.hostname}`).toString();
      try {
        const res = await pinnedFetch(target, url, {
          method: 'POST',
          signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
          body: JSON.stringify({ query: '{__schema{queryType{name}}}' }),
        });
        if (!res.ok) return null;
        const data = (await res.json().catch(() => null)) as { data?: { __schema?: unknown } } | null;
        return data?.data?.__schema ? path : null;
      } catch {
        return null;
      }
    })
  );
  const openIntrospectionPath = graphqlResults.find(Boolean);

  findings.push(
    openIntrospectionPath
      ? {
          id: 'graphql-introspection',
          category: 'webapp',
          title: 'GraphQL introspection enabled',
          severity: 'critical',
          detail: `Introspection query succeeded against ${openIntrospectionPath} — the full API schema is publicly queryable.`,
          recommendation: 'Disable introspection in production (most GraphQL servers have a one-line config flag for this) — an exposed schema hands an attacker a complete map of your API, including fields you never intended to be discoverable.',
          passed: false,
        }
      : {
          id: 'graphql-introspection',
          category: 'webapp',
          title: 'GraphQL introspection',
          severity: 'pass',
          detail: `No open introspection found (checked ${GRAPHQL_PATHS.length} common paths).`,
          recommendation: 'No action needed.',
          passed: true,
        }
  );

  const baselinePath = `/__aegis_baseline_${Math.random().toString(16).slice(2)}__`;
  const baseline = await probeApiDocPath(target, baselinePath);

  const docResults = await Promise.all(
    API_DOC_PATHS.map(async (path) => {
      const result = await probeApiDocPath(target, path);
      if (!result || result.status !== 200) return null;

      // Same soft-404/catch-all guard as exposedPaths.ts: a server that
      // returns 200 with the same body for any path would otherwise flag
      // every doc path at once on a site that has none of them.
      if (baseline && baseline.status === 200 && bodiesLookAlike(result.body, baseline.body)) return null;

      if (!looksLikeApiDoc(result.body, result.contentType)) return null;

      return path;
    })
  );
  const exposedDocs = docResults.filter((p): p is string => Boolean(p));

  findings.push(
    exposedDocs.length > 0
      ? {
          id: 'api-docs-exposed',
          category: 'webapp',
          title: 'API documentation publicly exposed',
          severity: 'low',
          detail: `Found at: ${exposedDocs.join(', ')}`,
          recommendation: 'Exposed API docs aren\'t automatically a vulnerability, but they do hand an attacker your full API surface for free. Put them behind auth if the API isn\'t meant to be public, or confirm this exposure is intentional.',
          passed: false,
        }
      : {
          id: 'api-docs-exposed',
          category: 'webapp',
          title: 'API documentation exposure',
          severity: 'pass',
          detail: `No public API docs found (checked ${API_DOC_PATHS.length} common paths).`,
          recommendation: 'No action needed.',
          passed: true,
        }
  );

  return findings;
}

async function probeApiDocPath(target: SafeTarget, path: string): Promise<{ status: number; body: string; contentType: string } | null> {
  const url = new URL(path, `${target.protocol}//${target.hostname}`).toString();
  try {
    const res = await pinnedFetch(target, url, {
      signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
      redirect: 'manual',
      headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
    });
    const body = (await res.text()).slice(0, 50_000);
    return { status: res.status, body, contentType: res.headers.get('content-type') ?? '' };
  } catch {
    return null;
  }
}

/** Same catch-all detector used in exposedPaths.ts — near-identical body
 * length between an intentionally-nonexistent path and a "hit" means the
 * server returns 200 for anything, not that this specific doc exists. */
function bodiesLookAlike(a: string, b: string): boolean {
  if (a === b) return true;
  const longer = Math.max(a.length, b.length);
  if (longer === 0) return true;
  return Math.abs(a.length - b.length) / longer < 0.05;
}

/** Verifies the response actually looks like an OpenAPI/Swagger document
 * or a Swagger UI page, rather than trusting a 200 status alone — a JSON
 * API doc should parse and declare itself as such; an HTML doc UI page
 * has recognizable markers. */
function looksLikeApiDoc(body: string, contentType: string): boolean {
  const looksJson = /json/i.test(contentType) || /^\s*[{[]/.test(body);
  if (looksJson) {
    try {
      const parsed = JSON.parse(body);
      return Boolean(parsed && typeof parsed === 'object' && ('swagger' in parsed || 'openapi' in parsed || 'paths' in parsed));
    } catch {
      return false;
    }
  }
  return /swagger-ui/i.test(body) || /swagger\s+ui/i.test(body) || /"openapi"\s*:/i.test(body);
}

// --- Source maps + client-side secret scanning ---

// Exported so cicdChecks.ts can reuse the exact same pattern set/logic for
// scanning CI/CD config file contents, rather than maintaining a second,
// slowly-diverging copy of the same regexes.
export const SECRET_PATTERNS: { name: string; regex: RegExp; severity: Finding['severity'] }[] = [
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
  { name: 'Stripe live secret key', regex: /sk_live_[0-9a-zA-Z]{16,}/, severity: 'critical' },
  // Deliberately excludes Google API keys (AIza...) — see checkGoogleApiKeys
  // below, which handles them separately because this exact format is also
  // Firebase's client-config key, which Google documents as safe to ship
  // in client code by design (security comes from Firebase Security Rules
  // and the key's own HTTP-referrer/API restrictions, not from secrecy).
  // Flatly calling every match here "critical: rotate immediately" was a
  // guaranteed false positive on any Firebase-based site.
  { name: 'Slack token', regex: /xox[baprs]-[0-9A-Za-z-]{10,}/, severity: 'critical' },
  // Requires the full block (BEGIN...body...END), not just the header line
  // — a real private key always has substantial base64 content between the
  // markers; the header alone can appear in documentation/example code
  // (SDK docs, PEM-format placeholder text in a "paste your key" UI) that
  // never leaks actual key material.
  {
    name: 'Private key block',
    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{100,}?-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
  },
];

/** Values that show up in generic-secret regex hits constantly and are
 * never real credentials — placeholders, docs examples, and default form
 * values. Filtering these out is most of what keeps the generic matcher
 * below usable rather than a wall of noise. */
const PLACEHOLDER_VALUE_PATTERN = /your[_-]?api|api[_-]?key[_-]?here|xxxxxxxx|00000000|11111111|replace[_-]?me|change[_-]?me|example|placeholder|sample|test[_-]?key|dummy|fake[_-]?key|<[a-z_]+>/i;

/** Real API keys/secrets are near-universally a dense mix of letters and
 * digits (base64/hex/random-alphanumeric generation). A 20+ char match
 * that's pure letters with no digits at all is far more likely to be an
 * English-ish identifier, translation string, or CSS-in-JS class hash than
 * an actual secret — this is a cheap, effective filter for that class of
 * false positive without needing real entropy calculation. */
function looksRandomEnough(value: string): boolean {
  return /\d/.test(value) && /[A-Za-z]/.test(value);
}

export function isPlausibleSecretValue(value: string): boolean {
  if (PLACEHOLDER_VALUE_PATTERN.test(value)) return false;
  if (!looksRandomEnough(value)) return false;
  // All-one-character or short-repeating-pattern strings are placeholder
  // filler ("aaaaaaaaaaaaaaaaaaaa"), not generated secrets.
  if (new Set(value).size <= 3) return false;
  return true;
}

/** Generic `apiKey`/`secretKey`-style assignment. Deliberately narrower
 * than a first pass at this: dropped "access_token" from the key-name
 * group (too broad — legitimate client-side OAuth implicit-flow tokens and
 * short-lived, intentionally-public bearer tokens are routinely stored in
 * a variable with exactly that name), and the captured value now has to
 * clear isPlausibleSecretValue() above before it counts as a hit. */
const GENERIC_SECRET_REGEX = /['"]?(api[_-]?key|secret[_-]?key)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,80})['"]/gi;

export function findGenericSecretMatch(content: string): boolean {
  GENERIC_SECRET_REGEX.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = GENERIC_SECRET_REGEX.exec(content))) {
    if (isPlausibleSecretValue(match[2] ?? '')) return true;
  }
  return false;
}

const GOOGLE_API_KEY_REGEX = /AIza[0-9A-Za-z\-_]{35}/;
const FIREBASE_CONFIG_MARKERS = [/authDomain\s*[:=]/i, /projectId\s*[:=]/i, /\.firebaseapp\.com/i, /\.firebaseio\.com/i];

/** Google API keys (AIza...) get their own check rather than living in
 * SECRET_PATTERNS, because this exact format is also Firebase's public
 * client-config key — flagging every match as "critical, rotate
 * immediately" is wrong often enough (any Firebase-based site — a common
 * stack) that it needs its own, more careful message rather than a blanket
 * severity. */
function checkGoogleApiKeyContext(content: string): { found: boolean; looksLikeFirebase: boolean } {
  const found = GOOGLE_API_KEY_REGEX.test(content);
  const looksLikeFirebase = found && FIREBASE_CONFIG_MARKERS.some((p) => p.test(content));
  return { found, looksLikeFirebase };
}

/** A real JS source map is JSON with a specific, distinctive shape (per
 * the Source Map v3 spec: version, sources, and mappings are all
 * required). Requiring that shape — rather than trusting HTTP 200 alone —
 * is what stops a catch-all/SPA-fallback route (very common; same class
 * of false positive this file already guards against for API docs) from
 * making every single script on the site look like it has an exposed
 * source map. */
function looksLikeSourceMap(body: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return false;
  }
  if (!parsed || typeof parsed !== 'object') return false;
  const obj = parsed as Record<string, unknown>;
  return typeof obj.version !== 'undefined' && Array.isArray(obj.sources) && typeof obj.mappings === 'string';
}

export async function checkSourceMapsAndSecrets(target: SafeTarget, pages: CrawledPage[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Collect same-origin script URLs from every crawled page, resolving each
  // relative src against ITS OWN page URL (not always the homepage — a
  // script referenced with a relative path on /app/dashboard resolves
  // differently than the same relative path would on /), then dedupe
  // across pages before applying the combined scan cap.
  const seen = new Set<string>();
  const scriptUrls: string[] = [];
  for (const page of pages) {
    for (const rawUrl of extractResourceUrls(page.html, 'script')) {
      const resolved = resolveIfSameOrigin(rawUrl, target, page.url);
      if (!resolved || seen.has(resolved)) continue;
      seen.add(resolved);
      scriptUrls.push(resolved);
      if (scriptUrls.length >= MAX_SCRIPTS_SCANNED) break;
    }
    if (scriptUrls.length >= MAX_SCRIPTS_SCANNED) break;
  }

  if (scriptUrls.length === 0) {
    findings.push({
      id: 'client-secrets',
      category: 'webapp',
      title: 'Client-side secret scan',
      severity: 'info',
      detail: `No same-origin scripts found to scan across ${pages.length} page(s).`,
      recommendation: 'Not applicable.',
      passed: true,
    });
    return findings;
  }

  const secretHits: string[] = [];
  const firebaseKeyHits: string[] = [];
  const genuineGoogleKeyHits: string[] = [];
  const exposedMaps: string[] = [];

  await Promise.all(
    scriptUrls.map(async (scriptUrl) => {
      try {
        const res = await pinnedFetch(target, scriptUrl, {
          signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
          headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
        });
        const content = (await res.text()).slice(0, MAX_SCRIPT_BYTES);
        const path = new URL(scriptUrl).pathname;

        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(content)) {
            // Never include the matched secret itself in the finding — just
            // the pattern name and which file, enough to act on without
            // this report becoming a second copy of the leaked credential.
            secretHits.push(`${pattern.name} in ${path}`);
          }
        }
        if (findGenericSecretMatch(content)) {
          secretHits.push(`Generic API key assignment in ${path}`);
        }

        const googleKey = checkGoogleApiKeyContext(content);
        if (googleKey.looksLikeFirebase) {
          firebaseKeyHits.push(path);
        } else if (googleKey.found) {
          genuineGoogleKeyHits.push(path);
        }
      } catch {
        // unreadable script — skip, not a finding on its own
      }

      try {
        const mapRes = await pinnedFetch(target, scriptUrl + '.map', {
          signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
          redirect: 'manual',
          headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
        });
        if (mapRes.status === 200) {
          const mapBody = (await mapRes.text()).slice(0, 500_000);
          if (looksLikeSourceMap(mapBody)) {
            exposedMaps.push(new URL(scriptUrl).pathname + '.map');
          }
          // else: status 200 but not actually a source map — same
          // catch-all/soft-404 pattern this whole file guards against
          // elsewhere; a real source map has a very distinctive JSON
          // shape, so requiring that shape here is sufficient without
          // needing a separate baseline probe.
        }
      } catch {
        // no map — fine
      }
    })
  );

  const hasOnlyGenericMatches = secretHits.length > 0 && secretHits.every((h) => h.startsWith('Generic API key assignment'));

  findings.push(
    secretHits.length > 0
      ? {
          id: 'client-secrets',
          category: 'webapp',
          title: 'Possible secret exposed in client-side JavaScript',
          severity: 'critical',
          detail: `Pattern match${secretHits.length > 1 ? 'es' : ''}: ${secretHits.join('; ')}.`,
          recommendation: hasOnlyGenericMatches
            ? 'This matched a generic "apiKey: ..." assignment shape rather than a specific known key format, so confirm it\'s a real credential (not test/mock fixture data) before rotating — but treat it as a real leak until you\'ve checked, since client-side JavaScript is fully readable by anyone. Secret keys belong server-side only.'
            : 'Treat the matched credential as compromised — rotate it immediately. Client-side JavaScript is fully readable by anyone; secret keys belong server-side only, never bundled into frontend code.',
          passed: false,
        }
      : {
          id: 'client-secrets',
          category: 'webapp',
          title: 'Client-side secret scan',
          severity: 'pass',
          detail: `No obvious secret patterns found in ${scriptUrls.length} same-origin script(s) checked across ${pages.length} page(s).`,
          recommendation: 'No action needed. Note this is a pattern-based check, not a guarantee — it catches common key formats, not every possible secret.',
          passed: true,
        }
  );

  // Google/Firebase API keys are reported separately from the generic
  // secret scan above: the AIza... format is also Firebase's public
  // client-config key, which Google documents as safe to ship in client
  // code (protection comes from Firebase Security Rules and the key's own
  // HTTP-referrer/API restrictions, not secrecy). Blanket-flagging every
  // match "critical, rotate" was a guaranteed false positive on any
  // Firebase-based site — this branches the message instead of the
  // severity doing the work of a judgment call it can't make.
  if (firebaseKeyHits.length > 0) {
    findings.push({
      id: 'google-firebase-key',
      category: 'webapp',
      title: 'Firebase/Google API key found in client code',
      severity: 'info',
      detail: `Found in: ${firebaseKeyHits.join(', ')}. This looks like a Firebase client config (other Firebase config fields were found alongside it), which is designed to be public.`,
      recommendation: 'This is expected for Firebase — no need to rotate it. Instead, verify Firebase Security Rules actually restrict access to your data, and that the API key has HTTP referrer restrictions set in Google Cloud Console so it can\'t be reused from other sites.',
      passed: true,
    });
  } else if (genuineGoogleKeyHits.length > 0) {
    findings.push({
      id: 'google-api-key',
      category: 'webapp',
      title: 'Google API key found in client code',
      severity: 'medium',
      detail: `Found in: ${genuineGoogleKeyHits.join(', ')}. Many Google API keys (Maps JavaScript API, etc.) are meant to be used client-side and secured via referrer/API restrictions rather than secrecy — this isn't automatically a leak.`,
      recommendation: 'Confirm this key has HTTP referrer restrictions and is scoped to only the specific Google APIs it needs, in Google Cloud Console. If it\'s unrestricted, restrict it rather than treating this as a rotate-immediately incident.',
      passed: false,
    });
  }

  findings.push(
    exposedMaps.length > 0
      ? {
          id: 'source-maps',
          category: 'webapp',
          title: 'Source maps publicly exposed',
          severity: 'high',
          detail: `Found: ${exposedMaps.join(', ')}`,
          recommendation: 'Source maps let anyone reconstruct your original, unminified source code — including comments and internal file structure. Exclude them from production deploys, or block access to *.map at the web server level.',
          passed: false,
        }
      : {
          id: 'source-maps',
          category: 'webapp',
          title: 'Source map exposure',
          severity: 'pass',
          detail: `No exposed source maps found for ${scriptUrls.length} script(s) checked.`,
          recommendation: 'No action needed.',
          passed: true,
        }
  );

  return findings;
}

// --- Subresource Integrity / supply chain ---

export function checkSRI(pages: CrawledPage[], target: SafeTarget): Finding[] {
  const pagesWithHtml = pages.filter((p) => p.html);
  if (pagesWithHtml.length === 0) {
    return [
      {
        id: 'sri',
        category: 'webapp',
        title: 'Subresource Integrity (SRI)',
        severity: 'info',
        detail: 'Could not evaluate — no page was reachable.',
        recommendation: 'Not applicable.',
        passed: true,
      },
    ];
  }

  const ownDomain = getRegistrableDomain(target.hostname);
  const seenUrls = new Set<string>();
  const thirdParty: { url: string; hasIntegrity: boolean }[] = [];

  for (const page of pagesWithHtml) {
    const resources = [
      ...extractResourceTags(page.html, 'script').map((t) => ({ url: getAttr(t, 'src'), hasIntegrity: Boolean(getAttr(t, 'integrity')) })),
      ...extractResourceTags(page.html, 'link')
        .filter((t) => /rel\s*=\s*["']stylesheet["']/i.test(t))
        .map((t) => ({ url: getAttr(t, 'href'), hasIntegrity: Boolean(getAttr(t, 'integrity')) })),
    ].filter((r): r is { url: string; hasIntegrity: boolean } => Boolean(r.url));

    for (const r of resources) {
      let resolved: URL;
      try {
        resolved = new URL(r.url, page.url);
      } catch {
        continue;
      }
      if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue; // data:, blob:, etc. — inline, not third-party
      if (getRegistrableDomain(resolved.hostname) === ownDomain) continue;

      const key = resolved.toString();
      if (seenUrls.has(key)) continue;
      seenUrls.add(key);
      thirdParty.push({ url: key, hasIntegrity: r.hasIntegrity });
    }
  }

  if (thirdParty.length === 0) {
    return [
      {
        id: 'sri',
        category: 'webapp',
        title: 'Third-party script/style supply chain',
        severity: 'info',
        detail: `No third-party scripts or stylesheets detected across ${pagesWithHtml.length} page(s) checked.`,
        recommendation: 'Not applicable.',
        passed: true,
      },
    ];
  }

  const missingIntegrity = thirdParty.filter((r) => !r.hasIntegrity);

  return [
    missingIntegrity.length > 0
      ? {
          id: 'sri',
          category: 'webapp',
          title: 'Third-party resources without Subresource Integrity',
          severity: 'medium',
          detail: `${missingIntegrity.length} of ${thirdParty.length} third-party script(s)/stylesheet(s) (across ${pagesWithHtml.length} page(s)) load without an integrity attribute.`,
          recommendation: 'Add an integrity (SRI) attribute to third-party <script>/<link> tags where the provider supports it. Without it, a compromise at that third party becomes a full compromise of this site — the browser has no way to detect the swapped content.',
          passed: false,
        }
      : {
          id: 'sri',
          category: 'webapp',
          title: 'Third-party resources without Subresource Integrity',
          severity: 'pass',
          detail: `All ${thirdParty.length} third-party script(s)/stylesheet(s) use SRI.`,
          recommendation: 'No action needed.',
          passed: true,
        },
  ];
}

// --- SaaS trust signals (informational only — never affects score) ---

const CONSENT_MANAGER_PATTERNS = [/cookiebot/i, /onetrust/i, /cookieyes/i, /osano/i, /termly/i, /iubenda/i, /cookie-?consent/i, /cc-window/i];

export function checkTrustSignals(html: string): Finding[] {
  if (!html) return [];

  const hasPrivacyLink = /<a\b[^>]*href\s*=\s*["'][^"']*privacy[^"']*["']/i.test(html);
  const hasTermsLink = /<a\b[^>]*href\s*=\s*["'][^"']*terms[^"']*["']/i.test(html);
  const hasCookieConsent = CONSENT_MANAGER_PATTERNS.some((p) => p.test(html));

  // Informational only — always passed: true, never scored. Presence/
  // absence here is a compliance/sales signal, not a vulnerability.
  return [
    {
      id: 'trust-privacy-policy',
      category: 'webapp',
      title: 'Privacy policy link',
      severity: 'info',
      detail: hasPrivacyLink ? 'A link to a privacy policy was found on the homepage.' : 'No link to a privacy policy was found on the homepage.',
      recommendation: hasPrivacyLink ? 'No action needed.' : 'Consider linking a privacy policy — increasingly expected by users and often a prerequisite for enterprise/B2B deals.',
      passed: true,
    },
    {
      id: 'trust-terms',
      category: 'webapp',
      title: 'Terms of service link',
      severity: 'info',
      detail: hasTermsLink ? 'A link to terms of service was found on the homepage.' : 'No link to terms of service was found on the homepage.',
      recommendation: hasTermsLink ? 'No action needed.' : 'Consider linking terms of service, especially before accepting payments or user data.',
      passed: true,
    },
    {
      id: 'trust-cookie-consent',
      category: 'webapp',
      title: 'Cookie consent tooling',
      severity: 'info',
      detail: hasCookieConsent ? 'A recognized cookie-consent tool was detected.' : 'No recognized cookie-consent tool was detected (heuristic check — a custom-built banner won\'t be detected).',
      recommendation: hasCookieConsent ? 'No action needed.' : 'If this site sets non-essential cookies (analytics, ads) for EU/UK/California visitors, a consent mechanism is likely required.',
      passed: true,
    },
  ];
}

// --- Shared HTML parsing helpers (regex-based — good enough for tag/attr
// extraction without pulling in a full HTML parser dependency) ---

function extractResourceTags(html: string, tagName: 'script' | 'link'): string[] {
  const re = new RegExp(`<${tagName}\\b[^>]*>`, 'gi');
  return html.match(re) ?? [];
}

function getAttr(tag: string, attr: string): string | null {
  const re = new RegExp(`${attr}\\s*=\\s*["']([^"']*)["']`, 'i');
  return tag.match(re)?.[1] ?? null;
}

function extractResourceUrls(html: string, tagName: 'script'): string[] {
  return extractResourceTags(html, tagName)
    .map((t) => getAttr(t, 'src'))
    .filter((u): u is string => Boolean(u));
}

/** Resolves a possibly-relative resource URL against `baseUrl` (the page it
 * was found on — crawled pages live at different paths, so this can't
 * always be the homepage) and returns it only if it's same-hostname as the
 * target (pinnedFetch refuses cross-hostname requests by design — this
 * filters before we'd hit that rather than after). */
function resolveIfSameOrigin(url: string, target: SafeTarget, baseUrl: string): string | null {
  try {
    const resolved = new URL(url, baseUrl);
    return resolved.hostname.toLowerCase() === target.hostname.toLowerCase() ? resolved.toString() : null;
  } catch {
    return null;
  }
}
