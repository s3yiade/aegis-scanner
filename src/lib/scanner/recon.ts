import crypto from 'node:crypto';
import type { Finding } from '@/types/scan';
import { pinnedFetch, type SafeTarget } from '@/lib/ssrfGuard';
import { getEndpointCopy } from './endpointNiche';

/**
 * "Attack-surface recon" checks — framed the way a threat actor's initial,
 * unauthenticated reconnaissance pass against a target would look, rather
 * than "is this server configured well" (headers.ts/tls.ts/dns.ts) or
 * "is this a web-app-specific misconfiguration" (webapp.ts). Same rules as
 * every other check in this scanner apply: passive/read-only, no
 * exploitation, no credential guessing, no payloads beyond a harmless
 * probe value, bounded number of requests, non-fatal to the overall scan.
 *
 * Everything here uses pinnedFetch against the already-SSRF-validated
 * target, same as every other check.
 */

const SHORT_TIMEOUT_MS = 6000;
const USER_AGENT = 'AegisScanner/1.0 (+security-scan)';

export async function checkRecon(target: SafeTarget, opts: { endpointType?: string | null } = {}): Promise<Finding[]> {
  const [methods, verboseErrors, hostHeaderTrust, openRedirect, accessSurface, rateLimit] = await Promise.all([
    checkHttpMethods(target).catch((): Finding[] => []),
    checkVerboseErrors(target).catch((): Finding[] => []),
    checkHostHeaderTrust(target).catch((): Finding[] => []),
    checkOpenRedirect(target).catch((): Finding[] => []),
    checkEndpointAccessSurface(target, opts.endpointType).catch((): Finding[] => []),
    checkRateLimiting(target).catch((): Finding[] => []),
  ]);

  return [...methods, ...verboseErrors, ...hostHeaderTrust, ...openRedirect, ...accessSurface, ...rateLimit];
}

// --- HTTP method enumeration ---
// A threat actor's first move against an unfamiliar endpoint is usually
// OPTIONS, to see what's even on the table. Flags methods that shouldn't
// normally be open to the world (TRACE — enables cross-site tracing/cookie
// theft in older browsers; and PUT/DELETE, which aren't dangerous by
// themselves but are worth a "verify these are actually auth-gated" flag
// since an OPTIONS response can't tell us whether they check auth).

const NOTABLE_METHODS = ['TRACE', 'CONNECT', 'PUT', 'DELETE'];

async function checkHttpMethods(target: SafeTarget): Promise<Finding[]> {
  const url = `${target.protocol}//${target.hostname}/`;
  const res = await pinnedFetch(target, url, {
    method: 'OPTIONS',
    signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
    headers: { 'User-Agent': USER_AGENT },
  });

  const allowHeader = res.headers.get('allow');
  if (!allowHeader) {
    return [
      {
        id: 'http-methods',
        category: 'recon',
        title: 'HTTP method enumeration',
        severity: 'info',
        detail: 'OPTIONS request returned no Allow header — the server may not implement OPTIONS, or handles it per-route rather than globally.',
        recommendation: 'No action needed from this check alone.',
        passed: true,
      },
    ];
  }

  const allowed = allowHeader.split(',').map((m) => m.trim().toUpperCase());
  const risky = NOTABLE_METHODS.filter((m) => allowed.includes(m));
  const traceEnabled = allowed.includes('TRACE');

  if (traceEnabled) {
    return [
      {
        id: 'http-methods',
        category: 'recon',
        title: 'TRACE method enabled',
        severity: 'medium',
        detail: `Allowed methods: ${allowed.join(', ')}. TRACE is enabled.`,
        recommendation: 'Disable the TRACE method at the web server/proxy level — it has no legitimate use in production and has historically been used to bypass HttpOnly cookie protections (Cross-Site Tracing).',
        passed: false,
      },
    ];
  }

  if (risky.length > 0) {
    return [
      {
        id: 'http-methods',
        category: 'recon',
        title: 'State-changing HTTP methods advertised',
        severity: 'low',
        detail: `Allowed methods: ${allowed.join(', ')}. This only reflects what's advertised, not whether these methods require authentication.`,
        recommendation: `Confirm ${risky.join('/')} actually require authentication/authorization on this route — an OPTIONS response can't verify that, only that the method isn't rejected outright.`,
        passed: false,
      },
    ];
  }

  return [
    {
      id: 'http-methods',
      category: 'recon',
      title: 'HTTP method enumeration',
      severity: 'pass',
      detail: `Allowed methods: ${allowed.join(', ')}. Nothing unexpected advertised.`,
      recommendation: 'No action needed.',
      passed: true,
    },
  ];
}

// --- Verbose error / debug disclosure ---
// Requests a path designed to 404 and inspects the response for stack
// traces, internal file paths, or a framework debug page — the kind of
// thing that hands a threat actor your language/framework/version and
// sometimes source file layout for free, before they've done anything else.

const DEBUG_MARKERS: { pattern: RegExp; label: string }[] = [
  { pattern: /traceback \(most recent call last\)/i, label: 'Python traceback' },
  { pattern: /whitelabel error page/i, label: 'Spring Boot debug page' },
  { pattern: /\bat\s+[\w.$]+\([\w.]+\.(?:java|kt):\d+\)/, label: 'Java stack trace' },
  { pattern: /Fatal error:.*\bin\b.*\bon line\b/i, label: 'PHP fatal error' },
  { pattern: /Warning:.*\bin\b.*\bon line\b/i, label: 'PHP warning with file path' },
  { pattern: /System\.(?:Exception|NullReferenceException|Web\.HttpException)/, label: '.NET exception' },
  { pattern: /Server Error in '\/' Application/i, label: 'ASP.NET debug page' },
  { pattern: /at\s+[\w./\\]+:\d+:\d+/, label: 'Node.js stack trace' },
  { pattern: /django\.core\.exceptions|You're seeing this error because you have DEBUG = True/i, label: 'Django debug page' },
  { pattern: /whoops.*(exception|error)/i, label: 'PHP Whoops debug page' },
];

async function checkVerboseErrors(target: SafeTarget): Promise<Finding[]> {
  const probePath = `/__aegis_recon_${crypto.randomBytes(6).toString('hex')}__`;
  const url = new URL(probePath, `${target.protocol}//${target.hostname}`).toString();

  const res = await pinnedFetch(target, url, {
    signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
    redirect: 'manual',
    headers: { 'User-Agent': USER_AGENT, Accept: 'text/html' },
  });

  const body = (await res.text().catch(() => '')).slice(0, 50_000);
  const hit = DEBUG_MARKERS.find((m) => m.pattern.test(body));

  if (hit) {
    return [
      {
        id: 'verbose-errors',
        category: 'recon',
        title: 'Verbose error / debug page disclosure',
        severity: 'high',
        detail: `A request to a nonexistent path returned what looks like a ${hit.label}, which typically reveals framework/language version and internal file paths.`,
        recommendation: 'Disable debug/development mode in production (e.g. Django DEBUG=False, ASP.NET customErrors, a generic error handler for unhandled exceptions) so unexpected errors return a plain error page instead of internals.',
        passed: false,
      },
    ];
  }

  return [
    {
      id: 'verbose-errors',
      category: 'recon',
      title: 'Verbose error / debug page disclosure',
      severity: 'pass',
      detail: 'No recognizable stack trace or framework debug page found on a request to a nonexistent path.',
      recommendation: 'No action needed.',
      passed: true,
    },
  ];
}

// --- Host header trust (X-Forwarded-Host reflection) ---
// A very common real-world pattern: an app builds absolute URLs (password
// reset links, canonical links, redirects) from a forwarded-host header
// without validating it against an allow-list. This sends one harmless
// X-Forwarded-Host value and checks whether it comes back reflected
// anywhere in the response — never touches the actual Host header (which
// fetch implementations generally refuse to override, for good reason).

async function checkHostHeaderTrust(target: SafeTarget): Promise<Finding[]> {
  const probeHost = `aegis-host-trust-probe-${crypto.randomBytes(4).toString('hex')}.invalid`;
  const url = `${target.protocol}//${target.hostname}/`;

  const res = await pinnedFetch(target, url, {
    signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
    redirect: 'manual',
    headers: {
      'User-Agent': USER_AGENT,
      'X-Forwarded-Host': probeHost,
      'X-Forwarded-Proto': 'https',
    },
  });

  const location = res.headers.get('location') ?? '';
  const body = res.status >= 300 && res.status < 400 ? '' : (await res.text().catch(() => '')).slice(0, 20_000);
  const reflected = location.includes(probeHost) || body.includes(probeHost);

  if (reflected) {
    return [
      {
        id: 'host-header-trust',
        category: 'recon',
        title: 'X-Forwarded-Host reflected untrusted',
        severity: 'medium',
        detail: 'A spoofed X-Forwarded-Host value was reflected back in a redirect Location or the response body — the kind of trust that enables Host-header-based cache poisoning or password-reset-link poisoning if this value feeds into generated URLs.',
        recommendation: 'Validate/allow-list the forwarded-host value at the load balancer or app level rather than trusting it verbatim, especially anywhere it\'s used to build absolute URLs (email links, redirects, canonical tags).',
        passed: false,
      },
    ];
  }

  return [
    {
      id: 'host-header-trust',
      category: 'recon',
      title: 'X-Forwarded-Host trust',
      severity: 'pass',
      detail: 'A spoofed X-Forwarded-Host value was not reflected in the response.',
      recommendation: 'No action needed.',
      passed: true,
    },
  ];
}

// --- Open redirect probe ---
// Tries a handful of common redirect-parameter names on the homepage with
// a value pointing at a domain we control the meaning of (an .invalid TLD,
// never resolvable), and checks whether the app redirects straight to it.

const REDIRECT_PARAMS = ['redirect', 'redirect_uri', 'next', 'url', 'return_to', 'continue', 'destination'];

async function checkOpenRedirect(target: SafeTarget): Promise<Finding[]> {
  const probeHost = `aegis-redirect-probe-${crypto.randomBytes(4).toString('hex')}.invalid`;
  const probeUrl = `https://${probeHost}/`;

  const results = await Promise.all(
    REDIRECT_PARAMS.map(async (param) => {
      const url = new URL(`${target.protocol}//${target.hostname}/`);
      url.searchParams.set(param, probeUrl);
      try {
        const res = await pinnedFetch(target, url.toString(), {
          signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
          redirect: 'manual',
          headers: { 'User-Agent': USER_AGENT },
        });
        const location = res.headers.get('location') ?? '';
        if (res.status >= 300 && res.status < 400 && location.includes(probeHost)) return param;
        return null;
      } catch {
        return null;
      }
    })
  );

  const vulnerableParams = results.filter((p): p is string => Boolean(p));

  if (vulnerableParams.length > 0) {
    return [
      {
        id: 'open-redirect',
        category: 'recon',
        title: 'Open redirect',
        severity: 'medium',
        detail: `The following query parameter(s) redirect straight to an arbitrary external URL: ${vulnerableParams.join(', ')}.`,
        recommendation: 'Validate redirect targets against an allow-list of known-good paths/domains rather than redirecting to whatever a query parameter contains. Open redirects are commonly chained into phishing (a link that starts on your trusted domain, then bounces the visitor elsewhere).',
        passed: false,
      },
    ];
  }

  return [
    {
      id: 'open-redirect',
      category: 'recon',
      title: 'Open redirect',
      severity: 'pass',
      detail: `Checked ${REDIRECT_PARAMS.length} common redirect parameter names on the homepage — none redirected to an external probe URL.`,
      recommendation: 'No action needed.',
      passed: true,
    },
  ];
}

// --- Endpoint access-surface probe ---
// The part that most directly mirrors a threat actor's target research:
// try a short, curated list of paths that commonly exist for a given kind
// of endpoint (billing, admin, profile, webhook, ...) and see what's
// reachable without any credentials. Uses the same baseline/catch-all
// guard as exposedPaths.ts so a server that 200s on everything doesn't
// generate a false positive for every path at once. A 200 here is
// reported as "reachable without authentication, verify this is
// intended" — not a confirmed data leak, since a genuinely public
// endpoint returning 200 is not itself a vulnerability.

const GENERIC_SURFACE_PATHS = ['/api/admin', '/api/internal', '/api/debug', '/api/config', '/api/status', '/api/health'];

async function checkEndpointAccessSurface(target: SafeTarget, endpointType?: string | null): Promise<Finding[]> {
  const endpointCopy = getEndpointCopy(endpointType);
  const paths = Array.from(new Set([...GENERIC_SURFACE_PATHS, ...(endpointCopy?.probePaths ?? [])]));

  const baselinePath = `/__aegis_recon_baseline_${crypto.randomBytes(8).toString('hex')}__`;
  const baseline = await probeJson(target, baselinePath);
  const baselineIsCatchAll = baseline !== null && baseline.status === 200;

  const results = await Promise.all(
    paths.map(async (path) => {
      const result = await probeJson(target, path);
      if (!result || result.status !== 200) return null;
      if (baselineIsCatchAll && bodiesLookTheSame(result.body, baseline!.body)) return null;
      return path;
    })
  );

  const reachable = results.filter((p): p is string => Boolean(p));

  if (reachable.length > 0) {
    const framing = endpointCopy
      ? ` — for a ${endpointCopy.label.toLowerCase()}, that means: ${endpointCopy.whyItMatters}`
      : '';
    return [
      {
        id: 'endpoint-access-surface',
        category: 'recon',
        title: 'Endpoint reachable without authentication',
        severity: endpointType === 'admin' ? 'critical' : 'medium',
        detail: `${reachable.length} path(s) responded HTTP 200 with no credentials supplied: ${reachable.join(', ')}. This confirms reachability, not that sensitive data was returned — verify this is intentionally public.${framing}`,
        recommendation: 'Require authentication on every endpoint that isn\'t deliberately public, and confirm that with a direct unauthenticated request like this one rather than assuming the frontend won\'t link to it.',
        passed: false,
      },
    ];
  }

  return [
    {
      id: 'endpoint-access-surface',
      category: 'recon',
      title: 'Endpoint access-surface probe',
      severity: 'pass',
      detail: `Checked ${paths.length} common ${endpointCopy ? endpointCopy.label.toLowerCase() + ' ' : ''}path(s) — none were reachable without authentication.`,
      recommendation: 'No action needed.',
      passed: true,
    },
  ];
}

interface ProbeResult {
  status: number;
  body: string;
}

async function probeJson(target: SafeTarget, path: string): Promise<ProbeResult | null> {
  const url = new URL(path, `${target.protocol}//${target.hostname}`).toString();
  try {
    const res = await pinnedFetch(target, url, {
      signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
      redirect: 'manual',
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json, text/plain, */*' },
    });
    const body = (await res.text().catch(() => '')).slice(0, 20_000);
    return { status: res.status, body };
  } catch {
    return null;
  }
}

function bodiesLookTheSame(a: string, b: string): boolean {
  if (a === b) return true;
  if (a.length === 0 && b.length === 0) return true;
  const longer = Math.max(a.length, b.length);
  if (longer === 0) return true;
  return Math.abs(a.length - b.length) / longer < 0.05;
}

// --- Rate-limit presence heuristic ---
// A short, bounded burst of requests against the homepage to see whether
// any rate-limiting kicks in at all. This is a light heuristic, not a load
// test: 6 requests, fired with small spacing, purely observational. Absence
// of a 429 in 6 requests doesn't prove there's no rate limiting (real
// limits are very often set well above 6/few-seconds) — flagged as info,
// not a scored failure, for exactly that reason.

const RATE_LIMIT_PROBE_COUNT = 6;
const RATE_LIMIT_PROBE_SPACING_MS = 150;

async function checkRateLimiting(target: SafeTarget): Promise<Finding[]> {
  const url = `${target.protocol}//${target.hostname}/`;
  let saw429 = false;
  let sawRateLimitHeader = false;

  for (let i = 0; i < RATE_LIMIT_PROBE_COUNT; i++) {
    try {
      const res = await pinnedFetch(target, url, {
        signal: AbortSignal.timeout(SHORT_TIMEOUT_MS),
        redirect: 'manual',
        headers: { 'User-Agent': USER_AGENT },
      });
      if (res.status === 429) saw429 = true;
      if (res.headers.get('retry-after') || res.headers.get('ratelimit-limit') || res.headers.get('x-ratelimit-limit')) {
        sawRateLimitHeader = true;
      }
    } catch {
      // network hiccup mid-burst — not conclusive either way, keep going
    }
    if (i < RATE_LIMIT_PROBE_COUNT - 1) {
      await new Promise((resolve) => setTimeout(resolve, RATE_LIMIT_PROBE_SPACING_MS));
    }
  }

  if (saw429 || sawRateLimitHeader) {
    return [
      {
        id: 'rate-limit-heuristic',
        category: 'recon',
        title: 'Rate limiting observed',
        severity: 'pass',
        detail: saw429
          ? `Received an HTTP 429 within a burst of ${RATE_LIMIT_PROBE_COUNT} requests.`
          : 'Rate-limit headers (Retry-After / RateLimit-Limit) were present on responses.',
        recommendation: 'No action needed.',
        passed: true,
      },
    ];
  }

  return [
    {
      id: 'rate-limit-heuristic',
      category: 'recon',
      title: 'No rate limiting observed',
      severity: 'info',
      detail: `No HTTP 429 or rate-limit headers seen in a burst of ${RATE_LIMIT_PROBE_COUNT} quick requests. This is a light heuristic, not conclusive — real limits are often set above this threshold, and this only checked the homepage.`,
      recommendation: 'If this endpoint accepts sensitive input (login, password reset, billing actions), confirm rate limiting exists independently of this check — brute-force and credential-stuffing protection is worth verifying directly.',
      passed: true,
    },
  ];
}
