import dns from 'node:dns/promises';
import net from 'node:net';
import { Agent, fetch as undiciFetch } from 'undici';

/**
 * SSRF protection. The scanner fetches whatever URL a user submits, so every
 * outbound request must go through this guard first. It:
 *   1. Restricts to http(s) with a public-looking hostname.
 *   2. Resolves DNS itself and rejects private/reserved/loopback/link-local
 *      ranges (blocks DNS-rebinding to internal infra, cloud metadata
 *      endpoints, etc.) rather than trusting the OS resolver used by fetch().
 *   3. Blocks common cloud metadata hosts explicitly as a belt-and-suspenders
 *      check even before DNS resolution.
 *
 * Callers should use `resolveSafeTarget()` and then make the outbound
 * request against the *resolved IP*, not the original hostname, to close the
 * TOCTOU/rebinding gap. Where a library only accepts a URL (e.g. tls.connect
 * takes host+port separately so it's fine), pin appropriately.
 */

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal', // GCP metadata
  '169.254.169.254', // AWS/Azure/GCP metadata IP
]);

interface CIDR {
  base: bigint;
  bits: number;
  family: 4 | 6;
}

function ipToBigInt(ip: string, family: 4 | 6): bigint {
  if (family === 4) {
    return ip
      .split('.')
      .reduce((acc, octet) => (acc << 8n) + BigInt(parseInt(octet, 10)), 0n);
  }
  // IPv6: expand and convert
  const full = expandIPv6(ip);
  return full
    .split(':')
    .reduce((acc, group) => (acc << 16n) + BigInt(parseInt(group || '0', 16)), 0n);
}

function expandIPv6(ip: string): string {
  if (!ip.includes('::')) return ip;
  const [head, tail] = ip.split('::');
  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const missing = 8 - headParts.length - tailParts.length;
  const middle = new Array(missing).fill('0');
  return [...headParts, ...middle, ...tailParts].join(':');
}

function parseCIDR(cidr: string, family: 4 | 6): CIDR {
  const [base, bitsStr] = cidr.split('/');
  if (!base || !bitsStr) {
    throw new Error(`Malformed CIDR literal in SSRF blocklist: "${cidr}"`);
  }
  const bits = parseInt(bitsStr, 10);
  if (Number.isNaN(bits)) {
    throw new Error(`Malformed CIDR prefix length in SSRF blocklist: "${cidr}"`);
  }
  return { base: ipToBigInt(base, family), bits, family };
}

const BLOCKED_V4_CIDRS = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10', // CGNAT
  '127.0.0.0/8',
  '169.254.0.0/16', // link-local + cloud metadata
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved
].map((c) => parseCIDR(c, 4));

const BLOCKED_V6_CIDRS = [
  '::1/128', // loopback
  '::/128',
  '::ffff:0:0/96', // IPv4-mapped (checked separately too)
  'fc00::/7', // unique local
  'fe80::/10', // link-local
  '2001:db8::/32', // documentation
].map((c) => parseCIDR(c, 6));

function isBlockedIPv4(ip: string): boolean {
  const val = ipToBigInt(ip, 4);
  return BLOCKED_V4_CIDRS.some(({ base, bits }) => {
    const mask = bits === 0 ? 0n : (~0n << BigInt(32 - bits)) & 0xffffffffn;
    return (val & mask) === (base & mask);
  });
}

function isBlockedIPv6(ip: string): boolean {
  const val = ipToBigInt(ip, 6);
  return BLOCKED_V6_CIDRS.some(({ base, bits }) => {
    const mask = bits === 0 ? 0n : (~0n << BigInt(128 - bits)) & ((1n << 128n) - 1n);
    return (val & mask) === (base & mask);
  });
}

export class SSRFBlockedError extends Error {
  constructor(reason: string) {
    super(`Blocked target: ${reason}`);
    this.name = 'SSRFBlockedError';
  }
}

export interface SafeTarget {
  hostname: string;
  port: number;
  protocol: 'http:' | 'https:';
  resolvedIp: string;
  originalUrl: string;
}

/** Validates a user-submitted URL and resolves it to a safe, public IP. */
export async function resolveSafeTarget(rawUrl: string): Promise<SafeTarget> {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw new SSRFBlockedError('not a valid URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SSRFBlockedError('only http/https are allowed');
  }

  const hostname = url.hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new SSRFBlockedError('hostname is on the blocklist');
  }

  if (hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new SSRFBlockedError('internal-looking hostname');
  }

  // If the hostname is already a literal IP, validate directly.
  if (net.isIP(hostname)) {
    assertPublicIp(hostname);
    return {
      hostname,
      port: url.port ? parseInt(url.port, 10) : url.protocol === 'https:' ? 443 : 80,
      protocol: url.protocol as 'http:' | 'https:',
      resolvedIp: hostname,
      originalUrl: url.toString(),
    };
  }

  // Resolve ourselves rather than trusting fetch()'s resolver, and pin the
  // request to the specific IP we validated (prevents DNS rebinding between
  // our check and the actual request).
  let addresses: string[];
  try {
    const [v4, v6] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
    ]);
    addresses = [
      ...(v4.status === 'fulfilled' ? v4.value : []),
      ...(v6.status === 'fulfilled' ? v6.value : []),
    ];
  } catch {
    throw new SSRFBlockedError('DNS resolution failed');
  }

  if (addresses.length === 0) {
    throw new SSRFBlockedError('no DNS records found');
  }

  // Every resolved address must be public — if any single record points
  // internally, refuse the whole target rather than picking a "safe" one,
  // since an attacker fully controls which record a subsequent lookup returns.
  for (const addr of addresses) {
    assertPublicIp(addr);
  }

  const resolvedIp = addresses[0];
  if (!resolvedIp) {
    throw new SSRFBlockedError('no DNS records found');
  }

  return {
    hostname,
    port: url.port ? parseInt(url.port, 10) : url.protocol === 'https:' ? 443 : 80,
    protocol: url.protocol as 'http:' | 'https:',
    resolvedIp,
    originalUrl: url.toString(),
  };
}

/**
 * Fetches from a validated SafeTarget while pinning the TCP connection to
 * the exact IP resolveSafeTarget() already checked — closing the
 * DNS-rebinding gap where a hostname could resolve to a public IP during
 * validation and a private one moments later when fetch() re-resolves it.
 * The `lookup` override refuses to resolve anything other than the pinned
 * hostname/IP pair, so even a redirect-following or retry path can't slip
 * a different hostname through this dispatcher.
 *
 * Use this (not global fetch) for every outbound request against a
 * user-submitted target.
 */
export function pinnedFetch(target: SafeTarget, url: string, init: RequestInit = {}) {
  const dispatcher = new Agent({
    connect: {
      lookup: (hostname, options, callback) => {
        if (hostname.toLowerCase() !== target.hostname.toLowerCase()) {
          callback(new Error(`Refusing to resolve unexpected hostname: ${hostname}`), '', 4);
          return;
        }
        const family = net.isIP(target.resolvedIp) as 4 | 6;
        // undici's connector can call this in two shapes depending on
        // internal options: legacy dns.lookup(err, address, family), or
        // dns.lookup(err, [{address, family}]) when { all: true } is
        // requested (used for Happy Eyeballs dual-stack resolution). Only
        // handling the legacy shape here silently broke every request —
        // undici received a malformed result and failed the connection
        // with a generic "fetch failed", no useful detail attached.
        if (options && (options as { all?: boolean }).all) {
          callback(null, [{ address: target.resolvedIp, family }]);
        } else {
          callback(null, target.resolvedIp, family);
        }
      },
    },
  });

  return undiciFetch(url, { ...init, dispatcher } as Parameters<typeof undiciFetch>[1]);
}

export interface RedirectHop {
  url: string;
  status: number;
}

export interface FollowResult {
  response: Response;
  finalTarget: SafeTarget;
  hops: RedirectHop[];
  /** True if any hop in the chain went from an https:// location to an
   * http:// one — the thing header checks actually care about, distinct
   * from "the original request was http" (tracked separately by callers
   * via the initial SafeTarget's protocol). */
  downgradedToHttp: boolean;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Fetches a target, following same-scheme-or-not redirects up to a bound,
 * re-validating every hop through the SSRF guard (resolveSafeTarget) before
 * following it — a redirect can point anywhere (a different host, an
 * attacker-controlled one, or — the common legitimate case — apex-to-www,
 * http-to-https, or a trailing-slash normalization), so each hop gets the
 * same scrutiny the original URL did.
 *
 * Content/header-based checks (security headers, HTML-derived checks) need
 * to evaluate the page a real visitor actually lands on, not an
 * intermediate 301/302 — otherwise a plain http->https redirect (extremely
 * common, and exactly where headers like HSTS are usually absent on the
 * redirect itself but present on the destination) reads as "every security
 * header is missing" when they're actually all there on the real page.
 *
 * Callers that specifically want the raw, unfollowed response for a single
 * path (e.g. probing whether /.env or /swagger.json exists) should keep
 * using pinnedFetch with redirect: 'manual' directly — a redirect away
 * from those probe paths (e.g. to a login page) is itself informative and
 * following it would lose that signal.
 */
export async function fetchFollowingRedirects(
  initialTarget: SafeTarget,
  init: RequestInit = {},
  maxRedirects = 5
): Promise<FollowResult> {
  let target = initialTarget;
  let url = initialTarget.originalUrl;
  const hops: RedirectHop[] = [];
  let downgradedToHttp = false;
  let attempts = 0;

  for (;;) {
    const res = (await pinnedFetch(target, url, { ...init, redirect: 'manual' })) as unknown as Response;

    if (!REDIRECT_STATUSES.has(res.status) || attempts >= maxRedirects) {
      return { response: res, finalTarget: target, hops, downgradedToHttp };
    }

    const location = res.headers.get('location');
    if (!location) {
      return { response: res, finalTarget: target, hops, downgradedToHttp };
    }

    let nextUrl: URL;
    try {
      nextUrl = new URL(location, url);
    } catch {
      return { response: res, finalTarget: target, hops, downgradedToHttp };
    }
    if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
      return { response: res, finalTarget: target, hops, downgradedToHttp };
    }
    if (target.protocol === 'https:' && nextUrl.protocol === 'http:') {
      downgradedToHttp = true;
    }

    hops.push({ url: nextUrl.toString(), status: res.status });
    attempts++;

    // Re-resolve+re-validate through the full SSRF guard — the redirect
    // target is untrusted input from the server's own response, treated
    // exactly like a fresh user-submitted URL.
    target = await resolveSafeTarget(nextUrl.toString());
    url = target.originalUrl;
  }
}

function assertPublicIp(ip: string) {
  const family = net.isIP(ip);
  if (family === 4 && isBlockedIPv4(ip)) {
    throw new SSRFBlockedError('resolves to a private/reserved IP range');
  }
  if (family === 6) {
    if (ip.startsWith('::ffff:')) {
      const mapped = ip.split(':').pop()!;
      if (net.isIP(mapped) === 4) {
        assertPublicIp(mapped);
        return;
      }
    }
    if (isBlockedIPv6(ip)) {
      throw new SSRFBlockedError('resolves to a private/reserved IP range');
    }
  }
  if (family === 0) {
    throw new SSRFBlockedError('unresolvable IP');
  }
}
