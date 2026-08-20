import type { Finding } from '@/types/scan';
import { fetchFollowingRedirects, type SafeTarget } from '@/lib/ssrfGuard';

const TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;

/**
 * Fetches the target once and evaluates response headers. Works the same
 * for a marketing site or a bare JSON API — the checks that matter (HSTS,
 * frame protections, content-type sniffing, CSP, cookie flags, and info
 * leakage via Server/X-Powered-By) are relevant to any HTTP-speaking app.
 *
 * Follows redirects (bounded, re-validated per hop — see
 * lib/ssrfGuard.fetchFollowingRedirects) before evaluating headers. This
 * matters: a plain http->https redirect, or an apex<->www redirect, is
 * extremely common and security headers are typically set on the final
 * response, not the redirect itself. Evaluating the redirect response's
 * headers instead of the destination's was previously reporting "missing"
 * for HSTS/CSP/X-Frame-Options/etc. on a large fraction of real sites that
 * have every one of those headers correctly configured on the page a
 * visitor actually lands on.
 */
export async function checkHeaders(target: SafeTarget): Promise<Finding[]> {
  const findings: Finding[] = [];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let res: Response;
  let downgradedToHttp = false;
  let finalIsHttps = target.protocol === 'https:';
  try {
    const result = await fetchFollowingRedirects(
      target,
      { signal: controller.signal, headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' } },
      MAX_REDIRECTS
    );
    res = result.response;
    downgradedToHttp = result.downgradedToHttp;
    finalIsHttps = result.finalTarget.protocol === 'https:';
  } catch (err) {
    clearTimeout(timer);
    findings.push({
      id: 'connectivity',
      category: 'headers',
      title: 'Site unreachable',
      severity: 'critical',
      detail: `Could not connect to ${target.hostname}: ${describeFetchError(err)}`,
      recommendation: 'Confirm the URL is correct and the server is publicly reachable.',
      passed: false,
    });
    return findings;
  } finally {
    clearTimeout(timer);
  }

  const h = res.headers;
  const originalWasHttps = target.protocol === 'https:';

  findings.push(
    boolCheck(
      'hsts',
      'headers',
      'HTTP Strict Transport Security (HSTS)',
      finalIsHttps && Boolean(h.get('strict-transport-security')),
      `Header ${h.get('strict-transport-security') ? 'present: ' + h.get('strict-transport-security') : 'missing'}`,
      'Add "Strict-Transport-Security: max-age=63072000; includeSubDomains" to force HTTPS on every visit.',
      'medium'
    )
  );

  findings.push(
    boolCheck(
      'x-frame-options',
      'headers',
      'Clickjacking protection (X-Frame-Options / frame-ancestors)',
      Boolean(h.get('x-frame-options')) || /frame-ancestors/i.test(h.get('content-security-policy') || ''),
      h.get('x-frame-options') ? `X-Frame-Options: ${h.get('x-frame-options')}` : 'No frame protection found',
      'Add "X-Frame-Options: DENY" or a CSP frame-ancestors directive to prevent clickjacking.',
      'medium'
    )
  );

  findings.push(
    boolCheck(
      'content-type-options',
      'headers',
      'MIME-sniffing protection',
      h.get('x-content-type-options') === 'nosniff',
      h.get('x-content-type-options') ? `Present: ${h.get('x-content-type-options')}` : 'Missing',
      'Add "X-Content-Type-Options: nosniff" to stop browsers guessing content types.',
      'low'
    )
  );

  findings.push(
    boolCheck(
      'csp',
      'headers',
      'Content Security Policy',
      Boolean(h.get('content-security-policy')),
      h.get('content-security-policy') ? 'Present' : 'Missing',
      'Add a Content-Security-Policy header to reduce the impact of any XSS that does slip through.',
      'medium'
    )
  );

  findings.push(
    boolCheck(
      'referrer-policy',
      'headers',
      'Referrer-Policy',
      Boolean(h.get('referrer-policy')),
      h.get('referrer-policy') ? `Present: ${h.get('referrer-policy')}` : 'Missing',
      'Add "Referrer-Policy: strict-origin-when-cross-origin" to limit data leaked via the Referer header.',
      'low'
    )
  );

  const serverHeader = h.get('server');
  const poweredBy = h.get('x-powered-by');
  const leaksInfo = Boolean((serverHeader && /\d/.test(serverHeader)) || poweredBy);
  findings.push(
    boolCheck(
      'info-leak',
      'headers',
      'Server/version information leakage',
      !leaksInfo,
      leaksInfo
        ? `Reveals: ${[serverHeader, poweredBy].filter(Boolean).join(', ')}`
        : 'No version-revealing headers found',
      'Remove or generalize the Server and X-Powered-By headers so attackers can\'t target known vulnerabilities for your exact stack version.',
      'low'
    )
  );

  // Set-Cookie is evaluated per individual cookie via getSetCookie() (Node
  // 18.14+), not headers.get('set-cookie') — the Fetch spec has get()
  // comma-join multiple Set-Cookie headers into one string, which is
  // unsafe (a cookie's own Expires value contains a comma) and also masks
  // the case where SOME cookies are missing flags and others aren't: a
  // combined-string substring search reports "found" as long as *any*
  // cookie has Secure/HttpOnly, even if a different, sensitive cookie on
  // the same response doesn't.
  const setCookies = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  if (setCookies.length > 0) {
    const insecureCookies = setCookies.filter((c) => !/;\s*secure(?:;|$)/i.test(c));
    const nonHttpOnlyCookies = setCookies.filter((c) => !/;\s*httponly(?:;|$)/i.test(c));
    const allOk = insecureCookies.length === 0 && nonHttpOnlyCookies.length === 0;
    findings.push(
      boolCheck(
        'cookie-flags',
        'headers',
        'Cookie security flags',
        allOk,
        allOk
          ? `${setCookies.length} cookie(s) observed, all with Secure and HttpOnly set`
          : `${insecureCookies.length} of ${setCookies.length} cookie(s) missing Secure, ${nonHttpOnlyCookies.length} missing HttpOnly`,
        'Set Secure, HttpOnly, and SameSite attributes on all cookies, especially session cookies.',
        'high'
      )
    );
  }

  // "Not served over HTTPS" reflects what was actually typed/requested —
  // if that was http://, flag it regardless of where redirects end up.
  if (!originalWasHttps) {
    findings.push({
      id: 'no-https',
      category: 'headers',
      title: 'Site not served over HTTPS',
      severity: 'critical',
      detail: `Scanned over plain HTTP (${target.originalUrl})`,
      recommendation: 'Serve the site exclusively over HTTPS with a valid TLS certificate and redirect all HTTP traffic.',
      passed: false,
    });
  } else if (downgradedToHttp) {
    // Distinct from the above: started on https, but somewhere in the
    // redirect chain a hop pointed back to http://. Checked across the
    // whole followed chain now, not just a single top-level redirect.
    findings.push({
      id: 'https-downgrade',
      category: 'headers',
      title: 'Redirects downgrade to HTTP',
      severity: 'high',
      detail: 'One or more redirects in the chain point from https:// back to an http:// URL.',
      recommendation: 'Ensure all redirects stay on HTTPS; never redirect from https:// to http://.',
      passed: false,
    });
  }

  return findings;
}

/**
 * undici's fetch() throws a generic `TypeError: fetch failed` — the real
 * cause (DNS failure, connection refused, TLS error, timeout) lives on
 * `err.cause`, not `err.message`. Without unwrapping it, every connectivity
 * failure looks identical and gives the person running the scan nothing to
 * act on.
 */
function describeFetchError(err: unknown): string {
  if (!(err instanceof Error)) return 'unknown error';
  const cause = (err as Error & { cause?: unknown }).cause;
  if (cause instanceof Error) {
    const code = (cause as NodeJS.ErrnoException).code;
    return code ? `${cause.message} (${code})` : cause.message;
  }
  return err.message;
}

function boolCheck(
  id: string,
  category: Finding['category'],
  title: string,
  passed: boolean,
  detail: string,
  recommendation: string,
  severityIfFailed: Finding['severity']
): Finding {
  return {
    id,
    category,
    title,
    severity: passed ? 'pass' : severityIfFailed,
    detail,
    recommendation,
    passed,
  };
}
