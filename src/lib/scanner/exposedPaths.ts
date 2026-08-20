import crypto from 'node:crypto';
import type { Finding } from '@/types/scan';
import { pinnedFetch, type SafeTarget } from '@/lib/ssrfGuard';

const TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 200_000;

/**
 * Passive checks only: a plain GET to well-known paths that commonly get
 * exposed by accident (env files, VCS metadata, default admin panels,
 * debug/status endpoints). No payloads, no auth bypass attempts, nothing
 * beyond "is this URL publicly reachable" — same class of check
 * SecurityHeaders.com/Observatory-style tools perform.
 *
 * Status code alone is not enough to call something "exposed", though —
 * a very common pattern (SPA/client-side-routed frameworks, CMSes with a
 * catch-all route, some misconfigured servers) is to return HTTP 200 for
 * literally any path, serving the same index page or a styled "not found"
 * page instead of a real 404. Trusting status 200 alone there means every
 * check in this file fires as a critical/high false positive simultaneously
 * on a site that's actually fine. Two layers guard against that:
 *   1. A baseline request to a deliberately-nonexistent path establishes
 *      whether the server does this at all, and its body is compared
 *      against every "hit" — a near-identical body means it's the same
 *      catch-all page, not the real file.
 *   2. Independent of the baseline, each check's content is verified
 *      against what that specific file/page actually looks like (a .env
 *      file has KEY=value lines and isn't HTML; a phpinfo() page contains
 *      its own distinctive markers; etc.) — this also catches the case
 *      where a WAF/edge rule serves its own custom 200 "blocked" page that
 *      happens to differ from the baseline but still isn't the real thing.
 * A path only counts as exposed if it clears both.
 */
const CHECKS: {
  path: string;
  title: string;
  severity: Finding['severity'];
  recommendation: string;
  looksLikeMatch: (body: string, contentType: string) => boolean;
}[] = [
  {
    path: '/.env',
    title: 'Exposed .env file',
    severity: 'critical',
    recommendation: 'Move .env out of the web root or add a server rule blocking access to dotfiles. Rotate any credentials it contained if it has ever been publicly reachable.',
    looksLikeMatch: (body) => !/<html[\s>]|<!doctype html/i.test(body) && /^(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\S*/m.test(body),
  },
  {
    path: '/.git/config',
    title: 'Exposed .git directory',
    severity: 'critical',
    recommendation: 'Block access to /.git/ at the web server level, or ensure the deploy process never places the repo inside the public web root.',
    looksLikeMatch: (body) => /\[core\]/i.test(body) && /repositoryformatversion/i.test(body),
  },
  {
    path: '/wp-config.php.bak',
    title: 'Exposed WordPress config backup',
    severity: 'critical',
    recommendation: 'Remove backup/editor files (.bak, .swp, ~) from the web root; they often bypass PHP execution and serve source directly.',
    looksLikeMatch: (body) => /DB_NAME|DB_PASSWORD|wp-settings\.php/i.test(body),
  },
  {
    path: '/.well-known/security.txt',
    title: 'security.txt present',
    severity: 'info',
    recommendation: 'Informational — good practice, no action needed if present.',
    // RFC 9116 requires a Contact field — a generic catch-all page won't have one.
    looksLikeMatch: (body) => /^\s*contact\s*:/im.test(body),
  },
  {
    path: '/server-status',
    title: 'Apache server-status exposed',
    severity: 'high',
    recommendation: 'Disable or restrict mod_status to internal IPs only; it leaks internal request/traffic details.',
    looksLikeMatch: (body) => /apache server status/i.test(body) || /scoreboard key/i.test(body),
  },
  {
    path: '/phpinfo.php',
    title: 'Exposed phpinfo()',
    severity: 'high',
    recommendation: 'Remove phpinfo.php from production — it reveals detailed server configuration useful to attackers.',
    looksLikeMatch: (body) => /phpinfo\(\)/i.test(body) || /<title>phpinfo\(\)/i.test(body) || /PHP Version/.test(body),
  },
];

interface ProbeResult {
  status: number;
  body: string;
  contentType: string;
}

async function probe(target: SafeTarget, path: string): Promise<ProbeResult | null> {
  const url = new URL(path, `${target.protocol}//${target.hostname}`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await pinnedFetch(target, url.toString(), {
      signal: controller.signal,
      redirect: 'manual',
      headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
    });
    const body = await readBodyCapped(res, MAX_BODY_BYTES);
    return { status: res.status, body, contentType: res.headers.get('content-type') ?? '' };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Reads up to maxBytes of a response body rather than trusting res.text()
 * to download the whole thing — some of these paths (phpinfo output
 * especially) can be large, and this is a passive scanner, not a client
 * that needs the full page. */
async function readBodyCapped(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        received += value.length;
        if (received >= maxBytes) break;
      }
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).subarray(0, maxBytes).toString('utf-8');
}

/** True if two bodies are close enough in length that they're almost
 * certainly the same catch-all page (allows a little variance for a
 * timestamp/nonce some frameworks inject into an otherwise-identical
 * template). */
function bodiesLookTheSame(a: string, b: string): boolean {
  if (a === b) return true;
  if (a.length === 0 && b.length === 0) return true;
  const longer = Math.max(a.length, b.length);
  if (longer === 0) return true;
  const diff = Math.abs(a.length - b.length);
  return diff / longer < 0.05;
}

export async function checkExposedPaths(target: SafeTarget): Promise<Finding[]> {
  const baselinePath = `/__aegis_baseline_${crypto.randomBytes(8).toString('hex')}__`;
  const baseline = await probe(target, baselinePath);
  const baselineIsCatchAll = baseline !== null && baseline.status === 200;

  const results = await Promise.all(
    CHECKS.map(async (check) => {
      const result = await probe(target, check.path);

      if (!result) {
        // Network error reaching this path — treat as "not accessible"
        // (good) rather than guessing at a false positive.
        return finding(check, true, 'Not accessible');
      }

      const statusSaysPresent = result.status === 200;

      if (!statusSaysPresent) {
        const passed = check.path !== '/.well-known/security.txt';
        return finding(
          check,
          passed,
          check.path === '/.well-known/security.txt' ? `Not found (informational only)` : `Not accessible (HTTP ${result.status})`
        );
      }

      // Status is 200 — now verify it's actually the real thing, not a
      // catch-all/SPA-fallback page or a custom "200 blocked" response.
      const matchesBaseline = baselineIsCatchAll && bodiesLookTheSame(result.body, baseline!.body);
      const contentMatches = check.looksLikeMatch(result.body, result.contentType);
      const genuinelyPresent = contentMatches && !matchesBaseline;

      if (check.path === '/.well-known/security.txt') {
        return finding(
          check,
          genuinelyPresent,
          genuinelyPresent ? 'Present' : matchesBaseline ? 'HTTP 200 but this server returns 200 for any path — no genuine security.txt content found' : 'Not found (informational only)'
        );
      }

      if (!genuinelyPresent) {
        const note = matchesBaseline
          ? `This server returns HTTP 200 with the same content for any path (no real 404), and the response here doesn't match the expected content for this file — treated as not exposed.`
          : `HTTP 200 but the response doesn't match the expected content for this file — treated as not exposed.`;
        return finding(check, true, note);
      }

      return finding(check, false, `Publicly accessible (HTTP ${result.status}) and content matches what's expected — this looks like a genuine exposure.`);
    })
  );
  return results;
}

function finding(check: (typeof CHECKS)[number], passed: boolean, detail: string): Finding {
  return {
    id: `exposed:${check.path}`,
    category: 'exposure',
    title: check.title,
    severity: passed ? 'pass' : check.severity,
    detail,
    recommendation: check.recommendation,
    passed,
  };
}
