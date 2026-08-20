import dns from 'node:dns/promises';
import type { Finding } from '@/types/scan';
import { resolveSafeTarget, pinnedFetch, SSRFBlockedError } from '@/lib/ssrfGuard';

/**
 * Subdomain takeover: a CNAME (e.g. `blog.example.com` -> `example.herokuapp.com`)
 * left pointing at a cloud resource that's since been deleted/deprovisioned.
 * The DNS record is still live, but nothing legitimate answers for it — so
 * anyone can provision a same-named resource on that provider and the
 * subdomain will start serving their content under the victim's own domain.
 * Same class of check as the `can-i-take-over-xyz` project / Nuclei's
 * subdomain-takeover templates; purely passive (DNS lookups + a GET to each
 * candidate's own homepage), same risk profile as the rest of dns.ts.
 *
 * Two-tier detection, strongest signal first:
 *   1. The CNAME target itself no longer resolves at all ("dangling DNS") —
 *      conclusive on its own, no HTTP fetch needed.
 *   2. The CNAME target's shared infrastructure is still up (very common —
 *      s3.amazonaws.com never goes away, only the specific bucket does), but
 *      fetching the subdomain returns that provider's own "nothing claimed
 *      here" page. Matched against known fingerprint text per provider.
 *
 * Only flags when the CNAME points to a *known* takeover-prone provider
 * domain — an external CNAME to, say, a mail or CDN provider not on this
 * list is left alone entirely rather than guessed at, to avoid flagging
 * perfectly normal third-party DNS delegation as a vulnerability.
 */

const CANDIDATE_SUBDOMAINS = [
  'www', 'blog', 'shop', 'store', 'app', 'api', 'dev', 'staging', 'test', 'beta',
  'old', 'm', 'help', 'support', 'docs', 'status', 'mail', 'cdn', 'assets', 'static',
  'images', 'img', 'portal', 'admin', 'my', 'secure', 'go', 'link', 'download', 'files',
];

interface VulnerableService {
  name: string;
  cnameSuffixes: string[];
  /** Any one of these appearing is sufficient (OR semantics). */
  fingerprints: string[];
  /** If set, ALL of these must appear together (AND semantics) — for
   * services whose distinctive text is too short/generic to trust alone
   * (see Statuspage below), requiring a second, unrelated phrase to also
   * be present cuts the odds of an unrelated page coincidentally matching
   * dramatically, without needing exact knowledge of the provider's full
   * page copy. */
  requireAll?: string[];
}

const VULNERABLE_SERVICES: VulnerableService[] = [
  { name: 'Amazon S3', cnameSuffixes: ['s3.amazonaws.com', 's3-website'], fingerprints: ['NoSuchBucket', 'The specified bucket does not exist'] },
  { name: 'GitHub Pages', cnameSuffixes: ['github.io'], fingerprints: ["There isn't a GitHub Pages site here", '404 - File not found'] },
  { name: 'Heroku', cnameSuffixes: ['herokuapp.com'], fingerprints: ['No such app', 'herokucdn.com/error-pages/no-such-app'] },
  { name: 'Microsoft Azure', cnameSuffixes: ['azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net'], fingerprints: ['404 Web Site not found', 'Web App - Unavailable'] },
  { name: 'Shopify', cnameSuffixes: ['myshopify.com'], fingerprints: ['Sorry, this shop is currently unavailable'] },
  { name: 'Fastly', cnameSuffixes: ['fastly.net'], fingerprints: ['Fastly error: unknown domain'] },
  { name: 'Netlify', cnameSuffixes: ['netlify.app'], fingerprints: ['Not Found - Request ID'] },
  { name: 'Vercel', cnameSuffixes: ['vercel.app'], fingerprints: ['The deployment could not be found', 'DEPLOYMENT_NOT_FOUND'] },
  { name: 'Surge.sh', cnameSuffixes: ['surge.sh'], fingerprints: ['project not found'] },
  { name: 'Tumblr', cnameSuffixes: ['tumblr.com'], fingerprints: ["There's nothing here.", "Whatever you were looking for doesn't currently exist"] },
  // No fingerprints: "404 Not Found" is generic default-server-error text
  // — a legitimately active, claimed Cargo site could return it for any
  // unconfigured path without being unclaimed at all. Still caught via
  // the stronger "CNAME target doesn't resolve" signal below if the
  // account is genuinely gone; just not via this weaker text match.
  { name: 'Cargo', cnameSuffixes: ['cargocollective.com'], fingerprints: [] },
  // "You are being" alone is 3 words and far too generic — plausible in
  // all kinds of unrelated redirect/interstitial copy having nothing to
  // do with Statuspage. Requires the word "statuspage" to also appear,
  // which an unrelated page is very unlikely to include.
  { name: 'Statuspage', cnameSuffixes: ['statuspage.io'], fingerprints: [], requireAll: ['You are being', 'statuspage'] },
  { name: 'Zendesk', cnameSuffixes: ['zendesk.com'], fingerprints: ['Help Center Closed'] },
  { name: 'UserVoice', cnameSuffixes: ['uservoice.com'], fingerprints: ['This UserVoice subdomain is currently available!'] },
  { name: 'Help Scout', cnameSuffixes: ['helpscoutdocs.com'], fingerprints: ['No settings were found for this company'] },
  { name: 'Ghost(Pro)', cnameSuffixes: ['ghost.io'], fingerprints: ['The thing you were looking for is no longer here'] },
  { name: 'Bitbucket', cnameSuffixes: ['bitbucket.io'], fingerprints: ['Repository not found'] },
  { name: 'Webflow', cnameSuffixes: ['proxy-ssl.webflow.com', 'webflow.io'], fingerprints: ["The page you are looking for doesn't exist"] },
  { name: 'Pantheon', cnameSuffixes: ['pantheonsite.io'], fingerprints: ['The gods are wise'] },
  { name: 'Unbounce', cnameSuffixes: ['unbouncepages.com'], fingerprints: ['The requested URL was not found on this server'] },
  // Same reasoning as Cargo above — "404 Not Found" alone is too generic
  // to trust as unclaimed-resource evidence.
  { name: 'Fly.io', cnameSuffixes: ['fly.dev'], fingerprints: [] },
];

const FETCH_TIMEOUT_MS = 5000;

export async function checkSubdomainTakeover(registrableDomain: string): Promise<Finding[]> {
  const results = await Promise.all(
    CANDIDATE_SUBDOMAINS.map((label) => checkOne(`${label}.${registrableDomain}`))
  );
  const takeovers = results.filter((f): f is Finding => f !== null);
  if (takeovers.length > 0) return takeovers;

  return [
    {
      id: 'subdomain-takeover',
      category: 'dns',
      title: 'Dangling subdomain (takeover risk)',
      severity: 'pass',
      detail: `Checked ${CANDIDATE_SUBDOMAINS.length} common subdomain names — none point to an unclaimed external resource.`,
      recommendation: 'No action needed. This checks common subdomain names only, not a full DNS zone export — a subdomain outside this list wouldn\'t be caught.',
      passed: true,
    },
  ];
}

async function checkOne(hostname: string): Promise<Finding | null> {
  let cnameChain: string[];
  try {
    cnameChain = await dns.resolveCname(hostname);
  } catch {
    return null; // no CNAME (or the label doesn't exist at all) — nothing to check
  }
  const finalCname = cnameChain[cnameChain.length - 1];
  if (!finalCname) return null;

  const service = VULNERABLE_SERVICES.find((s) => s.cnameSuffixes.some((suf) => finalCname.toLowerCase().endsWith(suf)));
  if (!service) return null; // points externally, but not at a known takeover-prone provider

  // Strongest signal: the CNAME's own target doesn't resolve at all —
  // conclusively dangling, nothing to even connect to. Only counts when
  // BOTH lookups fail with a genuine "this name doesn't exist" code
  // (ENOTFOUND/ENODATA) — a transient resolver error (timeout, SERVFAIL,
  // etc.) on one or both lookups is NOT evidence of anything and must not
  // be treated as if it were; that distinction is the difference between
  // a confirmed dangling record and a false "critical" from a DNS blip.
  const [v4, v6] = await Promise.allSettled([dns.resolve4(finalCname), dns.resolve6(finalCname)]);
  const isConclusiveNonExistence = (r: PromiseSettledResult<string[]>) =>
    r.status === 'rejected' && ['ENOTFOUND', 'ENODATA'].includes((r.reason as NodeJS.ErrnoException)?.code ?? '');

  if (v4.status === 'fulfilled' || v6.status === 'fulfilled') {
    // At least one resolved — target infra is up, fall through to the
    // fingerprint-based check below.
  } else if (isConclusiveNonExistence(v4) && isConclusiveNonExistence(v6)) {
    return takeoverFinding(hostname, service, `CNAME points to ${finalCname}, which no longer resolves at all — a classic dangling-DNS takeover setup.`);
  } else {
    // Both lookups failed, but not conclusively (a timeout/SERVFAIL/etc.
    // on at least one) — genuinely unknown, not evidence either way.
    // Don't guess; just skip this candidate rather than risk a false
    // "critical" from what might be a transient DNS issue.
    return null;
  }

  // Weaker but still real signal: the provider's shared infrastructure is
  // up (it usually is — only the specific bucket/app/site is gone), but the
  // response is that provider's own "nothing claimed here" page.
  for (const scheme of ['https', 'http']) {
    try {
      const target = await resolveSafeTarget(`${scheme}://${hostname}/`);
      const res = await pinnedFetch(target, target.originalUrl, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        redirect: 'manual',
        headers: { 'User-Agent': 'AegisScanner/1.0 (+security-scan)' },
      });
      const body = (await res.text()).slice(0, 20_000);
      const matchedFingerprint = service.fingerprints.find((fp) => body.includes(fp));
      const matchedAll = service.requireAll && service.requireAll.every((fp) => body.includes(fp));

      if (matchedFingerprint || matchedAll) {
        const matchedText = matchedFingerprint ?? service.requireAll!.join('" + "');
        return takeoverFinding(
          hostname,
          service,
          `CNAME points to ${finalCname} (${service.name}); the page returned that provider's "unclaimed resource" response ("${matchedText}").`
        );
      }
      return null; // resolved fine and didn't match the fingerprint — genuinely in use
    } catch (err) {
      if (err instanceof SSRFBlockedError) return null; // resolves privately — not a public takeover target
      // network/TLS error on this scheme — try the other before giving up;
      // a fetch failure alone isn't evidence of takeover, so no finding.
    }
  }
  return null;
}

function takeoverFinding(hostname: string, service: VulnerableService, detail: string): Finding {
  return {
    id: `subdomain-takeover:${hostname}`,
    category: 'dns',
    title: `Possible subdomain takeover: ${hostname}`,
    severity: 'critical',
    detail,
    recommendation: `Remove the dangling CNAME record for ${hostname} if it's no longer in use, or re-provision the ${service.name} resource it points to. Left as-is, anyone can claim that resource on ${service.name} and serve their own content under your domain.`,
    passed: false,
  };
}
