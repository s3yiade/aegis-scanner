import { resolveSafeTarget } from '@/lib/ssrfGuard';
import { getRegistrableDomain } from '@/lib/domain';
import { checkHeaders } from './headers';
import { checkTls } from './tls';
import { checkDns } from './dns';
import { checkExposedPaths } from './exposedPaths';
import { checkWebApp } from './webapp';
import { checkSubdomainTakeover } from './subdomainTakeover';
import { checkRecon } from './recon';
import { checkCicdExposure } from './cicdChecks';
import { checkCloudStorageExposure } from './cloudStorage';
import { checkCertTransparencySubdomains } from './ctLogs';
import { scanForCloneDomains } from './cloneDetection';
import { scoreFindings } from './score';
import type { CloneCandidate, Finding, ScanResult } from '@/types/scan';

export interface RunScanInput {
  targetUrl: string;
  targetType?: 'web' | 'api'; // agnostic: same checks apply, this only affects report framing
  niche?: string | null;
  // Only meaningful when targetType === 'api' — tailors the recon check's
  // access-surface path list and report copy. See lib/scanner/endpointNiche.ts.
  endpointType?: string | null;
}

/**
 * Runs the full check suite in parallel against a single validated target.
 * "Agnostic" here means: no assumption the target renders HTML or is a
 * marketing site. Headers, TLS, DNS, and exposed-path checks are all
 * protocol-level and apply equally to a REST/GraphQL API backend, an SPA,
 * or a traditional server-rendered site. `targetType` only changes report
 * copy (e.g. "API endpoint" vs "website"), not which checks run.
 */
export async function runScan(input: RunScanInput): Promise<ScanResult> {
  const target = await resolveSafeTarget(input.targetUrl);

  const [
    headerFindings,
    tlsFindings,
    dnsFindings,
    takeoverFindings,
    exposureFindings,
    webAppFindings,
    reconFindings,
    cicdFindings,
    cloudStorageFindings,
    ctLogFindings,
    cloneCandidates,
  ] = await Promise.all([
    checkHeaders(target).catch((): Finding[] => [errorFinding('headers', String(target.hostname))]),
    checkTls(target).catch((): Finding[] => [errorFinding('tls', String(target.hostname))]),
    checkDns(getRegistrableDomain(target.hostname)).catch((): Finding[] => [errorFinding('dns', String(target.hostname))]),
    checkSubdomainTakeover(getRegistrableDomain(target.hostname)).catch((): Finding[] => [
      errorFinding('dns', String(target.hostname)),
    ]),
    checkExposedPaths(target).catch((): Finding[] => [errorFinding('exposure', String(target.hostname))]),
    checkWebApp(target).catch((): Finding[] => [errorFinding('webapp', String(target.hostname))]),
    // Threat-actor-style recon: HTTP method enumeration, verbose error
    // disclosure, Host header trust, open redirects, and an
    // endpoint-type-aware unauthenticated access-surface probe. Same
    // agnostic/passive rules as everything else — see recon.ts.
    checkRecon(target, { endpointType: input.endpointType }).catch((): Finding[] => [errorFinding('recon', String(target.hostname))]),
    // CI/CD pipeline + supply-chain config exposure (GitHub Actions,
    // CircleCI, Jenkins, Terraform state, .npmrc, etc.) — see cicdChecks.ts.
    checkCicdExposure(target).catch((): Finding[] => [errorFinding('cicd', String(target.hostname))]),
    // These two hit fixed external services (AWS/GCS, crt.sh) rather than
    // the target itself — see the SSRF-reasoning comments in each file for
    // why they use plain fetch instead of pinnedFetch.
    checkCloudStorageExposure(target.hostname).catch((): Finding[] => [errorFinding('exposure', String(target.hostname))]),
    checkCertTransparencySubdomains(getRegistrableDomain(target.hostname)).catch((): Finding[] => [errorFinding('dns', String(target.hostname))]),
    // DNS-only, bounded, cheap enough to run on every scan. The resulting
    // list is never returned to an unauthenticated caller though — see
    // api/scan (teaser only gets the count) and api/report (full report
    // still only gets the count; the list itself needs a consult/paywall
    // gate — api/consult).
    scanForCloneDomains(target.hostname).catch((): CloneCandidate[] => []),
  ]);

  const findings = [
    ...headerFindings,
    ...tlsFindings,
    ...dnsFindings,
    ...takeoverFindings,
    ...exposureFindings,
    ...webAppFindings,
    ...reconFindings,
    ...cicdFindings,
    ...cloudStorageFindings,
    ...ctLogFindings,
  ];
  const { score, grade } = scoreFindings(findings);

  return {
    targetUrl: target.originalUrl,
    hostname: target.hostname,
    targetType: input.targetType ?? 'web',
    score,
    grade,
    findings,
    scannedAt: new Date().toISOString(),
    niche: input.niche ?? null,
    endpointType: input.endpointType ?? null,
    cloneCandidates,
  };
}

function errorFinding(category: Finding['category'], hostname: string): Finding {
  return {
    id: `${category}-error`,
    category,
    title: `${category} check failed`,
    severity: 'info',
    detail: `Could not complete this check for ${hostname}`,
    recommendation: 'Re-run the scan; if this persists the target may be blocking automated requests.',
    passed: true, // don't penalize the score for our own check failing
  };
}

/**
 * DNS checks (SPF/DMARC/MX) belong on the registrable/apex domain, not a
 * subdomain like app.example.com — mail records live at example.com even
 * when the scanned app is on a subdomain. See lib/domain.ts for the
 * public-suffix-aware resolution (handles co.uk, com.au, github.io, etc.
 * correctly, unlike a naive last-two-labels split).
 */
