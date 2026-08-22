import crypto from 'node:crypto';
import type { Finding } from '@/types/scan';
import { pinnedFetch, type SafeTarget } from '@/lib/ssrfGuard';
import { SECRET_PATTERNS, findGenericSecretMatch } from './webapp';

const TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 300_000;
const USER_AGENT = 'AegisScanner/1.0 (+security-scan)';

/**
 * A build/deploy pipeline config accidentally left reachable at the web
 * root reveals internal tooling, deploy targets, and package/service names
 * — and, in the worst (and not rare) case, an actual credential someone
 * pasted directly into the config instead of referencing it via the CI
 * platform's secret store. Same passive-only, no-exploitation rules as
 * everything else in this scanner: a plain GET, content-shape verification
 * against the same catch-all/soft-404 baseline pattern used in
 * exposedPaths.ts and webapp.ts, and (for anything genuinely exposed) a
 * pass through the exact same secret-pattern matcher used on client-side
 * JS — see webapp.ts's SECRET_PATTERNS, exported specifically for reuse
 * here rather than maintained as a second, drifting copy.
 *
 * Grouped by CI/CD *system* rather than one finding per candidate filename
 * (a system's config commonly lives under one of a few conventional names —
 * e.g. GitHub Actions workflows) so the report shows one row per system
 * instead of near-duplicate rows for filename variants.
 */
interface CicdSystem {
  id: string;
  title: string;
  paths: string[];
  severity: Finding['severity'];
  recommendation: string;
  looksLikeMatch: (body: string, contentType: string) => boolean;
}

const SYSTEMS: CicdSystem[] = [
  {
    id: 'github-actions',
    title: 'GitHub Actions workflow',
    paths: ['/.github/workflows/ci.yml', '/.github/workflows/deploy.yml', '/.github/workflows/main.yml', '/.github/workflows/release.yml', '/.github/workflows/build.yml'],
    severity: 'medium',
    recommendation: 'Workflow files belong in your repo, not the deployed web root. Confirm your build output/public directory doesn\'t include .github/ or any other VCS/CI metadata — most static-site and framework build configs exclude it by default, so this usually means a misconfigured output path or a manually-copied deploy.',
    looksLikeMatch: (body) => /^\s*on\s*:/m.test(body) && /^\s*jobs\s*:/m.test(body),
  },
  {
    id: 'circleci',
    title: 'CircleCI config',
    paths: ['/.circleci/config.yml'],
    severity: 'medium',
    recommendation: 'Remove .circleci/ from the deployed web root, or add a web-server rule blocking dotfile directories entirely.',
    looksLikeMatch: (body) => /^\s*version\s*:\s*2/m.test(body) && /^\s*jobs\s*:/m.test(body),
  },
  {
    id: 'jenkins',
    title: 'Jenkinsfile',
    paths: ['/Jenkinsfile'],
    severity: 'medium',
    recommendation: 'A Jenkinsfile at the web root reveals your build/deploy stages. Move it out of the public directory or block it at the web server level.',
    looksLikeMatch: (body) => /pipeline\s*\{/.test(body) || /\bstage\s*\(/.test(body) || /\bnode\s*\{/.test(body),
  },
  {
    id: 'gitlab-ci',
    title: 'GitLab CI config',
    paths: ['/.gitlab-ci.yml'],
    severity: 'medium',
    recommendation: 'Remove .gitlab-ci.yml from the deployed web root, or block dotfiles at the web server level.',
    looksLikeMatch: (body) => /^\s*stages\s*:/m.test(body) || (/^\s*script\s*:/m.test(body) && /^\s*image\s*:/m.test(body)),
  },
  {
    id: 'travis-ci',
    title: 'Travis CI config',
    paths: ['/.travis.yml'],
    severity: 'medium',
    recommendation: 'Remove .travis.yml from the deployed web root, or block dotfiles at the web server level.',
    looksLikeMatch: (body) => /^\s*language\s*:/m.test(body) && /^\s*script\s*:/m.test(body),
  },
  {
    id: 'azure-pipelines',
    title: 'Azure Pipelines config',
    paths: ['/azure-pipelines.yml'],
    severity: 'medium',
    recommendation: 'Remove azure-pipelines.yml from the deployed web root.',
    looksLikeMatch: (body) => /^\s*trigger\s*:/m.test(body) && (/^\s*pool\s*:/m.test(body) || /^\s*steps\s*:/m.test(body)),
  },
  {
    id: 'bitbucket-pipelines',
    title: 'Bitbucket Pipelines config',
    paths: ['/bitbucket-pipelines.yml'],
    severity: 'medium',
    recommendation: 'Remove bitbucket-pipelines.yml from the deployed web root.',
    looksLikeMatch: (body) => /^\s*pipelines\s*:/m.test(body),
  },
  {
    id: 'docker-build-files',
    title: 'Dockerfile / docker-compose',
    paths: ['/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml'],
    severity: 'low',
    recommendation: 'A Dockerfile or compose file reveals base images, exposed ports, and internal service names/wiring. Exclude these from the deployed output — they belong in the repo/build context, not the served directory.',
    looksLikeMatch: (body) => /^\s*FROM\s+\S+/im.test(body) || (/^\s*services\s*:/m.test(body) && /^\s*image\s*:/m.test(body)),
  },
  {
    id: 'package-manager-auth',
    title: 'Package manager auth config (.npmrc / .yarnrc)',
    paths: ['/.npmrc', '/.yarnrc'],
    severity: 'high',
    recommendation: '.npmrc/.yarnrc files sometimes contain a private-registry auth token pasted directly rather than referenced via an environment variable. Remove from the web root immediately and rotate the token if one was present — see the secret-scan result on this same finding for whether one was actually found.',
    looksLikeMatch: (body) => /_authToken\s*=/i.test(body) || /^\s*registry\s*=/im.test(body) || /^\/\/.*\/:_authToken/im.test(body),
  },
  {
    id: 'terraform-state',
    title: 'Terraform state file',
    paths: ['/terraform.tfstate', '/.terraform/terraform.tfstate'],
    severity: 'critical',
    recommendation: 'Terraform state commonly contains resource attributes in plaintext — including, for many providers, database passwords and API keys generated during provisioning. Remove immediately and treat any credentials referenced in it as compromised; state belongs in a remote backend (S3+DynamoDB, Terraform Cloud, etc.) with access control, never the web root.',
    looksLikeMatch: (body) => {
      try {
        const parsed = JSON.parse(body);
        return Boolean(parsed && typeof parsed === 'object' && 'resources' in parsed && ('terraform_version' in parsed || 'version' in parsed));
      } catch {
        return false;
      }
    },
  },
  {
    id: 'aws-credentials-file',
    title: 'AWS credentials file',
    paths: ['/.aws/credentials'],
    severity: 'critical',
    recommendation: 'A reachable AWS credentials file is a full account-access incident, not a configuration nitpick. Remove it immediately and rotate/deactivate the exposed key(s) in IAM right away, then audit CloudTrail for any activity from them.',
    looksLikeMatch: (body) => /^\s*\[[\w-]+\]/m.test(body) && /aws_access_key_id\s*=/i.test(body),
  },
  {
    id: 'k8s-secrets-manifest',
    title: 'Kubernetes Secret manifest',
    paths: ['/k8s/secrets.yaml', '/kubernetes/secrets.yaml', '/secrets.yaml'],
    severity: 'critical',
    recommendation: 'A reachable Kubernetes Secret manifest exposes base64-encoded (not encrypted) credential data. Remove from the web root immediately and rotate every value it contained — base64 is trivially reversible, not a security control.',
    looksLikeMatch: (body) => /^\s*kind\s*:\s*Secret/m.test(body),
  },
];

interface ProbeResult {
  status: number;
  body: string;
  contentType: string;
}

async function probe(target: SafeTarget, path: string): Promise<ProbeResult | null> {
  const url = new URL(path, `${target.protocol}//${target.hostname}`).toString();
  try {
    const res = await pinnedFetch(target, url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: 'manual',
      headers: { 'User-Agent': USER_AGENT },
    });
    const body = (await res.text().catch(() => '')).slice(0, MAX_BODY_BYTES);
    return { status: res.status, body, contentType: res.headers.get('content-type') ?? '' };
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

/** Runs the same secret-value pattern matcher used on client-side JS
 * (webapp.ts) against a genuinely-exposed CI/CD file's content — a CI
 * config legitimately references secret *names* constantly (e.g. GitHub
 * Actions' `${{ secrets.AWS_SECRET_ACCESS_KEY }}` syntax), but these
 * patterns match specific credential *value* formats, not variable names,
 * so referencing a secret by name doesn't trigger a false positive here. */
function scanForLeakedSecret(content: string): string | null {
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.regex.test(content)) return pattern.name;
  }
  if (findGenericSecretMatch(content)) return 'Generic API key assignment';
  return null;
}

export async function checkCicdExposure(target: SafeTarget): Promise<Finding[]> {
  const baselinePath = `/__aegis_cicd_baseline_${crypto.randomBytes(8).toString('hex')}__`;
  const baseline = await probe(target, baselinePath);
  const baselineIsCatchAll = baseline !== null && baseline.status === 200;

  return Promise.all(SYSTEMS.map((system) => checkSystem(target, system, baseline, baselineIsCatchAll)));
}

async function checkSystem(
  target: SafeTarget,
  system: CicdSystem,
  baseline: ProbeResult | null,
  baselineIsCatchAll: boolean
): Promise<Finding> {
  const results = await Promise.all(system.paths.map((path) => probe(target, path).then((r) => ({ path, r }))));

  for (const { path, r } of results) {
    if (!r || r.status !== 200) continue;
    const matchesBaseline = baselineIsCatchAll && bodiesLookTheSame(r.body, baseline!.body);
    if (matchesBaseline) continue;
    if (!system.looksLikeMatch(r.body, r.contentType)) continue;

    // Genuinely exposed — check whether it also contains a real credential.
    const leakedSecret = scanForLeakedSecret(r.body);

    return {
      id: `cicd:${system.id}`,
      category: 'cicd',
      title: leakedSecret ? `${system.title} exposed — contains a likely credential` : `${system.title} publicly exposed`,
      severity: leakedSecret ? 'critical' : system.severity,
      detail: leakedSecret
        ? `Reachable at ${path}, and its content matched a known credential pattern (${leakedSecret}). Never include the matched value itself in a report — treat it as compromised and rotate it immediately.`
        : `Reachable at ${path} with content matching what's expected for this file type.`,
      recommendation: leakedSecret
        ? `Rotate the exposed credential immediately, THEN remove the file from the web root (${system.recommendation})`
        : system.recommendation,
      passed: false,
    };
  }

  return {
    id: `cicd:${system.id}`,
    category: 'cicd',
    title: system.title,
    severity: 'pass',
    detail: `Not publicly reachable (checked ${system.paths.length} common path${system.paths.length > 1 ? 's' : ''}).`,
    recommendation: 'No action needed.',
    passed: true,
  };
}
