import { getRegistrableDomain } from '@/lib/domain';
import type { Finding } from '@/types/scan';

/**
 * Derives likely bucket names from the target's domain and checks whether
 * an S3 or GCS bucket by that name exists and, if so, whether it's
 * publicly listable — one of the most common real-world breach vectors,
 * and a very concrete finding to hand someone ("your backups bucket is
 * publicly listable") compared to a missing header.
 *
 * Deliberately NOT routed through pinnedFetch/resolveSafeTarget: those
 * exist to stop the SCANNED TARGET from redirecting this scanner at
 * internal/private infrastructure via malicious DNS or redirects. That
 * threat model doesn't apply here — the destination host is always a
 * fixed, well-known public cloud-storage domain (s3.amazonaws.com,
 * storage.googleapis.com) that this code chose, not something derived
 * from an untrusted redirect or DNS response. Only the bucket-name label
 * is templated from the target's hostname, and it's sanitized to the
 * S3/GCS bucket-naming charset before use, so there's no path for the
 * scanned site to redirect these requests anywhere.
 *
 * Azure Blob Storage is intentionally not covered — its two-level
 * account+container naming means checking it means guessing both
 * independently, which multiplies request count fast for a much lower
 * hit rate than S3/GCS's single-label bucket names.
 */

const TIMEOUT_MS = 4000;
const USER_AGENT = 'AegisScanner/1.0 (+security-scan)';

const SUFFIXES = [
  '',
  '-assets',
  '-static',
  '-media',
  '-uploads',
  '-backup',
  '-backups',
  '-files',
  '-data',
  '-prod',
  '-production',
  '-staging',
  '-dev',
  '-public',
  '-images',
  '-cdn',
  '-storage',
  '-com',
];

function sanitizeBucketLabel(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 63);
}

function candidateBucketNames(hostname: string): string[] {
  const registrable = getRegistrableDomain(hostname);
  const base = sanitizeBucketLabel(registrable.split('.')[0] ?? registrable);
  if (!base || base.length < 3) return [];

  const names = new Set<string>();
  for (const suffix of SUFFIXES) {
    const candidate = sanitizeBucketLabel(`${base}${suffix}`);
    if (candidate.length >= 3 && candidate.length <= 63) names.add(candidate);
  }
  names.add(sanitizeBucketLabel(`www-${base}`));
  return [...names];
}

interface BucketProbeOutcome {
  bucket: string;
  provider: 'S3' | 'GCS';
  state: 'listable' | 'exists-private' | 'absent' | 'error';
}

async function probeBucket(url: string, provider: 'S3' | 'GCS', bucket: string): Promise<BucketProbeOutcome> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: 'manual',
      headers: { 'User-Agent': USER_AGENT },
    });
    if (res.status === 200) return { bucket, provider, state: 'listable' };

    const body = await res.text().catch(() => '');
    if (res.status === 403 || /AccessDenied/i.test(body)) return { bucket, provider, state: 'exists-private' };
    if (res.status === 404 || /NoSuchBucket/i.test(body)) return { bucket, provider, state: 'absent' };
    return { bucket, provider, state: 'error' };
  } catch {
    return { bucket, provider, state: 'error' };
  }
}

export async function checkCloudStorageExposure(hostname: string): Promise<Finding[]> {
  const candidates = candidateBucketNames(hostname);
  if (candidates.length === 0) {
    return [
      {
        id: 'cloud-storage-buckets',
        category: 'exposure',
        title: 'Cloud storage bucket exposure',
        severity: 'info',
        detail: 'Could not derive candidate bucket names from this hostname.',
        recommendation: 'Not applicable.',
        passed: true,
      },
    ];
  }

  const probes = candidates.flatMap((bucket) => [
    probeBucket(`https://${bucket}.s3.amazonaws.com/`, 'S3', bucket),
    probeBucket(`https://storage.googleapis.com/${bucket}/`, 'GCS', bucket),
  ]);

  const results = await Promise.all(probes);
  const listable = results.filter((r) => r.state === 'listable');
  const privateButExists = results.filter((r) => r.state === 'exists-private');

  if (listable.length > 0) {
    return [
      {
        id: 'cloud-storage-buckets',
        category: 'exposure',
        title: 'Publicly listable cloud storage bucket found',
        severity: 'critical',
        detail: `${listable.length} bucket(s) matching this domain are publicly listable: ${listable.map((b) => `${b.bucket} (${b.provider})`).join(', ')}. Anyone can enumerate every object inside without credentials.`,
        recommendation:
          "Disable public listing immediately (S3: block public access at the bucket/account level; GCS: remove allUsers/allAuthenticatedUsers from IAM). Audit what was actually stored in it and treat anything sensitive as exposed.",
        passed: false,
      },
    ];
  }

  if (privateButExists.length > 0) {
    return [
      {
        id: 'cloud-storage-buckets',
        category: 'exposure',
        title: 'Cloud storage bucket(s) found (not publicly listable)',
        severity: 'info',
        detail: `${privateButExists.length} bucket(s) matching this domain exist but denied listing: ${privateButExists.map((b) => `${b.bucket} (${b.provider})`).join(', ')}. This only confirms the bucket exists — individual objects inside could still be public even though listing is denied.`,
        recommendation: "Worth a manual spot-check of a few known object keys/paths for public read access, since a private listing doesn't guarantee private objects.",
        passed: true,
      },
    ];
  }

  return [
    {
      id: 'cloud-storage-buckets',
      category: 'exposure',
      title: 'Cloud storage bucket exposure',
      severity: 'pass',
      detail: `Checked ${candidates.length} likely bucket name(s) against S3 and GCS — none found.`,
      recommendation: 'No action needed. Note this only checks common naming patterns, not an exhaustive search.',
      passed: true,
    },
  ];
}
