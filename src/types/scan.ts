export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';

export interface Finding {
  id: string;
  category: 'headers' | 'tls' | 'dns' | 'exposure' | 'webapp' | 'recon' | 'cicd';
  title: string;
  severity: Severity;
  detail: string;
  recommendation: string;
  passed: boolean;
}

export interface ScanResult {
  targetUrl: string;
  hostname: string;
  targetType: 'web' | 'api';
  score: number;
  grade: string;
  findings: Finding[];
  scannedAt: string;
  niche?: string | null;
  // Only meaningful when targetType === 'api' — which kind of endpoint this
  // is (billing, admin, profile, webhook, ...). Tailors report copy and adds
  // a handful of endpoint-specific paths to the access-surface recon check.
  // See lib/scanner/endpointNiche.ts.
  endpointType?: string | null;
  cloneCandidates: CloneCandidate[];
}

export interface TeaserResult {
  hostname: string;
  score: number;
  grade: string;
  headline: string;
  topIssueCount: number;
  criticalCount: number;
  scanId: string;
  cloneCandidateCount: number;
}

export interface CloneCandidate {
  domain: string;
  permutationType: string;
  resolvedIps: string[];
  registrationStatus: 'active' | 'registered_dormant';
}

export interface ContentSimilarityMatch {
  url: string;
  title: string;
  snippet: string;
}

export interface BenchmarkResult {
  niche: string;
  avgScore: number;
  avgGrade: string;
  sampleSize: number;
}
