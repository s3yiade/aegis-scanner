import type { Finding } from '@/types/scan';

const PENALTY: Record<Finding['severity'], number> = {
  critical: 25,
  high: 14,
  medium: 7,
  low: 3,
  info: 0,
  pass: 0,
};

export function scoreFindings(findings: Finding[]): { score: number; grade: string } {
  let score = 100;
  for (const f of findings) {
    if (!f.passed) score -= PENALTY[f.severity];
  }
  score = Math.max(0, Math.min(100, score));

  const grade =
    score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';

  return { score, grade };
}
