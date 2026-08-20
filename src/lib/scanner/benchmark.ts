import { getSupabaseAdmin } from '@/lib/supabase';
import type { BenchmarkResult } from '@/types/scan';

/**
 * Reads pre-aggregated niche_benchmarks rather than computing an average
 * over the full scans table on every report view. Refresh this table on a
 * schedule (e.g. a daily cron hitting refreshNicheBenchmark for each niche
 * that has meaningful sample size) rather than live-aggregating per request.
 */
export async function getBenchmark(niche: string): Promise<BenchmarkResult | null> {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from('niche_benchmarks')
    .select('*')
    .eq('niche', niche)
    .maybeSingle();

  if (error || !data || data.sample_size < 5) {
    // Don't show a benchmark built from fewer than 5 unique domains — too
    // noisy to be credible, and a small sample is easy to reverse-engineer
    // toward a specific competitor's score. (sample_size is deduped by
    // hostname in refreshNicheBenchmark — a floor of 5 only means anything
    // if it can't be cleared by rescanning one domain five times.)
    return null;
  }

  return {
    niche: data.niche,
    avgScore: Number(data.avg_score),
    avgGrade: data.avg_grade,
    sampleSize: data.sample_size,
  };
}

function scoreToGrade(score: number): string {
  return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
}

/** Called from a scheduled job (see api/cron/rescan) to keep aggregates fresh. */
export async function refreshNicheBenchmark(niche: string): Promise<void> {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from('scans')
    .select('hostname, score, scanned_at')
    .eq('niche', niche)
    .gte('scanned_at', new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString()) // rolling 90-day window
    .order('scanned_at', { ascending: false });

  if (error || !data || data.length === 0) return;

  // Dedupe by hostname, keeping each domain's most recent score in the
  // window. Without this, a single domain rescanned repeatedly (a
  // recurring clone-watch check-in, a repeat visitor, someone re-testing
  // their own site after a fix) is counted once per scan rather than once
  // per business — skewing the average toward whichever domain happens to
  // get scanned most often, and quietly defeating the 5-sample floor in
  // getBenchmark() below: 5 scans of ONE domain would clear that floor
  // while the "benchmark" is really just that one business's score, not
  // an aggregate of five.
  const latestScoreByHostname = new Map<string, number>();
  for (const row of data) {
    if (!latestScoreByHostname.has(row.hostname)) {
      latestScoreByHostname.set(row.hostname, row.score);
    }
  }

  const scores = Array.from(latestScoreByHostname.values());
  const avgScore = scores.reduce((sum, s) => sum + s, 0) / scores.length;

  await supabase.from('niche_benchmarks').upsert({
    niche,
    avg_score: avgScore,
    avg_grade: scoreToGrade(avgScore),
    sample_size: scores.length, // unique domains, not raw scan count
    updated_at: new Date().toISOString(),
  });
}
