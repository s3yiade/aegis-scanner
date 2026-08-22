import type { Finding } from '@/types/scan';

/**
 * Compares two scans' findings for the paid continuous-monitoring diff
 * report (see api/cron/rescan and the monitor_diffs table) — the thing
 * that separates the Pro tier from the free "your score changed" email:
 * exactly which checks started failing, which got fixed, and which got
 * worse/better without necessarily flipping pass/fail.
 *
 * Findings are matched across scans by `${category}:${id}` rather than a
 * database identity (findings aren't persisted as their own rows) — every
 * check in this scanner uses a stable id for a given check (see
 * lib/scanner/*.ts), so the same check on two different scans of the same
 * target produces the same key. If a check ever returns more than one
 * finding under the same id in a single scan (a few multi-path checks
 * return one finding per matched path today they don't, but defensively),
 * the last one wins — good enough for a diff, not worth a more complex
 * multi-match model.
 */

export interface FindingDiff {
  scoreDelta: number;
  added: Finding[]; // now failing, previously passing or absent
  resolved: Finding[]; // now passing, previously failing
  changed: { key: string; title: string; from: Finding['severity']; to: Finding['severity'] }[]; // failing both times, severity moved
}

export function diffFindings(previous: Finding[] | null, next: Finding[], previousScore: number | null, nextScore: number): FindingDiff {
  const prevMap = toMap(previous ?? []);
  const nextMap = toMap(next);

  const added: Finding[] = [];
  const resolved: Finding[] = [];
  const changed: FindingDiff['changed'] = [];

  for (const [key, nextFinding] of nextMap) {
    const prevFinding = prevMap.get(key);

    if (!nextFinding.passed) {
      if (!prevFinding || prevFinding.passed) {
        added.push(nextFinding);
      } else if (prevFinding.severity !== nextFinding.severity) {
        changed.push({ key, title: nextFinding.title, from: prevFinding.severity, to: nextFinding.severity });
      }
    } else if (prevFinding && !prevFinding.passed) {
      resolved.push(nextFinding);
    }
  }

  return {
    scoreDelta: previousScore === null ? 0 : nextScore - previousScore,
    added,
    resolved,
    changed,
  };
}

/** True if there's anything a paying subscriber would actually want an
 * email about — used to decide whether to send a diff alert at all (no
 * point emailing "nothing changed" on every re-scan). */
export function diffHasNotableChange(diff: FindingDiff): boolean {
  return diff.added.length > 0 || diff.resolved.length > 0 || diff.changed.length > 0 || diff.scoreDelta !== 0;
}

function toMap(findings: Finding[]): Map<string, Finding> {
  const map = new Map<string, Finding>();
  for (const f of findings) {
    map.set(`${f.category}:${f.id}`, f);
  }
  return map;
}
