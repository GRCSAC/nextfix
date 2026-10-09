import type { Decision, Finding, ScanReport } from '../../engine/src/types.ts';

export interface ScanDiff {
  added: Finding[];
  resolved: Finding[];
  changed: { finding: Finding; from: Decision; to: Decision }[];
}

/** What changed between two reports, keyed by component purl + advisory id. */
export function diffReports(current: ScanReport, previous: ScanReport | undefined): ScanDiff {
  if (!previous) return { added: [], resolved: [], changed: [] };
  const prev = new Map(previous.findings.map((f) => [f.id, f]));
  const cur = new Map(current.findings.map((f) => [f.id, f]));
  const added = current.findings.filter((f) => !prev.has(f.id));
  const resolved = previous.findings.filter((f) => !cur.has(f.id));
  const changed: ScanDiff['changed'] = [];
  for (const f of current.findings) {
    const p = prev.get(f.id);
    if (p && p.decision !== f.decision) changed.push({ finding: f, from: p.decision, to: f.decision });
  }
  return { added, resolved, changed };
}
