import type { Finding, ScanReport } from '../types.ts';

const TIER_LABEL: Record<Finding['reach']['tier'], string> = {
  reachable: 'reachable',
  'called-unreached': 'called, unreached',
  'imported-unknown-symbol': 'imported (no fn data)',
  'imported-not-called': 'imported, not called',
  unused: 'not imported',
  'dev-only': 'dev only',
};

export function renderSummary(r: ScanReport): string {
  const s = r.summary;
  const lines = [
    `NextFix ${r.tool.version} — ${r.target.name ?? r.target.dir}${r.target.version ? ' ' + r.target.version : ''}`,
    `${s.components} components, ${s.advisories} advisories → ${s.findings} findings`,
    `Act ${s.byDecision.Act} · Attend ${s.byDecision.Attend} · Track* ${s.byDecision['Track*']} · Track ${s.byDecision.Track}`,
    `${Math.round(s.noiseRemoved * 100)}% of findings need no action right now, with evidence.`,
    `Entry points: ${r.entryPoints.length} (${r.entryPoints.filter((e) => !e.authenticated).length} unauthenticated) · network: ${r.exposure.network}${r.exposure.ports.length ? ' on ' + r.exposure.ports.join(',') : ''}`,
  ];
  return lines.join('\n');
}

export function renderTable(r: ScanReport): string {
  const rows = r.findings.map((f) => {
    const entry = f.reach.paths[0] ? `${f.reach.paths[0].entry.method} ${f.reach.paths[0].entry.path}${f.reach.paths[0].entry.authenticated ? ' (auth)' : ''}` : '';
    return [f.decision, String(f.score), `${f.component.name}@${f.component.version}`, f.advisory.cve ?? f.advisory.id, TIER_LABEL[f.reach.tier], entry, f.advisory.fixedVersion ? `→ ${f.advisory.fixedVersion}` : 'no fix'];
  });
  const head = ['DECISION', 'SCORE', 'PACKAGE', 'ADVISORY', 'REACH', 'ENTRY', 'FIX'];
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((row) => row[i]!.length)));
  const fmt = (row: string[]) => row.map((c, i) => c.padEnd(widths[i]!)).join('  ');
  return [fmt(head), widths.map((w) => '-'.repeat(w)).join('  '), ...rows.map(fmt)].join('\n');
}

export function renderWhy(r: ScanReport, max = 3): string {
  const out: string[] = [];
  for (const f of r.findings.filter((x) => x.decision === 'Act' || x.decision === 'Attend').slice(0, max)) {
    out.push(`\n${f.decision} · ${f.component.name}@${f.component.version} · ${f.advisory.cve ?? f.advisory.id}`);
    for (const w of f.why) out.push(`  - ${w}`);
  }
  return out.join('\n');
}
