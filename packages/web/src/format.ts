import type { Decision, Finding, ReachTier, ScanReport } from './api.ts';

/** Logical order (most urgent first). */
export const DECISIONS: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];
/** Visual order for bars and rings: validated so adjacent hues stay distinct. */
export const BUCKET_ORDER: Decision[] = ['Act', 'Attend', 'Track', 'Track*'];

export const DECISION_META: Record<Decision, { label: string; short: string; icon: string; cls: string; color: string; help: string }> = {
  Act: { label: 'Act', short: 'Fix now', icon: '▲', cls: 'act', color: 'var(--c-act)', help: 'Critical issues that should be remediated immediately.' },
  Attend: { label: 'Attend', short: 'Fix next cycle', icon: '●', cls: 'attend', color: 'var(--c-attend)', help: 'Important issues to address in the next release cycle.' },
  'Track*': { label: 'Track*', short: 'Watch', icon: '◐', cls: 'watch', color: 'var(--c-watch)', help: 'Monitor and re-check when exploit data or the code changes.' },
  Track: { label: 'Track', short: 'Set aside with evidence', icon: '○', cls: 'aside', color: 'var(--c-aside)', help: 'Not reachable, unused or not shipped, with audit-defensible evidence.' },
};

export const TIER_LABEL: Record<ReachTier, string> = {
  reachable: 'Reachable from an entry point',
  'called-unreached': 'Called, but no entry point reaches it',
  'imported-unknown-symbol': 'Imported; no function-level data yet',
  'imported-not-called': 'Imported, vulnerable function never called',
  unused: 'Installed but never imported',
  'dev-only': 'Dev dependency, not shipped',
};

export const TIER_SHORT: Record<ReachTier, string> = {
  reachable: 'Reachable',
  'called-unreached': 'Called, unreached',
  'imported-unknown-symbol': 'Imported, no fn data',
  'imported-not-called': 'Imported, not called',
  unused: 'Not imported',
  'dev-only': 'Dev only',
};

export const TIERS: ReachTier[] = ['reachable', 'called-unreached', 'imported-unknown-symbol', 'imported-not-called', 'unused', 'dev-only'];

/** Evidence categories: the set-aside tiers and the audit-facing wording for each. */
export const EVIDENCE_TIERS: { tier: ReachTier; label: string; justification: string }[] = [
  { tier: 'dev-only', label: 'Development dependency (not shipped)', justification: 'component_not_present' },
  { tier: 'unused', label: 'Installed but never imported', justification: 'vulnerable_code_not_in_execute_path' },
  { tier: 'imported-not-called', label: 'Vulnerable function never called', justification: 'vulnerable_code_not_in_execute_path' },
  { tier: 'called-unreached', label: 'Called, but unreachable from any entry point', justification: 'under_investigation' },
];

export function pct(n: number): string {
  return `${Math.round(n * 100)}%`;
}

export function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function dateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
}

export function advisoryName(f: Finding): string {
  return f.advisory.cve ?? f.advisory.id;
}

export function bestPath(f: Finding) {
  return f.reach.paths.find((x) => !x.entry.authenticated && x.userInput) ?? f.reach.paths.find((x) => !x.entry.authenticated) ?? f.reach.paths.find((x) => x.userInput) ?? f.reach.paths[0];
}

export function entryLabel(f: Finding): string | undefined {
  const p = bestPath(f);
  return p ? `${p.entry.method} ${p.entry.path}` : undefined;
}

/** One line an executive can read: what, where, and why it is ranked there. */
export function headline(f: Finding): string {
  const p = bestPath(f);
  if (p) {
    const bits = [`${p.entry.method} ${p.entry.path}`, p.entry.authenticated ? 'behind auth' : 'no auth', p.userInput ? 'request data reaches it' : undefined];
    return `${f.component.name}.${p.callSite.symbol} via ${bits.filter(Boolean).join(', ')}`;
  }
  return TIER_LABEL[f.reach.tier];
}

export function recommendation(f: Finding): string {
  if (f.advisory.fixedVersion) return `Upgrade ${f.component.name} to ${f.advisory.fixedVersion}`;
  const p = bestPath(f);
  if (p && !p.entry.authenticated) return `No fix published; add an auth guard to ${p.entry.method} ${p.entry.path}`;
  return 'No fix published; mitigate at the entry point';
}

export function severity(f: Finding): { label: string; cls: string } {
  const s = f.advisory.cvssScore;
  const label = f.advisory.severityLabel ?? (s === undefined ? 'Unknown' : s >= 9 ? 'CRITICAL' : s >= 7 ? 'HIGH' : s >= 4 ? 'MEDIUM' : 'LOW');
  const norm = label.toUpperCase() === 'MODERATE' ? 'MEDIUM' : label.toUpperCase();
  const pretty = norm.charAt(0) + norm.slice(1).toLowerCase();
  return { label: pretty, cls: norm === 'CRITICAL' ? 'sev-critical' : norm === 'HIGH' ? 'sev-high' : norm === 'MEDIUM' ? 'sev-medium' : 'sev-low' };
}

export function fixCommand(f: Finding): string | undefined {
  if (!f.advisory.fixedVersion) return undefined;
  if (f.component.ecosystem === 'PyPI') return `pip install "${f.component.name}==${f.advisory.fixedVersion}"`;
  return `npm install ${f.component.name}@${f.advisory.fixedVersion}`;
}

export type ComponentState = ReachTier | 'clean';
export const STATE_LABEL: Record<ComponentState, string> = { ...TIER_SHORT, clean: 'No advisories' };
export const STATE_ORDER: ComponentState[] = [...TIERS, 'clean'];

/** Worst reachability tier per component, plus components with no advisories at all. */
export function componentStates(report: ScanReport): Record<ComponentState, number> {
  const worst = new Map<string, ReachTier>();
  for (const f of report.findings) {
    const cur = worst.get(f.component.purl);
    if (!cur || TIERS.indexOf(f.reach.tier) < TIERS.indexOf(cur)) worst.set(f.component.purl, f.reach.tier);
  }
  const out = Object.fromEntries(STATE_ORDER.map((s) => [s, 0])) as Record<ComponentState, number>;
  for (const t of worst.values()) out[t]++;
  out.clean = Math.max(0, report.summary.components - worst.size);
  return out;
}

export function componentWorstTier(report: ScanReport, purl: string): ComponentState {
  let best: ReachTier | undefined;
  for (const f of report.findings) {
    if (f.component.purl !== purl) continue;
    if (!best || TIERS.indexOf(f.reach.tier) < TIERS.indexOf(best)) best = f.reach.tier;
  }
  return best ?? 'clean';
}

export function ticketMarkdown(f: Finding, targetName: string): string {
  const title = `[${f.decision}] ${f.component.name}@${f.component.version}: ${advisoryName(f)} — ${f.advisory.summary}`;
  const lines = [
    `# ${title}`,
    '',
    `**Target:** ${targetName}  `,
    `**Decision:** ${f.decision} (${DECISION_META[f.decision].short})  `,
    `**Score:** ${f.score}/100  `,
    `**Reachability:** ${TIER_LABEL[f.reach.tier]} (confidence: ${f.reach.confidence})  `,
    '',
    '## Why',
    ...f.why.map((w) => `- ${w}`),
    '',
  ];
  const p = bestPath(f);
  if (p) {
    lines.push('## Path', '```', `${p.entry.method} ${p.entry.path}${p.entry.authenticated ? ' [auth: ' + p.entry.guards.join(', ') + ']' : ' [no auth]'}`);
    for (const h of p.hops) lines.push(`  → ${h.name}  (${h.file}:${h.line})`);
    lines.push(`  → ${p.callSite.text}()  (${p.callSite.file}:${p.callSite.line})`, '```');
    if (p.userInput && p.taintedArgument) lines.push(`Request data \`${p.inputSource ?? ''}\` arrives as argument ${p.taintedArgument.index + 1} (\`${p.taintedArgument.text}\`).`);
    lines.push('');
  }
  lines.push('## Fix');
  const cmd = fixCommand(f);
  if (cmd) lines.push(`${f.fix}`, '', '```bash', cmd, '```', '');
  else lines.push('No fixed version is published yet. Mitigate at the entry point.', '');
  if (f.advisory.references.length) lines.push('## References', ...f.advisory.references.slice(0, 6).map((r) => `- ${r}`), '');
  lines.push('_Generated by NextFix._');
  return lines.join('\n');
}
