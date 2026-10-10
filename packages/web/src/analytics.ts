import type { Decision, EntryPoint, Finding, ReachTier, ScanDiff, ScanReport } from './api.ts';
import { DECISIONS, DECISION_META, bestPath, pct } from './format.ts';
import { compareVersions } from '../../engine/src/vulns/ecosystems.ts';

/* Derived views of one report: everything the Overview draws comes from these pure functions. */

const order = (d: Decision) => DECISIONS.indexOf(d);
export const worstOf = (fs: Finding[]): Decision | undefined => fs.reduce<Decision | undefined>((w, f) => (w === undefined || order(f.decision) < order(w) ? f.decision : w), undefined);

const likely = (f: Finding) => !!f.kev || (f.epss?.score ?? 0) >= 0.1;
const openPath = (f: Finding) => f.reach.paths.some((p) => !p.entry.authenticated);
const openInput = (f: Finding) => f.reach.paths.some((p) => !p.entry.authenticated && p.userInput);

// ---------------------------------------------------------------------------------------------
// Posture verdict

export type Posture = 'Exposed' | 'Attention' | 'Contained' | 'Clean';

export interface Verdict {
  posture: Posture;
  decision?: Decision;
  headline: string;
  detail?: string;
  rule: string;
  /** The finding the headline is about, when there is one. */
  findingId?: string;
}

export function verdict(report: ScanReport): Verdict {
  const s = report.summary.byDecision;
  const rule = 'Exposed when anything is Fix now · Attention when anything is Fix next cycle · Contained when only Watch remains · Clean when nothing is open.';
  if (s.Act > 0) {
    const act = report.findings.filter((f) => f.decision === 'Act');
    const f = act[0]!;
    const p = bestPath(f);
    const one = act.length === 1;
    const bits = [
      `${one ? 'One vulnerability is' : `${act.length} vulnerabilities are`} reachable ${p ? (p.entry.authenticated ? 'behind a login' : 'without a login') : 'from the code'}`,
      p?.userInput ? (one ? 'carries request data' : 'carry request data') : undefined,
      f.kev ? `and ${one ? 'is' : 'the worst is'} on CISA's known-exploited list` : (f.epss?.score ?? 0) >= 0.1 ? `and ${one ? 'has' : 'the worst has'} a ${pct(f.epss!.score)} chance of exploitation within 30 days` : undefined,
    ].filter(Boolean);
    return {
      posture: 'Exposed',
      decision: 'Act',
      headline: `${bits.join(', ')}.`,
      detail: `${f.component.name} ${f.component.version} · ${f.advisory.cve ?? f.advisory.id}${p ? ` · ${p.entry.method} ${p.entry.path}` : ''}${f.advisory.fixedVersion ? ` · fix: upgrade to ${f.advisory.fixedVersion}` : ' · no fix published yet'}`,
      rule,
      findingId: f.id,
    };
  }
  if (s.Attend > 0) {
    const open = report.findings.filter((f) => f.decision === 'Attend' && openPath(f)).length;
    return {
      posture: 'Attention',
      decision: 'Attend',
      headline: `${s.Attend} finding${s.Attend === 1 ? '' : 's'} need${s.Attend === 1 ? 's' : ''} fixing in the next release cycle; nothing is both reachable without a login and known to be exploited.`,
      detail: open ? `${open} of them ${open === 1 ? 'is' : 'are'} reachable without a login.` : 'None is reachable without a login.',
      rule,
    };
  }
  if (s['Track*'] > 0) {
    return { posture: 'Contained', decision: 'Track*', headline: `${s['Track*']} finding${s['Track*'] === 1 ? ' is' : 's are'} being watched; nothing needs a fix this cycle.`, detail: 'Watched items are re-checked when exploit data or the code changes.', rule };
  }
  return { posture: 'Clean', headline: report.findings.length ? `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}, all set aside with evidence; nothing needs action.` : 'No findings. Keep scanning after each release.', rule };
}

// ---------------------------------------------------------------------------------------------
// Evidence funnel

export interface FunnelRow {
  key: string;
  label: string;
  count: number;
  color: string;
  /** What this step removed and why; `tier` filters the findings page to it. */
  removed?: { count: number; note: string; tier?: ReachTier; decision?: Decision };
}

export function funnel(report: ScanReport): FunnelRow[] {
  const all = report.findings;
  const tier = (t: ReachTier) => all.filter((f) => f.reach.tier === t);
  const shipped = all.filter((f) => f.reach.tier !== 'dev-only');
  const own = shipped.filter((f) => f.reach.tier !== 'image-only');
  const imported = own.filter((f) => f.reach.tier !== 'unused');
  const unknown = tier('imported-unknown-symbol');
  const called = imported.filter((f) => f.reach.tier !== 'imported-not-called');
  const reachable = tier('reachable');
  const open = reachable.filter(openPath);
  const input = open.filter(openInput);
  const exploited = input.filter(likely);
  const n = (k: number, one: string, many = `${one}s`) => `${k} ${k === 1 ? one : many}`;
  return [
    { key: 'found', label: 'Advisories found', count: all.length, color: 'var(--muted)' },
    { key: 'shipped', label: 'In shipped code', count: shipped.length, color: 'var(--muted)', removed: { count: all.length - shipped.length, note: `${n(all.length - shipped.length, 'development-only dependency', 'development-only dependencies')}`, tier: 'dev-only' } },
    { key: 'own', label: "In the application's own dependencies", count: own.length, color: 'var(--c-aside)', removed: { count: shipped.length - own.length, note: `${shipped.length - own.length} only in the container image (base OS, tooling)`, tier: 'image-only' } },
    { key: 'imported', label: 'Imported by application code', count: imported.length, color: 'var(--c-aside)', removed: { count: own.length - imported.length, note: `${own.length - imported.length} installed but never imported`, tier: 'unused' } },
    { key: 'called', label: 'Vulnerable function called', count: called.length, color: 'var(--c-watch)', removed: { count: imported.length - called.length, note: `${imported.length - called.length} never call the vulnerable function`, tier: 'imported-not-called' } },
    { key: 'reachable', label: 'Reachable from an entry point', count: reachable.length, color: 'var(--c-attend)', removed: { count: called.length - reachable.length, note: [tier('called-unreached').length ? `${tier('called-unreached').length} called only from code no route reaches` : '', unknown.length ? `${unknown.length} with no function data yet, watched` : ''].filter(Boolean).join(' · '), tier: unknown.length && !tier('called-unreached').length ? 'imported-unknown-symbol' : 'called-unreached' } },
    { key: 'open', label: 'Reachable without a login', count: open.length, color: 'var(--c-attend)', removed: { count: reachable.length - open.length, note: `${reachable.length - open.length} behind a login`, tier: 'reachable' } },
    { key: 'input', label: 'Request data reaches the call', count: input.length, color: 'var(--c-attend)', removed: { count: open.length - input.length, note: `${open.length - input.length} with the application's own inputs only`, tier: 'reachable' } },
    { key: 'exploited', label: 'Known or likely exploited', count: exploited.length, color: 'var(--c-act)', removed: { count: input.length - exploited.length, note: `${input.length - exploited.length} with no exploitation evidence yet`, tier: 'reachable' } },
  ];
}

/** Ratios the funnel gives for free, as sentences with the numbers in them. */
export function ratios(report: ScanReport): { label: string; value: string; note: string }[] {
  const all = report.findings.length;
  const actionable = report.summary.byDecision.Act + report.summary.byDecision.Attend;
  const image = report.findings.filter((f) => f.reach.tier === 'image-only').length;
  const openRoutes = report.entryPoints.filter((e) => !e.authenticated);
  const exposedRoutes = openRoutes.filter((e) => report.findings.some((f) => f.reach.paths.some((p) => sameEntry(p.entry, e))));
  return [
    { label: 'Need no action', value: all ? pct((all - actionable) / all) : '—', note: `${all - actionable} of ${all} findings set aside or watched, each with a reason` },
    { label: 'Exposed surface', value: `${exposedRoutes.length} of ${openRoutes.length}`, note: 'open routes that reach a vulnerable call' },
    { label: 'From the image', value: all ? pct(image / all) : '—', note: `${image} findings come from the base image and its tooling` },
  ];
}

// ---------------------------------------------------------------------------------------------
// Exposure matrix

export type MatrixRow = 'open' | 'auth' | 'called' | 'image' | 'aside';
export type MatrixCol = 'kev' | 'likely' | 'none';
export const MATRIX_ROWS: { key: MatrixRow; label: string; tier?: ReachTier }[] = [
  { key: 'open', label: 'Reachable, no login', tier: 'reachable' },
  { key: 'auth', label: 'Reachable, behind a login', tier: 'reachable' },
  { key: 'called', label: 'Called, or no function data', tier: 'called-unreached' },
  { key: 'image', label: 'Only in the container image', tier: 'image-only' },
  { key: 'aside', label: 'Not in the execute path', tier: 'unused' },
];
export const MATRIX_COLS: { key: MatrixCol; label: string }[] = [
  { key: 'kev', label: 'Exploited in the wild (KEV)' },
  { key: 'likely', label: 'Likely (EPSS ≥ 10%)' },
  { key: 'none', label: 'No evidence yet' },
];

export interface MatrixCell {
  row: MatrixRow;
  col: MatrixCol;
  findings: Finding[];
  worst?: Decision;
}

export function matrix(report: ScanReport): MatrixCell[] {
  const rowOf = (f: Finding): MatrixRow => {
    switch (f.reach.tier) {
      case 'reachable':
        return openPath(f) ? 'open' : 'auth';
      case 'called-unreached':
      case 'imported-unknown-symbol':
        return 'called';
      case 'image-only':
        return 'image';
      default:
        return 'aside';
    }
  };
  const colOf = (f: Finding): MatrixCol => (f.kev ? 'kev' : (f.epss?.score ?? 0) >= 0.1 ? 'likely' : 'none');
  const cells: MatrixCell[] = [];
  for (const r of MATRIX_ROWS) {
    for (const c of MATRIX_COLS) {
      const fs = report.findings.filter((f) => rowOf(f) === r.key && colOf(f) === c.key);
      cells.push({ row: r.key, col: c.key, findings: fs, worst: worstOf(fs) });
    }
  }
  return cells;
}

/** "6 next cycle, 16 watch" for a cell that mixes decisions. */
export function cellLabel(cell: MatrixCell): string {
  if (!cell.findings.length) return '0';
  const counts = DECISIONS.map((d) => [d, cell.findings.filter((f) => f.decision === d).length] as const).filter(([, n]) => n > 0);
  if (counts.length === 1) return `${cell.findings.length} · ${DECISION_META[counts[0]![0]].short}`;
  return `${cell.findings.length} · ${counts.map(([d, n]) => `${n} ${DECISION_META[d].short.toLowerCase()}`).join(', ')}`;
}

// ---------------------------------------------------------------------------------------------
// Fix leverage

export interface Upgrade {
  key: string;
  name: string;
  version: string;
  target: string;
  inImage: boolean;
  direct: boolean;
  closes: Finding[];
  byDecision: Record<Decision, number>;
  actionable: number;
}

export function upgrades(report: ScanReport): Upgrade[] {
  const groups = new Map<string, Upgrade>();
  for (const f of report.findings) {
    if (!f.advisory.fixedVersion) continue;
    const c = f.component;
    const key = `${c.purl}`;
    let g = groups.get(key);
    if (!g) {
      g = { key, name: c.name, version: c.version, target: f.advisory.fixedVersion, inImage: c.origin === 'image', direct: c.direct, closes: [], byDecision: { Act: 0, Attend: 0, 'Track*': 0, Track: 0 }, actionable: 0 };
      groups.set(key, g);
    }
    if (compareVersions(c.ecosystem, f.advisory.fixedVersion, g.target) > 0) g.target = f.advisory.fixedVersion;
    g.closes.push(f);
    g.byDecision[f.decision]++;
    if (f.decision === 'Act' || f.decision === 'Attend') g.actionable++;
  }
  return [...groups.values()].sort((a, b) => b.actionable - a.actionable || b.closes.length - a.closes.length || a.name.localeCompare(b.name));
}

/** The sentence the leverage chart proves. */
export function leverageSentence(report: ScanReport, ups: Upgrade[]): string {
  const actionable = report.findings.filter((f) => f.decision === 'Act' || f.decision === 'Attend');
  if (!actionable.length) return 'Nothing needs action; upgrades below close watched or set-aside findings.';
  const covering = ups.filter((u) => u.actionable > 0);
  const packages = covering.filter((u) => !u.inImage).length;
  const image = covering.filter((u) => u.inImage).length;
  const noFix = actionable.filter((f) => !f.advisory.fixedVersion).length;
  const parts: string[] = [];
  if (packages) parts.push(`${packages} package upgrade${packages === 1 ? '' : 's'}`);
  if (image) parts.push(`${image === 1 ? 'one' : image} base-image refresh${image === 1 ? '' : 'es'}`);
  const head = parts.length ? `${parts.join(' and ')} clear${parts.length === 1 && packages === 1 ? 's' : ''} ${noFix ? 'all but ' + noFix + ' of' : 'everything'} ${noFix ? 'the findings that need' : 'that needs'} action.` : '';
  const tail = noFix ? ` ${noFix} actionable finding${noFix === 1 ? ' has' : 's have'} no fix published yet; mitigate at the entry point.` : '';
  return (head + tail).trim() || `${noFix} actionable findings have no fix published yet.`;
}

// ---------------------------------------------------------------------------------------------
// What changed

export interface Bridge {
  previous?: { findings: number; at: string };
  current: number;
  added: Finding[];
  resolved: Finding[];
  escalated: { finding: Finding; from: Decision; to: Decision; reasons?: string[] }[];
  deescalated: { finding: Finding; from: Decision; to: Decision; reasons?: string[] }[];
}

export function bridge(report: ScanReport, diff?: ScanDiff): Bridge {
  const changed = (diff?.changed ?? []) as { finding: Finding; from: Decision; to: Decision; reasons?: string[] }[];
  return {
    previous: diff?.previous ? { findings: diff.previous.summary.findings, at: diff.previous.createdAt } : undefined,
    current: report.findings.length,
    added: diff?.added ?? [],
    resolved: diff?.resolved ?? [],
    escalated: changed.filter((c) => order(c.to) < order(c.from)),
    deescalated: changed.filter((c) => order(c.to) > order(c.from)),
  };
}

// ---------------------------------------------------------------------------------------------
// Attack surface

export interface SurfaceTile {
  entry: EntryPoint;
  findings: Finding[];
  worst?: Decision;
  userInput: boolean;
}

export function sameEntry(a: EntryPoint, b: EntryPoint): boolean {
  return a.method === b.method && a.path === b.path && a.file === b.file && a.line === b.line;
}

export function surface(report: ScanReport): SurfaceTile[] {
  const tiles = report.entryPoints.map((e) => {
    const fs = report.findings.filter((f) => f.reach.paths.some((p) => sameEntry(p.entry, e)));
    const userInput = report.findings.some((f) => f.reach.paths.some((p) => sameEntry(p.entry, e) && p.userInput));
    return { entry: e, findings: fs, worst: worstOf(fs), userInput };
  });
  return tiles.sort((a, b) => (a.worst ? order(a.worst) : 9) - (b.worst ? order(b.worst) : 9) || b.findings.length - a.findings.length || Number(a.entry.authenticated) - Number(b.entry.authenticated) || a.entry.path.localeCompare(b.entry.path));
}
