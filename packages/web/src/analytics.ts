import type { Decision, EntryPoint, Exception, Finding, ReachTier, RouteTraffic, ScanDiff, ScanReport, SurfaceChange, TrafficFile } from './api.ts';
import { DECISIONS, DECISION_META, bestPath, compact, pct } from './format.ts';
import { compareVersions } from '../../engine/src/vulns/ecosystems.ts';

/* Derived views of one report: everything the Overview draws comes from these pure functions. */

const order = (d: Decision) => DECISIONS.indexOf(d);
export const worstOf = (fs: Finding[]): Decision | undefined => fs.reduce<Decision | undefined>((w, f) => (w === undefined || order(f.decision) < order(w) ? f.decision : w), undefined);

const likely = (f: Finding) => !!f.kev || (f.epss?.score ?? 0) >= 0.1;
const openPath = (f: Finding) => f.reach.paths.some((p) => !p.entry.authenticated);
const openInput = (f: Finding) => f.reach.paths.some((p) => !p.entry.authenticated && p.userInput);
/** An open route to the call took requests from public addresses. */
const openPublic = (f: Finding) => f.reach.paths.some((p) => !p.entry.authenticated && (p.entry.traffic?.public ?? 0) > 0);
/** Every route to the call was quiet in the window. */
const allCold = (f: Finding) => f.reach.paths.length > 0 && f.reach.paths.every((p) => p.entry.traffic !== undefined && p.entry.traffic.requests === 0);

/** Access logs were read and recorded at least one request. */
export function hasTraffic(report: ScanReport): boolean {
  return !!report.traffic && report.traffic.requests > 0;
}

/** "the 30 days to Oct 11" for sentences about the window. */
export function windowPhrase(report: ScanReport): string {
  const t = report.traffic;
  if (!t?.to) return '';
  return `the ${t.windowDays} days to ${new Date(t.to).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}`;
}

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
    const seen = p && !p.entry.authenticated && (p.entry.traffic?.public ?? 0) > 0 ? p.entry.traffic!.public : 0;
    const bits = [
      `${one ? 'One vulnerability is' : `${act.length} vulnerabilities are`} reachable ${p ? (p.entry.authenticated ? 'behind a login' : 'without a login') : 'from the code'}`,
      p?.userInput ? (one ? 'carries request data' : 'carry request data') : undefined,
      f.kev ? `and ${one ? 'is' : 'the worst is'} on CISA's known-exploited list` : (f.epss?.score ?? 0) >= 0.1 ? `and ${one ? 'has' : 'the worst has'} a ${pct(f.epss!.score)} chance of exploitation within 30 days` : undefined,
    ].filter(Boolean);
    const observed = seen ? ` The internet is already calling that route: ${compact(seen)} public request${seen === 1 ? '' : 's'} in ${windowPhrase(report)}.` : '';
    return {
      posture: 'Exposed',
      decision: 'Act',
      headline: `${bits.join(', ')}.${observed}`,
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
  /** What this step removed and why; `tier` filters the findings page to it, `query` adds other filters. */
  removed?: { count: number; note: string; tier?: ReachTier; decision?: Decision; query?: Record<string, string> };
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
  // With access logs read, the chain continues through the routes the internet actually calls.
  const observed = hasTraffic(report);
  const seen = observed ? open.filter(openPublic) : open;
  const input = seen.filter(openInput);
  const exploited = input.filter(likely);
  const n = (k: number, one: string, many = `${one}s`) => `${k} ${k === 1 ? one : many}`;
  const cold = open.filter(allCold).length;
  const internalOnly = open.length - seen.length - cold;
  const seenRow: FunnelRow[] = observed
    ? [{ key: 'seen', label: 'Route called from the internet', count: seen.length, color: 'var(--c-attend)', removed: { count: open.length - seen.length, note: [cold ? `${cold} on routes nobody called in ${windowPhrase(report)}` : '', internalOnly > 0 ? `${internalOnly} with internal traffic only` : ''].filter(Boolean).join(' · ') || 'none removed', tier: 'reachable', query: { traffic: cold ? 'cold' : 'internal' } } }]
    : [];
  return [
    { key: 'found', label: 'Advisories found', count: all.length, color: 'var(--muted)' },
    { key: 'shipped', label: 'In shipped code', count: shipped.length, color: 'var(--muted)', removed: { count: all.length - shipped.length, note: `${n(all.length - shipped.length, 'development-only dependency', 'development-only dependencies')}`, tier: 'dev-only' } },
    { key: 'own', label: "In the application's own dependencies", count: own.length, color: 'var(--c-aside)', removed: { count: shipped.length - own.length, note: `${shipped.length - own.length} only in the container image (base OS, tooling)`, tier: 'image-only' } },
    { key: 'imported', label: 'Imported by application code', count: imported.length, color: 'var(--c-aside)', removed: { count: own.length - imported.length, note: `${own.length - imported.length} installed but never imported`, tier: 'unused' } },
    { key: 'called', label: 'Vulnerable function called', count: called.length, color: 'var(--c-watch)', removed: { count: imported.length - called.length, note: `${imported.length - called.length} never call the vulnerable function`, tier: 'imported-not-called' } },
    { key: 'reachable', label: 'Reachable from an entry point', count: reachable.length, color: 'var(--c-attend)', removed: { count: called.length - reachable.length, note: [tier('called-unreached').length ? `${tier('called-unreached').length} called only from code no route reaches` : '', unknown.length ? `${unknown.length} with no function data yet, watched` : ''].filter(Boolean).join(' · '), tier: unknown.length && !tier('called-unreached').length ? 'imported-unknown-symbol' : 'called-unreached' } },
    { key: 'open', label: 'Reachable without a login', count: open.length, color: 'var(--c-attend)', removed: { count: reachable.length - open.length, note: `${reachable.length - open.length} behind a login`, tier: 'reachable' } },
    ...seenRow,
    { key: 'input', label: 'Request data reaches the call', count: input.length, color: 'var(--c-attend)', removed: { count: seen.length - input.length, note: `${seen.length - input.length} with the application's own inputs only`, tier: 'reachable' } },
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
  const out = [
    { label: 'Need no action', value: all ? pct((all - actionable) / all) : '—', note: `${all - actionable} of ${all} findings set aside or watched, each with a reason` },
    { label: 'Exposed surface', value: `${exposedRoutes.length} of ${openRoutes.length}`, note: 'open routes that reach a vulnerable call' },
  ];
  if (hasTraffic(report)) {
    const seen = openRoutes.filter((e) => (e.traffic?.public ?? 0) > 0).length;
    out.push({ label: 'Called from the internet', value: `${seen} of ${openRoutes.length}`, note: `open routes with public traffic in ${windowPhrase(report)}` });
  }
  out.push({ label: 'From the image', value: all ? pct(image / all) : '—', note: `${image} findings come from the base image and its tooling` });
  return out;
}

// ---------------------------------------------------------------------------------------------
// What the logs say

export interface TrafficRoute {
  entry: EntryPoint;
  traffic: RouteTraffic;
  findings: Finding[];
  worst?: Decision;
}

export interface TrafficView {
  /** Logs were configured and read; `requests` may still be 0. */
  configured: boolean;
  observed: boolean;
  sentence: string;
  detail: string;
  files: TrafficFile[];
  /** Routes by public traffic, busiest first (every route that took a request). */
  routes: TrafficRoute[];
  /** Open routes nobody called that still reach a vulnerable call. */
  quiet: TrafficRoute[];
  stale: boolean;
  days: number;
}

export function trafficView(report: ScanReport): TrafficView {
  const t = report.traffic;
  const days = t?.windowDays ?? 30;
  const empty: TrafficView = { configured: !!t, observed: false, sentence: '', detail: '', files: t?.files ?? [], routes: [], quiet: [], stale: !!t?.stale, days };
  if (!t) return empty;
  if (!t.requests) return { ...empty, sentence: 'The configured logs held no requests that could be read.', detail: t.files.map((f) => `${f.path}: ${f.lines} lines, ${f.parsed} read as requests (${f.format})`).join(' · ') };
  const rows: TrafficRoute[] = report.entryPoints
    .filter((e) => e.traffic)
    .map((e) => {
      const fs = report.findings.filter((f) => f.reach.paths.some((p) => sameEntry(p.entry, e)));
      return { entry: e, traffic: e.traffic!, findings: fs, worst: worstOf(fs) };
    });
  const routes = rows.filter((r) => r.traffic.requests > 0).sort((a, b) => b.traffic.public - a.traffic.public || b.traffic.requests - a.traffic.requests);
  const quiet = rows.filter((r) => r.traffic.requests === 0 && !r.entry.authenticated && r.findings.length).sort((a, b) => (a.worst ? order(a.worst) : 9) - (b.worst ? order(b.worst) : 9) || b.findings.length - a.findings.length);
  const window = windowPhrase(report);
  const sentence = `${compact(t.requests)} request${t.requests === 1 ? '' : 's'} in ${window}: ${compact(t.public)} from public addresses, ${compact(t.internal)} internal. ${t.routesSeen} of ${report.entryPoints.length} routes were called${t.routesCold ? `; ${t.routesCold} ${t.routesCold === 1 ? 'was' : 'were'} not` : ''}.`;
  const detailBits = [
    t.unmatched ? `${compact(t.unmatched)} requests matched no route (static files, other services, probes)` : '',
    t.stale ? 'The logs end more than a month before this scan, so quiet routes are reported but do not lower a decision.' : '',
    t.windowDays < 14 ? 'The window is shorter than two weeks, so quiet routes do not lower a decision.' : '',
  ].filter(Boolean);
  return { configured: true, observed: true, sentence, detail: detailBits.join(' '), files: t.files, routes, quiet, stale: t.stale, days };
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
  /** Attack-surface changes since the previous scan, widening ones first. */
  surface: SurfaceChange[];
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
    surface: diff?.surface ?? [],
  };
}

// ---------------------------------------------------------------------------------------------
// Attack surface

export interface SurfaceTile {
  entry: EntryPoint;
  findings: Finding[];
  worst?: Decision;
  userInput: boolean;
  /** Present when access logs were read. */
  traffic?: RouteTraffic;
}

export function sameEntry(a: EntryPoint, b: EntryPoint): boolean {
  return a.method === b.method && a.path === b.path && a.file === b.file && a.line === b.line;
}

export function surface(report: ScanReport): SurfaceTile[] {
  const tiles = report.entryPoints.map((e) => {
    const fs = report.findings.filter((f) => f.reach.paths.some((p) => sameEntry(p.entry, e)));
    const userInput = report.findings.some((f) => f.reach.paths.some((p) => sameEntry(p.entry, e) && p.userInput));
    return { entry: e, findings: fs, worst: worstOf(fs), userInput, traffic: e.traffic };
  });
  return tiles.sort((a, b) => (a.worst ? order(a.worst) : 9) - (b.worst ? order(b.worst) : 9) || (b.traffic?.public ?? 0) - (a.traffic?.public ?? 0) || b.findings.length - a.findings.length || Number(a.entry.authenticated) - Number(b.entry.authenticated) || a.entry.path.localeCompare(b.entry.path));
}

// ---------------------------------------------------------------------------------------------
// Decide: what a person still has to rule on

export interface Decide {
  /** Proposed exceptions nobody has approved or rejected yet. */
  pending: Exception[];
  /** Approved exceptions that run out within 30 days, soonest first. */
  expiring: Exception[];
  /** Open routes that reach an actionable finding while the service's network exposure is not confirmed. */
  routes: SurfaceTile[];
}

export function decide(exceptions: Exception[], report: ScanReport, now = Date.now()): Decide {
  const soon = now + 30 * 86_400_000;
  const pending = exceptions.filter((e) => e.status === 'pending').sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const expiring = exceptions
    .filter((e) => e.status === 'approved' && e.expiresAt && Date.parse(e.expiresAt) > now && Date.parse(e.expiresAt) <= soon)
    .sort((a, b) => Date.parse(a.expiresAt!) - Date.parse(b.expiresAt!));
  // A route is confirmed public by observation (public traffic) or by the service's exposure; the rest wait on a person.
  const confirmed = report.exposure.network === 'published' || report.exposure.reach === 'internet';
  const routes = confirmed ? [] : surface(report).filter((t) => !t.entry.authenticated && (t.traffic?.public ?? 0) === 0 && t.findings.some((f) => f.decision === 'Act' || f.decision === 'Attend'));
  return { pending, expiring, routes };
}
