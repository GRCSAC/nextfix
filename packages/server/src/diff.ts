import type { Decision, EntryPoint, Finding, ScanReport } from '../../engine/src/types.ts';

export interface ChangedFinding {
  finding: Finding;
  from: Decision;
  to: Decision;
  /** Short, human-readable reasons: "decision Attend → Act", "entered KEV", "fix published 4.18.0". */
  reasons: string[];
}

export interface DiffSummary {
  added: number;
  resolved: number;
  /** Decision moved towards Act. */
  escalated: number;
  /** Decision moved away from Act. */
  deescalated: number;
}

export type SurfaceKind = 'route-added' | 'route-removed' | 'guard-removed' | 'guard-added' | 'network' | 'reach' | 'port-added' | 'port-removed' | 'traffic-public' | 'traffic-quiet' | 'link-added' | 'link-removed';
export type SurfaceLevel = 'act' | 'attend' | 'info' | 'good';

/** One change to the attack surface between two scans: routes, guards, exposure, traffic, links. */
export interface SurfaceChange {
  kind: SurfaceKind;
  /** act: widens the surface where it hurts; attend: widens it; info: neutral; good: narrows it. */
  level: SurfaceLevel;
  text: string;
  /** `METHOD /path` when the change is about one route. */
  route?: string;
  /** Findings reachable through that route in the current scan. */
  findings?: number;
}

export interface ScanDiff {
  added: Finding[];
  resolved: Finding[];
  changed: ChangedFinding[];
  /** Surface changes, widening ones first (absent in diffs computed before 1.1). */
  surface: SurfaceChange[];
  summary: DiffSummary & { surface: number };
}

const LEVEL_ORDER: SurfaceLevel[] = ['act', 'attend', 'info', 'good'];
const MAX_SURFACE = 40;

const routeKey = (e: EntryPoint) => `${e.method.toUpperCase()} ${e.path}`;

/** Findings in a report that an entry point reaches, by route key. */
function findingsByRoute(report: ScanReport): Map<string, Finding[]> {
  const out = new Map<string, Finding[]>();
  for (const f of report.findings) for (const p of f.reach.paths) {
    const k = routeKey(p.entry);
    if (!out.has(k)) out.set(k, []);
    if (!out.get(k)!.includes(f)) out.get(k)!.push(f);
  }
  return out;
}

const worstOf = (fs: Finding[]): Decision | undefined => fs.reduce<Decision | undefined>((w, f) => (w === undefined || DECISION_ORDER.indexOf(f.decision) < DECISION_ORDER.indexOf(w) ? f.decision : w), undefined);
const DECISION_WORD: Record<Decision, string> = { Act: 'Fix now', Attend: 'Fix next cycle', 'Track*': 'Watch', Track: 'Set aside' };

function reaches(fs: Finding[]): string {
  if (!fs.length) return 'reaches no vulnerable call';
  const w = worstOf(fs)!;
  return `reaches ${fs.length} finding${fs.length === 1 ? '' : 's'}, worst ${DECISION_WORD[w]}`;
}

/** What changed on the attack surface between two reports. Empty when there is no previous report. */
export function surfaceDiff(current: ScanReport, previous: ScanReport | undefined): SurfaceChange[] {
  if (!previous) return [];
  const out: SurfaceChange[] = [];
  const prev = new Map(previous.entryPoints.map((e) => [routeKey(e), e]));
  const cur = new Map(current.entryPoints.map((e) => [routeKey(e), e]));
  const curFindings = findingsByRoute(current);
  const prevFindings = findingsByRoute(previous);
  const actionable = (fs: Finding[]) => fs.some((f) => f.decision === 'Act' || f.decision === 'Attend');

  for (const [k, e] of cur) {
    const fs = curFindings.get(k) ?? [];
    const was = prev.get(k);
    if (!was) {
      if (e.authenticated) out.push({ kind: 'route-added', level: 'info', text: `New route behind a login: ${k} (${e.guards.join(', ') || 'guarded'}; ${reaches(fs)})`, route: k, findings: fs.length });
      else out.push({ kind: 'route-added', level: actionable(fs) ? 'act' : fs.length ? 'attend' : 'info', text: `New route without a login: ${k} (${reaches(fs)})`, route: k, findings: fs.length });
      continue;
    }
    if (was.authenticated && !e.authenticated) out.push({ kind: 'guard-removed', level: actionable(fs) ? 'act' : 'attend', text: `Auth guard removed from ${k} (was behind ${was.guards.join(', ') || 'a guard'}; ${reaches(fs)})`, route: k, findings: fs.length });
    else if (!was.authenticated && e.authenticated) out.push({ kind: 'guard-added', level: 'good', text: `${k} is now behind ${e.guards.join(', ') || 'a login'}`, route: k, findings: fs.length });
    // Traffic: both scans read logs for this route.
    if (was.traffic && e.traffic) {
      if (!was.traffic.public && e.traffic.public) out.push({ kind: 'traffic-public', level: e.authenticated ? 'info' : actionable(fs) ? 'act' : 'attend', text: `Public traffic has started on ${k}: ${e.traffic.public.toLocaleString('en-US')} request${e.traffic.public === 1 ? '' : 's'} from public addresses${e.authenticated ? ' (behind a login)' : ''}${fs.length ? `; ${reaches(fs)}` : ''}`, route: k, findings: fs.length });
      else if (was.traffic.public && !e.traffic.public) out.push({ kind: 'traffic-quiet', level: 'info', text: `No public traffic on ${k} any more (was ${was.traffic.public.toLocaleString('en-US')})`, route: k, findings: fs.length });
    }
  }
  for (const [k, was] of prev) {
    if (cur.has(k)) continue;
    const fs = prevFindings.get(k) ?? [];
    out.push({ kind: 'route-removed', level: fs.length ? 'good' : 'info', text: `Route removed: ${k}${fs.length ? ` (${fs.length} finding${fs.length === 1 ? '' : 's'} no longer reachable through it)` : ''}`, route: k, findings: 0 });
  }

  // Exposure of the service as a whole.
  const px = previous.exposure;
  const cx = current.exposure;
  if (px.network !== cx.network) {
    if (cx.network === 'published') out.push({ kind: 'network', level: 'attend', text: `Service is now network-published (${cx.evidence.join('; ') || 'ports published'}); it was ${px.network === 'local-only' ? 'bound to loopback' : 'not confirmed'} before` });
    else if (cx.network === 'local-only') out.push({ kind: 'network', level: 'good', text: 'Service now binds to loopback only' });
    else out.push({ kind: 'network', level: 'info', text: 'Network exposure is no longer confirmed (no Dockerfile EXPOSE or compose ports found)' });
  }
  const pr = px.reach ?? 'unknown';
  const cr = cx.reach ?? 'unknown';
  if (pr !== cr) {
    if (cr === 'internet') out.push({ kind: 'reach', level: 'act', text: `Now internet-facing: ${(cx.reachEvidence ?? []).join('; ')}` });
    else if (cr === 'internal') out.push({ kind: 'reach', level: pr === 'internet' ? 'good' : 'info', text: `${pr === 'internet' ? 'No longer internet-facing' : 'Confirmed as internal only'}: ${(cx.reachEvidence ?? []).join('; ')}` });
    else out.push({ kind: 'reach', level: 'info', text: `Internet reach is no longer confirmed (was ${pr})` });
  }
  const prevPorts = new Set(px.ports);
  const curPorts = new Set(cx.ports);
  for (const p of curPorts) if (!prevPorts.has(p)) out.push({ kind: 'port-added', level: 'attend', text: `Port ${p} is now published` });
  for (const p of prevPorts) if (!curPorts.has(p)) out.push({ kind: 'port-removed', level: 'good', text: `Port ${p} is no longer published` });

  // Links to other services.
  const prevLinks = new Map((previous.links?.outbound ?? []).map((l) => [l.host, l]));
  const curLinks = new Map((current.links?.outbound ?? []).map((l) => [l.host, l]));
  if (previous.links && current.links) {
    for (const [h, l] of curLinks) if (!prevLinks.has(h)) out.push({ kind: 'link-added', level: 'info', text: `Now calls ${h}${l.external ? ' (outside service)' : ''}: ${l.evidence}` });
    for (const h of prevLinks.keys()) if (!curLinks.has(h)) out.push({ kind: 'link-removed', level: 'info', text: `No longer calls ${h}` });
  }

  return out.sort((a, b) => LEVEL_ORDER.indexOf(a.level) - LEVEL_ORDER.indexOf(b.level)).slice(0, MAX_SURFACE);
}

/** Surface changes that widen the surface (act or attend), the number the portfolio and digest quote. */
export function wideningCount(surface: SurfaceChange[]): number {
  return surface.filter((s) => s.level === 'act' || s.level === 'attend').length;
}

const DECISION_ORDER: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];

/**
 * Finding ids are `purl|advisory`. PyPI names are case-insensitive (and `_`/`.`/`-` are
 * equivalent), so a lockfile that renames `PyYAML` to `pyyaml` must not read as a new finding.
 */
export function normalizeFindingId(id: string): string {
  const bar = id.indexOf('|');
  const purl = bar === -1 ? id : id.slice(0, bar);
  const rest = bar === -1 ? '' : id.slice(bar);
  const m = /^(pkg:[^/]+\/)(.*)$/i.exec(purl);
  if (!m) return id;
  const type = m[1]!.toLowerCase();
  let name = m[2]!;
  if (type === 'pkg:pypi/') {
    const at = name.indexOf('@');
    const bare = at === -1 ? name : name.slice(0, at);
    name = bare.toLowerCase().replace(/[-_.]+/g, '-') + (at === -1 ? '' : name.slice(at));
  }
  return `${type}${name}${rest}`;
}

function hasUserInput(f: Finding): boolean {
  return f.reach.paths.some((p) => p.userInput);
}

function entryKeys(f: Finding): Set<string> {
  return new Set(f.reach.paths.map((p) => `${p.entry.method} ${p.entry.path}`));
}

/** Why a finding that exists in both reports looks different now. Empty when nothing of interest changed. */
export function changeReasons(prev: Finding, cur: Finding): string[] {
  const reasons: string[] = [];
  if (prev.decision !== cur.decision) reasons.push(`decision ${prev.decision} → ${cur.decision}`);
  if (!prev.kev && cur.kev) reasons.push('entered KEV');
  if (prev.kev && !cur.kev) reasons.push('left KEV');
  const pe = prev.epss?.score ?? 0;
  const ce = cur.epss?.score ?? 0;
  if (pe < 0.1 && ce >= 0.1) reasons.push(`EPSS rose to ${(ce * 100).toFixed(0)}%`);
  else if (pe >= 0.1 && ce < 0.1) reasons.push(`EPSS fell to ${(ce * 100).toFixed(0)}%`);
  if (prev.reach.tier !== cur.reach.tier) {
    if (cur.reach.tier === 'reachable') reasons.push('new entry point reaches it');
    else if (prev.reach.tier === 'reachable') reasons.push('no longer reachable');
    else reasons.push(`reach ${prev.reach.tier} → ${cur.reach.tier}`);
  } else if (cur.reach.tier === 'reachable') {
    const before = entryKeys(prev);
    const added = [...entryKeys(cur)].filter((k) => !before.has(k));
    if (added.length) reasons.push(`new entry point reaches it (${added[0]})`);
  }
  const pu = hasUserInput(prev);
  const cu = hasUserInput(cur);
  if (!pu && cu) reasons.push('request data now reaches it');
  if (pu && !cu) reasons.push('request data no longer reaches it');
  if (prev.advisory.fixedVersion !== cur.advisory.fixedVersion) {
    if (cur.advisory.fixedVersion) reasons.push(`fix published ${cur.advisory.fixedVersion}`);
    else reasons.push('fix withdrawn');
  }
  const pa = prev.reach.paths.some((p) => !p.entry.authenticated);
  const ca = cur.reach.paths.some((p) => !p.entry.authenticated);
  if (!pa && ca && prev.reach.tier === cur.reach.tier) reasons.push('now reachable without auth');
  if (pa && !ca && prev.reach.tier === cur.reach.tier) reasons.push('now behind auth');
  return reasons;
}

/** What changed between two reports, keyed by normalised component purl + advisory id. */
export function diffReports(current: ScanReport, previous: ScanReport | undefined): ScanDiff {
  if (!previous) return { added: [], resolved: [], changed: [], surface: [], summary: { added: 0, resolved: 0, escalated: 0, deescalated: 0, surface: 0 } };
  const prev = new Map(previous.findings.map((f) => [normalizeFindingId(f.id), f]));
  const cur = new Map(current.findings.map((f) => [normalizeFindingId(f.id), f]));
  const added = current.findings.filter((f) => !prev.has(normalizeFindingId(f.id)));
  const resolved = previous.findings.filter((f) => !cur.has(normalizeFindingId(f.id)));
  const changed: ChangedFinding[] = [];
  let escalated = 0;
  let deescalated = 0;
  for (const f of current.findings) {
    const p = prev.get(normalizeFindingId(f.id));
    if (!p) continue;
    const reasons = changeReasons(p, f);
    if (!reasons.length) continue;
    changed.push({ finding: f, from: p.decision, to: f.decision, reasons });
    const delta = DECISION_ORDER.indexOf(f.decision) - DECISION_ORDER.indexOf(p.decision);
    if (delta < 0) escalated++;
    else if (delta > 0) deescalated++;
  }
  const surface = surfaceDiff(current, previous);
  return { added, resolved, changed, surface, summary: { added: added.length, resolved: resolved.length, escalated, deescalated, surface: wideningCount(surface) } };
}
