import type { Decision, Finding, ScanReport } from '../../engine/src/types.ts';

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

export interface ScanDiff {
  added: Finding[];
  resolved: Finding[];
  changed: ChangedFinding[];
  summary: DiffSummary;
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
  if (!previous) return { added: [], resolved: [], changed: [], summary: { added: 0, resolved: 0, escalated: 0, deescalated: 0 } };
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
  return { added, resolved, changed, summary: { added: added.length, resolved: resolved.length, escalated, deescalated } };
}
