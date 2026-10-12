import type { DatabaseSync } from 'node:sqlite';
import type { Decision, InternetReach, ScanReport, ServiceIdentity } from '../../../engine/src/types.ts';
import type { Route } from './core.ts';
import { exposedSurface, listTargetMeta, servedReport, verdict, type Posture, type TargetMeta } from './portfolio.ts';

/*
 * Surface: what the deployment and the logs say about an application, beside what the code says.
 * Holds the access-log paths per target (read at scan time) and builds the portfolio map from
 * the service links and internet reach every report carries since 1.1.
 */

export const migrations: string[] = [
  // 8: access logs per target, a JSON list of file or folder paths the scan reads.
  `
    ALTER TABLE targets ADD COLUMN access_logs TEXT;
  `,
];

export const MAX_LOG_SOURCES = 20;
export const MAX_LOG_PATH = 500;

/** The access-log paths a target's scans read, or an empty list. */
export function accessLogsOf(db: DatabaseSync, targetId: number): string[] {
  const r = db.prepare('SELECT access_logs FROM targets WHERE id = ?').get(targetId) as { access_logs: string | null } | undefined;
  return parseAccessLogs(r?.access_logs ?? null);
}

export function parseAccessLogs(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw) as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim().length > 0) : [];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------------------------
// Portfolio map

export interface MapNode {
  id: number;
  name: string;
  owner: string | null;
  posture: Posture;
  byDecision: Record<Decision, number>;
  reach: InternetReach;
  reachEvidence: string[];
  lastScanAt?: string;
  identity: ServiceIdentity;
  /** The headline finding when the application is Exposed. */
  headline?: string;
  findingId?: string;
  exposedSurface: { open: number; total: number };
  /** Applications that depend on this one, directly or through others (what breaks if it falls). */
  upstream: number[];
  /** Applications this one reaches, directly or through others (where an intruder could go next). */
  downstream: number[];
}

export interface MapEdge {
  from: number;
  to: number;
  /** The host name as written in the caller's files, and where. */
  host: string;
  evidence: string;
}

export interface ExternalNode {
  host: string;
  /** True for a public-looking domain (a SaaS or a partner); false for an internal name no application answers to. */
  external: boolean;
  callers: { id: number; evidence: string }[];
}

export interface PortfolioMap {
  nodes: MapNode[];
  edges: MapEdge[];
  external: ExternalNode[];
  /** Applications whose latest scan says the internet reaches them. */
  internet: number[];
  computedAt: string;
}

const INTERNAL_SUFFIX = /\.(local|internal|svc|cluster\.local|localhost|test|lan|home|corp|intranet|private)$/i;
const DECISION_ZERO: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };

/** The names a target answers to: its report's identity plus its own name and folder. */
function keysOf(t: TargetMeta, report: ScanReport | undefined): Set<string> {
  const keys = new Set<string>();
  const add = (s: string | undefined) => {
    if (s) keys.add(s.trim().toLowerCase());
  };
  add(t.name);
  add(t.dir.replace(/[\\/]+$/, '').split(/[\\/]/).pop());
  add(report?.target.name);
  for (const n of report?.links?.identity.names ?? []) add(n);
  for (const h of report?.links?.identity.hosts ?? []) add(h);
  keys.delete('');
  return keys;
}

/** Which targets a link host names: exact, or the first label of a cluster-local / internal name. */
export function matchHost(host: string, keys: Map<number, Set<string>>, exclude: number): number[] {
  const h = host.toLowerCase().replace(/:\d+$/, '');
  const first = h.split('.')[0]!;
  const bare = INTERNAL_SUFFIX.test(h) || !h.includes('.') ? first : undefined;
  const hits: number[] = [];
  for (const [id, set] of keys) {
    if (id === exclude) continue;
    if (set.has(h) || (bare !== undefined && set.has(bare))) hits.push(id);
    else for (const k of set) if (k.includes('.') && h.endsWith('.' + k)) hits.push(id);
  }
  return [...new Set(hits)];
}

function closure(start: number, next: Map<number, Set<number>>): number[] {
  const seen = new Set<number>();
  const stack = [...(next.get(start) ?? [])];
  while (stack.length) {
    const n = stack.pop()!;
    if (n === start || seen.has(n)) continue;
    seen.add(n);
    for (const m of next.get(n) ?? []) stack.push(m);
  }
  return [...seen].sort((a, b) => a - b);
}

/** Build the map from every target's latest report (after exceptions). */
export function portfolioMap(db: DatabaseSync, nowMs = Date.now()): PortfolioMap {
  const now = new Date(nowMs).toISOString();
  const targets = listTargetMeta(db);
  const reports = new Map<number, ScanReport | undefined>();
  for (const t of targets) reports.set(t.id, servedReport(db, t.id, now)?.report);
  const keys = new Map(targets.map((t) => [t.id, keysOf(t, reports.get(t.id))]));

  const edges: MapEdge[] = [];
  const external = new Map<string, ExternalNode>();
  const callees = new Map<number, Set<number>>();
  const callers = new Map<number, Set<number>>();
  for (const t of targets) {
    const links = reports.get(t.id)?.links?.outbound ?? [];
    for (const l of links) {
      const hits = matchHost(l.host, keys, t.id);
      if (hits.length) {
        for (const to of hits) {
          if (edges.some((e) => e.from === t.id && e.to === to)) continue;
          edges.push({ from: t.id, to, host: l.host, evidence: l.evidence });
          if (!callees.has(t.id)) callees.set(t.id, new Set());
          callees.get(t.id)!.add(to);
          if (!callers.has(to)) callers.set(to, new Set());
          callers.get(to)!.add(t.id);
        }
        continue;
      }
      const key = l.host.toLowerCase();
      let x = external.get(key);
      if (!x) {
        x = { host: key, external: l.external, callers: [] };
        external.set(key, x);
      }
      if (!x.callers.some((c) => c.id === t.id)) x.callers.push({ id: t.id, evidence: l.evidence });
    }
  }

  const nodes: MapNode[] = targets.map((t) => {
    const report = reports.get(t.id);
    const v = report ? verdict(report) : undefined;
    return {
      id: t.id,
      name: t.name,
      owner: t.owner,
      posture: v?.posture ?? 'Never scanned',
      byDecision: { ...DECISION_ZERO, ...(report?.summary.byDecision ?? {}) },
      reach: report?.exposure.reach ?? 'unknown',
      reachEvidence: report?.exposure.reachEvidence ?? [],
      lastScanAt: report?.generatedAt,
      identity: report?.links?.identity ?? { names: [], hosts: [] },
      headline: v?.posture === 'Exposed' ? v.headline : undefined,
      findingId: v?.findingId,
      exposedSurface: report ? exposedSurface(report) : { open: 0, total: 0 },
      upstream: closure(t.id, callers),
      downstream: closure(t.id, callees),
    };
  });
  const sortedExternal = [...external.values()].sort((a, b) => b.callers.length - a.callers.length || Number(a.external) - Number(b.external) || a.host.localeCompare(b.host));
  return { nodes, edges, external: sortedExternal, internet: nodes.filter((n) => n.reach === 'internet').map((n) => n.id), computedAt: now };
}

export const routes: Route[] = [
  {
    method: 'GET',
    pattern: '/api/portfolio/map',
    role: 'viewer',
    handler({ db }) {
      return { body: portfolioMap(db) };
    },
  },
];
