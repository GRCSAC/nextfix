import type { DatabaseSync } from 'node:sqlite';
import type { Decision, Finding, ScanReport, ScanSummary } from '../../../engine/src/types.ts';
import { FeatureError, type Route } from './core.ts';
import { activeExceptions, applyExceptions, isInForce, latestReport, targetExists } from './exceptions.ts';
import { MAX_LOG_PATH, MAX_LOG_SOURCES, parseAccessLogs } from './surface.ts';

/*
 * Portfolio: one row per application with its posture, computed from the latest report (after
 * exceptions), the finding history and the exceptions table. Also the owner and scan schedule
 * columns on targets.
 */

export const migrations: string[] = [
  // 5: owner and scan schedule on targets. ALTER TABLE ADD COLUMN cannot be made idempotent in
  // SQLite; the store runs each version once, and applyFeatureMigrations() skips the duplicate-column error.
  `
    ALTER TABLE targets ADD COLUMN owner TEXT;
    ALTER TABLE targets ADD COLUMN schedule_hours INTEGER;
  `,
];

export type Posture = 'Exposed' | 'Attention' | 'Contained' | 'Clean' | 'Never scanned';

export interface Verdict {
  posture: Posture;
  decision?: Decision;
  headline: string;
  detail?: string;
  findingId?: string;
}

export interface PortfolioRow {
  id: number;
  name: string;
  dir: string;
  owner: string | null;
  schedule: { everyHours: number } | null;
  lastScanAt?: string;
  lastScanId?: number;
  posture: Posture;
  headline: string;
  byDecision: Record<Decision, number>;
  /** Open (unauthenticated) routes that reach a vulnerable call, over all open routes. */
  exposedSurface: { open: number; total: number };
  /** Days the most overdue Act or Attend finding is past its SLA; absent when nothing is overdue. */
  oldestPastSlaDays?: number;
  /** Actionable (Act + Attend) findings per scan, oldest first, up to 8 scans. */
  trend: number[];
  pendingExceptions: number;
}

export const DECISION_ORDER: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];
const DAY_MS = 86_400_000;
const TREND_SCANS = 8;
const DECISION_ZERO: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };

export interface SlaDays {
  slaActDays: number;
  slaAttendDays: number;
}

/** SLA days from the settings table, with the store's defaults. */
export function slaSettings(db: DatabaseSync): SlaDays {
  const out: SlaDays = { slaActDays: 7, slaAttendDays: 30 };
  const rows = db.prepare("SELECT key, value FROM settings WHERE key IN ('slaActDays', 'slaAttendDays')").all() as { key: string; value: string }[];
  for (const r of rows) {
    const n = Number(r.value);
    if (Number.isFinite(n) && n > 0) out[r.key as keyof SlaDays] = n;
  }
  return out;
}

const pct = (n: number) => `${Math.round(n * 100)}%`;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** 1200 → "1.2k", 41200 → "41k" (same rule as the dashboard's format.ts). */
export function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 10_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k`;
  if (n < 1_000_000) return `${Math.round(n / 1000)}k`;
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
}

/** "the 30 days to Oct 11", as the dashboard words the traffic window. */
export function windowPhrase(report: ScanReport): string {
  const t = report.traffic;
  if (!t?.to) return '';
  const d = new Date(t.to);
  return `the ${t.windowDays} days to ${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
}

/** Worst case first: unauthenticated and carrying request data, then unauthenticated, then any with data. */
export function bestPath(f: Finding) {
  return f.reach.paths.find((x) => !x.entry.authenticated && x.userInput) ?? f.reach.paths.find((x) => !x.entry.authenticated) ?? f.reach.paths.find((x) => x.userInput) ?? f.reach.paths[0];
}

const openPath = (f: Finding) => f.reach.paths.some((p) => !p.entry.authenticated);

/**
 * The posture verdict, same rules and wording as the dashboard's verdict() in packages/web/src/analytics.ts
 * (kept in step by hand; the server cannot import the web package): Exposed when anything is Act,
 * Attention when anything is Attend, Contained when only Track* remains, else Clean.
 */
export function verdict(report: ScanReport): Verdict {
  const s = report.summary.byDecision;
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
    };
  }
  if (s['Track*'] > 0) {
    return { posture: 'Contained', decision: 'Track*', headline: `${s['Track*']} finding${s['Track*'] === 1 ? ' is' : 's are'} being watched; nothing needs a fix this cycle.`, detail: 'Watched items are re-checked when exploit data or the code changes.' };
  }
  return { posture: 'Clean', headline: report.findings.length ? `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}, all set aside with evidence; nothing needs action.` : 'No findings. Keep scanning after each release.' };
}

/** Open routes that reach a vulnerable call, over all open routes (the dashboard's "Exposed surface" ratio). */
export function exposedSurface(report: ScanReport): { open: number; total: number } {
  const openRoutes = report.entryPoints.filter((e) => !e.authenticated);
  const exposed = openRoutes.filter((e) => report.findings.some((f) => f.reach.paths.some((p) => p.entry.method === e.method && p.entry.path === e.path && p.entry.file === e.file && p.entry.line === e.line)));
  return { open: exposed.length, total: openRoutes.length };
}

export interface SlaBreach {
  findingId: string;
  decision: Decision;
  ageDays: number;
  overdueDays: number;
}

/**
 * Open Act and Attend findings older than their SLA, using the decisions of the served report
 * (so an exception that moved a finding to Track takes it off the list) and first_seen from the history.
 */
export function slaBreaches(db: DatabaseSync, targetId: number, report: ScanReport, sla: SlaDays, nowMs = Date.now()): SlaBreach[] {
  const rows = db.prepare('SELECT finding_id, first_seen_at FROM finding_history WHERE target_id = ? AND resolved_at IS NULL').all(targetId) as { finding_id: string; first_seen_at: string }[];
  const firstSeen = new Map(rows.map((r) => [r.finding_id, r.first_seen_at]));
  const limit: Partial<Record<Decision, number>> = { Act: sla.slaActDays, Attend: sla.slaAttendDays };
  const out: SlaBreach[] = [];
  for (const f of report.findings) {
    const days = limit[f.decision];
    const seen = firstSeen.get(f.id);
    if (days === undefined || !seen) continue;
    const age = Math.max(0, (nowMs - Date.parse(seen)) / DAY_MS);
    if (age > days) out.push({ findingId: f.id, decision: f.decision, ageDays: Math.floor(age), overdueDays: Math.floor(age - days) });
  }
  return out.sort((a, b) => b.overdueDays - a.overdueDays);
}

/** Actionable findings per scan, oldest first, over the newest `TREND_SCANS` scans. */
export function trend(db: DatabaseSync, targetId: number): number[] {
  const rows = db.prepare('SELECT summary FROM scans WHERE target_id = ? ORDER BY created_at DESC, id DESC LIMIT ?').all(targetId, TREND_SCANS) as { summary: string }[];
  return rows
    .map((r) => {
      try {
        const s = JSON.parse(r.summary) as Partial<ScanSummary>;
        return (s.byDecision?.Act ?? 0) + (s.byDecision?.Attend ?? 0);
      } catch {
        return 0;
      }
    })
    .reverse();
}

interface TargetRaw {
  id: number;
  dir: string;
  name: string | null;
  owner: string | null;
  schedule_hours: number | null;
  access_logs: string | null;
}

export interface TargetMeta {
  id: number;
  name: string;
  dir: string;
  owner: string | null;
  schedule: { everyHours: number } | null;
  /** Access logs the scan reads for this application (files or folders; may be absolute). */
  accessLogs: string[];
}

function toMeta(r: TargetRaw): TargetMeta {
  return { id: r.id, name: r.name ?? r.dir, dir: r.dir, owner: r.owner, schedule: r.schedule_hours ? { everyHours: r.schedule_hours } : null, accessLogs: parseAccessLogs(r.access_logs) };
}

export function listTargetMeta(db: DatabaseSync): TargetMeta[] {
  const rows = db.prepare('SELECT id, dir, name, owner, schedule_hours, access_logs FROM targets ORDER BY name, dir').all() as unknown as TargetRaw[];
  return rows.map(toMeta);
}

export function getTargetMeta(db: DatabaseSync, id: number): TargetMeta | undefined {
  const r = db.prepare('SELECT id, dir, name, owner, schedule_hours, access_logs FROM targets WHERE id = ?').get(id) as TargetRaw | undefined;
  return r ? toMeta(r) : undefined;
}

/** The latest report of a target with its exceptions applied, or undefined when never scanned. */
export function servedReport(db: DatabaseSync, targetId: number, now = new Date().toISOString()): { scanId: number; report: ScanReport } | undefined {
  const latest = latestReport(db, targetId);
  if (!latest) return undefined;
  return { scanId: latest.scanId, report: applyExceptions(latest.report, activeExceptions(db, targetId, now).filter((e) => isInForce(e, now)), now) };
}

/** One portfolio row. */
export function portfolioRow(db: DatabaseSync, target: TargetMeta, sla: SlaDays, nowMs = Date.now()): PortfolioRow {
  const now = new Date(nowMs).toISOString();
  const served = servedReport(db, target.id, now);
  const pending = activeExceptions(db, target.id, now).filter((e) => e.status === 'pending').length;
  if (!served) {
    return { ...target, posture: 'Never scanned', headline: 'Not scanned yet.', byDecision: { ...DECISION_ZERO }, exposedSurface: { open: 0, total: 0 }, trend: [], pendingExceptions: pending };
  }
  const { report } = served;
  const v = verdict(report);
  const breaches = slaBreaches(db, target.id, report, sla, nowMs);
  return {
    ...target,
    lastScanAt: report.generatedAt,
    lastScanId: served.scanId,
    posture: v.posture,
    headline: v.headline,
    byDecision: { ...DECISION_ZERO, ...report.summary.byDecision },
    exposedSurface: exposedSurface(report),
    oldestPastSlaDays: breaches.length ? breaches[0]!.overdueDays : undefined,
    trend: trend(db, target.id),
    pendingExceptions: pending,
  };
}

export function portfolio(db: DatabaseSync, nowMs = Date.now()): { targets: PortfolioRow[] } {
  const sla = slaSettings(db);
  return { targets: listTargetMeta(db).map((t) => portfolioRow(db, t, sla, nowMs)) };
}

export interface TargetPatch {
  owner?: string | null;
  schedule?: { everyHours: number } | null;
  accessLogs?: string[] | null;
}

/** Validate a PATCH body; unknown keys are ignored, absent keys left alone. */
export function parseTargetPatch(body: Record<string, unknown>): TargetPatch {
  const out: TargetPatch = {};
  if ('owner' in body) {
    const v = body.owner;
    if (v === null || v === '') out.owner = null;
    else if (typeof v === 'string' && v.trim().length <= 200) out.owner = v.trim();
    else throw new FeatureError(400, 'owner must be a string of at most 200 characters, or null');
  }
  if ('schedule' in body) {
    const v = body.schedule;
    if (v === null) out.schedule = null;
    else if (v && typeof v === 'object' && Number.isInteger((v as { everyHours?: unknown }).everyHours) && (v as { everyHours: number }).everyHours >= 1 && (v as { everyHours: number }).everyHours <= 24 * 365) out.schedule = { everyHours: (v as { everyHours: number }).everyHours };
    else throw new FeatureError(400, 'schedule must be { everyHours: 1..8760 } or null');
  }
  if ('accessLogs' in body) {
    const v = body.accessLogs;
    if (v === null) out.accessLogs = null;
    else if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
      const list = [...new Set((v as string[]).map((x) => x.trim()).filter(Boolean))];
      if (list.length > MAX_LOG_SOURCES) throw new FeatureError(400, `accessLogs may list at most ${MAX_LOG_SOURCES} files or folders`);
      if (list.some((x) => x.length > MAX_LOG_PATH || /[\0\r\n]/.test(x))) throw new FeatureError(400, `each access log path must be one line of at most ${MAX_LOG_PATH} characters`);
      out.accessLogs = list.length ? list : null;
    } else throw new FeatureError(400, 'accessLogs must be a list of file or folder paths, or null');
  }
  return out;
}

export function updateTargetMeta(db: DatabaseSync, id: number, patch: TargetPatch): TargetMeta {
  if (!targetExists(db, id)) throw new FeatureError(404, 'Target not found');
  if (patch.owner !== undefined) db.prepare('UPDATE targets SET owner = ? WHERE id = ?').run(patch.owner, id);
  if (patch.schedule !== undefined) db.prepare('UPDATE targets SET schedule_hours = ? WHERE id = ?').run(patch.schedule ? patch.schedule.everyHours : null, id);
  if (patch.accessLogs !== undefined) db.prepare('UPDATE targets SET access_logs = ? WHERE id = ?').run(patch.accessLogs ? JSON.stringify(patch.accessLogs) : null, id);
  return getTargetMeta(db, id)!;
}

export const routes: Route[] = [
  {
    method: 'GET',
    pattern: '/api/portfolio',
    role: 'viewer',
    handler({ db }) {
      return { body: portfolio(db) };
    },
  },
  {
    method: 'PATCH',
    pattern: '/api/targets/:id',
    role: 'analyst',
    handler({ db, params, body, audit }) {
      const id = Number(params.id);
      if (!Number.isInteger(id) || id < 1) throw new FeatureError(400, 'Bad target id');
      const patch = parseTargetPatch(body);
      const meta = updateTargetMeta(db, id, patch);
      audit('target.update', `target:${id}`, patch);
      return { body: meta };
    },
  },
];
