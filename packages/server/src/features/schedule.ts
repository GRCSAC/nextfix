import type { DatabaseSync } from 'node:sqlite';
import { Cache, defaultCachePath } from '../../../engine/src/vulns/cache.ts';
import { fetchEpss } from '../../../engine/src/vulns/epss.ts';
import { fetchKev } from '../../../engine/src/vulns/kev.ts';
import { decide } from '../../../engine/src/decide/ssvc.ts';
import type { Advisory, Decision, Finding, ScanReport } from '../../../engine/src/types.ts';
import { changeReasons, type ChangedFinding } from '../diff.ts';
import { FeatureError, type Route } from './core.ts';
import { expireExceptions, latestReport, targetExists } from './exceptions.ts';
import { DECISION_ORDER } from './portfolio.ts';
import { sendDigestIfDue } from './digest.ts';

/*
 * Scheduler: every minute, scan targets whose schedule is due, run the nightly re-decide pass
 * and send the weekly digest when its hour comes. Everything that decides "is it due" takes a
 * `now` so tests drive it without clocks.
 */

export const migrations: string[] = [
  // 6: decisions the nightly re-decide pass changed, so the digest can report promotions.
  `
    CREATE TABLE IF NOT EXISTS redecide_events (
      id INTEGER PRIMARY KEY,
      target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL,
      scan_id INTEGER,
      from_decision TEXT NOT NULL,
      to_decision TEXT NOT NULL,
      reasons TEXT NOT NULL,
      at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS redecide_events_target ON redecide_events(target_id, at);
  `,
];

/** Settings key holding the last nightly run, so a restart does not run it twice. */
export const REDECIDE_LAST_RUN_KEY = 'redecideLastRunAt';
export const DEFAULT_REDECIDE_AT = '03:00';
export const DEFAULT_TICK_MS = 60_000;
const HOUR_MS = 3_600_000;

export type Redecide = (report: ScanReport) => Promise<ChangedFinding[]>;

export interface SchedulerOptions {
  db: DatabaseSync;
  /** Runs a scan of the target and stores it (the server's scan path, lock included). */
  runScan(targetId: number): Promise<unknown>;
  /** The re-decide step; defaults to redecideReport() over `cachePath`. */
  redecide?: Redecide;
  log?: (msg: string) => void;
  /** Advisory cache for the default re-decide (the engine's cache by default). */
  cachePath?: string;
  /** Milliseconds between ticks (default one minute). */
  tickMs?: number;
  /** Clock, for tests. */
  now?: () => number;
  /** `HH:MM` local time for the nightly pass; defaults to NEXTFIX_REDECIDE_AT or 03:00. */
  redecideAt?: string;
  /** Set false to leave the weekly digest out (tests). */
  digest?: boolean;
}

export interface Scheduler {
  stop(): void;
  /** Run one pass now; resolves when it is done. */
  tick(nowMs?: number): Promise<TickResult>;
}

export interface TickResult {
  scanned: number[];
  redecided: boolean;
  digestSent: boolean;
  errors: string[];
}

// ---------------------------------------------------------------------------------------------
// Re-decide (a copy of the server's redecide(); see the note on duplication in the module report)

/** Exploitation evidence across every CVE an advisory covers: KEV on any, the highest EPSS. */
function exploitationFor(a: Advisory, epss: Map<string, { score: number; percentile: number }>, kev: Map<string, { dateAdded: string; ransomware: boolean }>): Pick<Finding, 'epss' | 'kev'> {
  const ids = a.cves?.length ? a.cves : a.cve ? [a.cve] : [];
  let best: Finding['epss'];
  let hit: Finding['kev'];
  for (const cve of ids) {
    const e = epss.get(cve);
    if (e && (!best || e.score > best.score)) best = { score: e.score, percentile: e.percentile, cve };
    const k = kev.get(cve);
    if (k && !hit) hit = { dateAdded: k.dateAdded, ransomware: k.ransomware, cve };
  }
  return { epss: best, kev: hit };
}

/**
 * Re-run the decision step over a stored report with the cache's current EPSS and KEV data.
 * Same logic as redecide() in server.ts; the server may pass its own through `redecide` instead.
 */
export async function redecideReport(report: ScanReport, cachePath = defaultCachePath(), log: (msg: string) => void = () => {}): Promise<ChangedFinding[]> {
  const cves = [...new Set(report.findings.flatMap((f) => (f.advisory.cves?.length ? f.advisory.cves : f.advisory.cve ? [f.advisory.cve] : [])))];
  const cache = new Cache(cachePath);
  try {
    let epss: Awaited<ReturnType<typeof fetchEpss>>;
    let kev: Awaited<ReturnType<typeof fetchKev>>;
    try {
      [epss, kev] = await Promise.all([fetchEpss(cves, cache, false), fetchKev(cache, false)]);
    } catch (err) {
      // No network: the cached data, expired or not, is the freshest there is.
      log(`redecide: using cached EPSS/KEV (${err instanceof Error ? err.message : String(err)})`);
      [epss, kev] = await Promise.all([fetchEpss(cves, cache, true), fetchKev(cache, true)]);
    }
    const changed: ChangedFinding[] = [];
    for (const f of report.findings) {
      const partial = { id: f.id, component: f.component, advisory: f.advisory, symbols: f.symbols, reach: f.reach, exposure: f.exposure, ...exploitationFor(f.advisory, epss, kev) };
      const next: Finding = { ...partial, ...decide(partial) };
      if (next.decision === f.decision) continue;
      changed.push({ finding: next, from: f.decision, to: next.decision, reasons: changeReasons(f, next) });
    }
    return changed;
  } finally {
    cache.close();
  }
}

// ---------------------------------------------------------------------------------------------
// Pure due-logic

export interface DueTarget {
  id: number;
  everyHours: number;
  lastScanAt: string | null;
}

/** Targets with a schedule whose last scan is older than it (or that were never scanned). */
export function dueTargets(db: DatabaseSync, nowMs = Date.now()): DueTarget[] {
  const rows = db
    .prepare(
      `SELECT t.id, t.schedule_hours, (SELECT MAX(created_at) FROM scans WHERE target_id = t.id) AS last_scan_at
       FROM targets t WHERE t.schedule_hours IS NOT NULL AND t.schedule_hours > 0 ORDER BY t.id`,
    )
    .all() as { id: number; schedule_hours: number; last_scan_at: string | null }[];
  return rows
    .filter((r) => !r.last_scan_at || Date.parse(r.last_scan_at) + r.schedule_hours * HOUR_MS <= nowMs)
    .map((r) => ({ id: r.id, everyHours: r.schedule_hours, lastScanAt: r.last_scan_at }));
}

/** `HH:MM` → minutes after local midnight; falls back to 03:00 on bad input. */
export function parseClock(value: string | undefined): number {
  const m = /^(\d{1,2}):(\d{2})$/.exec((value ?? '').trim());
  if (!m) return 3 * 60;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (h > 23 || min > 59) return 3 * 60;
  return h * 60 + min;
}

/** The most recent local-time instant at `minutesAfterMidnight` that is not after `nowMs`. */
export function lastOccurrence(nowMs: number, minutesAfterMidnight: number): number {
  const d = new Date(nowMs);
  d.setHours(Math.floor(minutesAfterMidnight / 60), minutesAfterMidnight % 60, 0, 0);
  if (d.getTime() > nowMs) d.setDate(d.getDate() - 1);
  return d.getTime();
}

/** The nightly pass is due once per day, when its clock time has passed and the last run predates it. */
export function isNightlyDue(lastRunAt: string | null | undefined, nowMs: number, at: string = process.env.NEXTFIX_REDECIDE_AT ?? DEFAULT_REDECIDE_AT): boolean {
  const scheduled = lastOccurrence(nowMs, parseClock(at));
  const last = lastRunAt ? Date.parse(lastRunAt) : Number.NEGATIVE_INFINITY;
  return last < scheduled;
}

export interface RedecideEvent {
  id: number;
  targetId: number;
  findingId: string;
  scanId: number | null;
  from: Decision;
  to: Decision;
  reasons: string[];
  at: string;
  /** True when the decision moved towards Act. */
  promoted: boolean;
}

export function recordRedecideEvents(db: DatabaseSync, targetId: number, scanId: number | null, changed: ChangedFinding[], at: string): number {
  const ins = db.prepare('INSERT INTO redecide_events (target_id, finding_id, scan_id, from_decision, to_decision, reasons, at) VALUES (?, ?, ?, ?, ?, ?, ?)');
  for (const c of changed) ins.run(targetId, c.finding.id, scanId, c.from, c.to, JSON.stringify(c.reasons), at);
  return changed.length;
}

export function listRedecideEvents(db: DatabaseSync, targetId: number, since?: string): RedecideEvent[] {
  const sql = 'SELECT id, target_id, finding_id, scan_id, from_decision, to_decision, reasons, at FROM redecide_events WHERE target_id = ?' + (since ? ' AND at >= ?' : '') + ' ORDER BY at DESC, id DESC';
  const rows = (since ? db.prepare(sql).all(targetId, since) : db.prepare(sql).all(targetId)) as { id: number; target_id: number; finding_id: string; scan_id: number | null; from_decision: string; to_decision: string; reasons: string; at: string }[];
  return rows.map((r) => {
    const from = r.from_decision as Decision;
    const to = r.to_decision as Decision;
    let reasons: string[] = [];
    try {
      reasons = JSON.parse(r.reasons) as string[];
    } catch {
      reasons = [];
    }
    return { id: r.id, targetId: r.target_id, findingId: r.finding_id, scanId: r.scan_id, from, to, reasons, at: r.at, promoted: DECISION_ORDER.indexOf(to) < DECISION_ORDER.indexOf(from) };
  });
}

/**
 * Re-decide every scanned target and record what changed (both directions; the digest picks the
 * promotions). The stored reports are left as they are, like the POST /redecide route.
 */
export async function runRedecideAll(db: DatabaseSync, redecide: Redecide, now = new Date().toISOString(), log: (msg: string) => void = () => {}): Promise<{ targets: number; changed: number }> {
  const targets = db.prepare('SELECT id FROM targets ORDER BY id').all() as { id: number }[];
  let changedTotal = 0;
  let scanned = 0;
  for (const t of targets) {
    const latest = latestReport(db, t.id);
    if (!latest) continue;
    scanned++;
    try {
      const changed = await redecide(latest.report);
      changedTotal += recordRedecideEvents(db, t.id, latest.scanId, changed, now);
      if (changed.length) log(`redecide: target ${t.id}: ${changed.length} decision${changed.length === 1 ? '' : 's'} changed`);
    } catch (err) {
      log(`redecide: target ${t.id} failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { targets: scanned, changed: changedTotal };
}

function getSetting(db: DatabaseSync, key: string): string | undefined {
  const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
  if (!r) return undefined;
  try {
    const v = JSON.parse(r.value) as unknown;
    return typeof v === 'string' ? v : r.value;
  } catch {
    return r.value;
  }
}

function setSetting(db: DatabaseSync, key: string, value: string): void {
  db.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').run(key, JSON.stringify(value), new Date().toISOString());
}

// ---------------------------------------------------------------------------------------------
// The scheduler

export function startScheduler(opts: SchedulerOptions): Scheduler {
  const log = opts.log ?? (() => {});
  const now = opts.now ?? Date.now;
  const redecide: Redecide = opts.redecide ?? ((report) => redecideReport(report, opts.cachePath, log));
  const redecideAt = opts.redecideAt ?? process.env.NEXTFIX_REDECIDE_AT ?? DEFAULT_REDECIDE_AT;
  let busy = false;
  let stopped = false;

  async function tick(nowMs = now()): Promise<TickResult> {
    const result: TickResult = { scanned: [], redecided: false, digestSent: false, errors: [] };
    if (busy || stopped) return result;
    busy = true;
    const iso = new Date(nowMs).toISOString();
    try {
      try {
        expireExceptions(opts.db, iso);
      } catch (err) {
        result.errors.push(`expire: ${err instanceof Error ? err.message : String(err)}`);
      }
      // Scheduled scans, one at a time: the server's scan lock refuses a second one anyway.
      for (const t of dueTargets(opts.db, nowMs)) {
        if (stopped) break;
        try {
          log(`schedule: scanning target ${t.id} (every ${t.everyHours} h)`);
          await opts.runScan(t.id);
          result.scanned.push(t.id);
        } catch (err) {
          const msg = `schedule: scan of target ${t.id} failed: ${err instanceof Error ? err.message : String(err)}`;
          log(msg);
          result.errors.push(msg);
        }
      }
      // Nightly re-decide.
      if (!stopped && isNightlyDue(getSetting(opts.db, REDECIDE_LAST_RUN_KEY), nowMs, redecideAt)) {
        setSetting(opts.db, REDECIDE_LAST_RUN_KEY, iso);
        try {
          const r = await runRedecideAll(opts.db, redecide, iso, log);
          log(`redecide: nightly pass over ${r.targets} target${r.targets === 1 ? '' : 's'}, ${r.changed} change${r.changed === 1 ? '' : 's'}`);
          result.redecided = true;
        } catch (err) {
          const msg = `redecide: nightly pass failed: ${err instanceof Error ? err.message : String(err)}`;
          log(msg);
          result.errors.push(msg);
        }
      }
      // Weekly digest.
      if (!stopped && opts.digest !== false) {
        try {
          result.digestSent = await sendDigestIfDue(opts.db, nowMs, log);
        } catch (err) {
          const msg = `digest: ${err instanceof Error ? err.message : String(err)}`;
          log(msg);
          result.errors.push(msg);
        }
      }
    } finally {
      busy = false;
    }
    return result;
  }

  const timer = setInterval(() => {
    tick().catch((err) => log(`schedule: ${err instanceof Error ? err.message : String(err)}`));
  }, opts.tickMs ?? DEFAULT_TICK_MS);
  timer.unref();

  return {
    stop() {
      stopped = true;
      clearInterval(timer);
    },
    tick,
  };
}

export const routes: Route[] = [
  {
    method: 'GET',
    pattern: '/api/targets/:id/redecide-events',
    role: 'viewer',
    handler({ db, params, query }) {
      const id = Number(params.id);
      if (!Number.isInteger(id) || id < 1) throw new FeatureError(400, 'Bad target id');
      if (!targetExists(db, id)) throw new FeatureError(404, 'Target not found');
      const since = query.since?.trim();
      if (since && !Number.isFinite(Date.parse(since))) throw new FeatureError(400, 'since must be an ISO timestamp');
      return { body: listRedecideEvents(db, id, since ? new Date(since).toISOString() : undefined) };
    },
  },
];
