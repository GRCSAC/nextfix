import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { dirname, join } from 'node:path';
import type { Decision, ReachTier, ScanReport, ScanSummary } from '../../engine/src/types.ts';

export interface TargetRow {
  id: number;
  dir: string;
  name: string | null;
  createdAt: string;
}

export interface ScanRow {
  id: number;
  targetId: number;
  createdAt: string;
  toolVersion: string;
  summary: ScanSummary;
}

export interface LockRow {
  name: string;
  pid: number;
  host: string;
  port: number;
  since: string;
  heartbeatAt: string;
}

export interface OtherServer {
  pid: number;
  port: number;
  since: string;
}

/** One finding's life across scans of a target. */
export interface HistoryRow {
  targetId: number;
  findingId: string;
  firstSeenAt: string;
  lastSeenAt: string;
  firstScanId: number;
  lastScanId: number;
  resolvedAt: string | null;
  resolvedScanId: number | null;
  decisionLatest: Decision;
}

export type AgeBucket = '0-7' | '8-30' | '31-90' | '90+';
export const AGE_BUCKETS: AgeBucket[] = ['0-7', '8-30', '31-90', '90+'];

export interface HistorySummary {
  rows: HistoryRow[];
  /** Open findings per decision, split by days since first seen. */
  open: Record<Decision, Record<AgeBucket, number>>;
  /** Open findings older than the decision's SLA (Act and Attend have one). */
  pastSla: Record<Decision, number>;
  sla: { slaActDays: number; slaAttendDays: number };
  /** Median days from first seen to resolved, over findings resolved in the last 90 days; null when none. */
  medianDaysToResolve: number | null;
  resolvedLast30: number;
  introducedLast30: number;
  /** Finding id → first_seen_at, for the current report's rows. */
  firstSeen: Record<string, string>;
  computedAt: string;
}

/** Keys the settings table knows, with their defaults. */
export const SETTING_DEFAULTS = { slaActDays: 7, slaAttendDays: 30, retentionScans: 50 } as const;
export type SettingKey = keyof typeof SETTING_DEFAULTS;
export type Settings = { [K in SettingKey]: number };
export const SETTING_KEYS = Object.keys(SETTING_DEFAULTS) as SettingKey[];

export interface StoreOptions {
  /** Owner of the rows this process writes to `locks`; defaults to process.pid. */
  pid?: number;
}

/** A lock row whose heartbeat is older than this belongs to a process that is gone. */
export const LOCK_STALE_MS = 60_000;

export function defaultDbPath(): string {
  return join(homedir(), '.nextfix', 'nextfix.sqlite');
}

/**
 * Schema versions, applied in order and recorded in PRAGMA user_version. Every statement is
 * idempotent so a database created before versioning existed (user_version 0) migrates cleanly.
 */
const MIGRATIONS: string[] = [
  // 1: targets, scans, integrations, tickets and the locks table.
  `
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY,
      dir TEXT NOT NULL UNIQUE,
      name TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY,
      target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      tool_version TEXT NOT NULL,
      summary TEXT NOT NULL,
      report TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS scans_target ON scans(target_id, created_at);
    CREATE TABLE IF NOT EXISTS integrations (
      kind TEXT PRIMARY KEY,
      config TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tickets (
      target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      key TEXT NOT NULL,
      url TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (target_id, finding_id, kind)
    );
    CREATE TABLE IF NOT EXISTS locks (
      name TEXT NOT NULL,
      pid INTEGER NOT NULL,
      host TEXT NOT NULL,
      port INTEGER NOT NULL,
      since TEXT NOT NULL,
      heartbeat_at TEXT NOT NULL,
      PRIMARY KEY (name, pid)
    );
  `,
  // 2: finding history across scans, and a key/value settings table. Existing scans are
  // walked oldest to newest right after this version is applied (see migrate()).
  `
    CREATE TABLE IF NOT EXISTS finding_history (
      target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      first_scan_id INTEGER NOT NULL,
      last_scan_id INTEGER NOT NULL,
      resolved_at TEXT,
      resolved_scan_id INTEGER,
      decision_latest TEXT NOT NULL,
      PRIMARY KEY (target_id, finding_id)
    );
    CREATE INDEX IF NOT EXISTS finding_history_open ON finding_history(target_id, resolved_at);
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `,
];

/** Versions whose arrival needs a data pass as well as the DDL above. */
const HISTORY_VERSION = 2;

const DECISION_ZERO: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
const TIER_ZERO: Record<ReachTier, number> = { reachable: 0, 'called-unreached': 0, 'imported-unknown-symbol': 0, 'image-only': 0, 'imported-not-called': 0, unused: 0, 'dev-only': 0 };
const DAY_MS = 86_400_000;

/** Reports written by older versions lack keys added since (for example `image-only` before 0.8). */
export function normalizeSummary(summary: Partial<ScanSummary> | undefined): ScanSummary {
  const s = summary ?? {};
  return {
    components: s.components ?? 0,
    advisories: s.advisories ?? 0,
    findings: s.findings ?? 0,
    byDecision: { ...DECISION_ZERO, ...(s.byDecision ?? {}) },
    byTier: { ...TIER_ZERO, ...(s.byTier ?? {}) },
    noiseRemoved: s.noiseRemoved ?? 0,
  };
}

/** Days between two ISO timestamps, never negative. */
function daysBetween(fromIso: string, toMs: number): number {
  return Math.max(0, (toMs - Date.parse(fromIso)) / DAY_MS);
}

export function ageBucket(days: number): AgeBucket {
  if (days <= 7) return '0-7';
  if (days <= 30) return '8-30';
  if (days <= 90) return '31-90';
  return '90+';
}

interface RawScan {
  id: number;
  target_id: number;
  created_at: string;
  tool_version: string;
  summary: string;
}

interface RawHistory {
  target_id: number;
  finding_id: string;
  first_seen_at: string;
  last_seen_at: string;
  first_scan_id: number;
  last_scan_id: number;
  resolved_at: string | null;
  resolved_scan_id: number | null;
  decision_latest: string;
}

/** Scan history. One row per scan, full report kept as JSON so the UI can replay any scan. */
export class Store {
  private db: DatabaseSync;
  readonly path: string;
  readonly pid: number;

  constructor(path = defaultDbPath(), options: StoreOptions = {}) {
    mkdirSync(dirname(path), { recursive: true });
    this.path = path;
    this.pid = options.pid ?? process.pid;
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA foreign_keys = ON');
    this.migrate();
  }

  private migrate(): void {
    const row = this.db.prepare('PRAGMA user_version').get() as { user_version: number };
    for (let v = row.user_version; v < MIGRATIONS.length; v++) {
      this.transaction(() => {
        this.db.exec(MIGRATIONS[v]!);
        if (v + 1 === HISTORY_VERSION) this.backfillHistory();
        this.db.exec(`PRAGMA user_version = ${v + 1}`);
      });
    }
  }

  /** Run `fn` inside one transaction; nested calls join the outer one. */
  private inTransaction = false;
  private transaction<T>(fn: () => T): T {
    if (this.inTransaction) return fn();
    this.inTransaction = true;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    } finally {
      this.inTransaction = false;
    }
  }

  get schemaVersion(): number {
    return (this.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  }

  // ---- locks: one database may be opened by several servers ----

  private staleBefore(): string {
    return new Date(Date.now() - LOCK_STALE_MS).toISOString();
  }

  private rowToLock(r: { name: string; pid: number; host: string; port: number; since: string; heartbeat_at: string }): LockRow {
    return { name: r.name, pid: r.pid, host: r.host, port: r.port, since: r.since, heartbeatAt: r.heartbeat_at };
  }

  /** Live lock rows (stale ones are dropped first). */
  listLocks(name?: string): LockRow[] {
    this.db.prepare('DELETE FROM locks WHERE heartbeat_at < ?').run(this.staleBefore());
    const sql = 'SELECT name, pid, host, port, since, heartbeat_at FROM locks' + (name ? ' WHERE name = ?' : '') + ' ORDER BY since';
    const rows = (name ? this.db.prepare(sql).all(name) : this.db.prepare(sql).all()) as { name: string; pid: number; host: string; port: number; since: string; heartbeat_at: string }[];
    return rows.map((r) => this.rowToLock(r));
  }

  /** Record this process as a running server and report another live server on the same database, if any. */
  acquireServerLock(host: string, port: number): OtherServer | undefined {
    const now = new Date().toISOString();
    this.db
      .prepare('INSERT INTO locks (name, pid, host, port, since, heartbeat_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(name, pid) DO UPDATE SET host = excluded.host, port = excluded.port, heartbeat_at = excluded.heartbeat_at')
      .run('server', this.pid, host, port, now, now);
    return this.otherServer();
  }

  /** Another live server (different pid) using this database. */
  otherServer(): OtherServer | undefined {
    const other = this.listLocks('server').find((l) => l.pid !== this.pid);
    return other ? { pid: other.pid, port: other.port, since: other.since } : undefined;
  }

  /** Keep this process's lock rows fresh; call every 20 s or so. */
  heartbeat(): void {
    this.db.prepare('UPDATE locks SET heartbeat_at = ? WHERE pid = ?').run(new Date().toISOString(), this.pid);
  }

  /** Drop every lock row this process holds. */
  releaseLocks(): void {
    this.db.prepare('DELETE FROM locks WHERE pid = ?').run(this.pid);
  }

  /** True while any live process has the scan lock. */
  scanInProgress(): boolean {
    return this.listLocks('scan').length > 0;
  }

  /** The live scan lock, if one is held. */
  currentScan(): LockRow | undefined {
    return this.listLocks('scan')[0];
  }

  /** Take the scan lock. Returns false when a live process (this one included) already holds it. */
  beginScan(host = hostname(), port = 0): boolean {
    this.db.prepare('DELETE FROM locks WHERE name = ? AND heartbeat_at < ?').run('scan', this.staleBefore());
    const now = new Date().toISOString();
    const res = this.db
      .prepare("INSERT INTO locks (name, pid, host, port, since, heartbeat_at) SELECT 'scan', ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM locks WHERE name = 'scan')")
      .run(this.pid, host, port, now, now);
    return Number(res.changes) === 1;
  }

  endScan(): void {
    this.db.prepare('DELETE FROM locks WHERE name = ? AND pid = ?').run('scan', this.pid);
  }

  // ---- settings (numbers only so far: SLA days and scan retention) ----

  getSettings(): Settings {
    const out = { ...SETTING_DEFAULTS } as Settings;
    const rows = this.db.prepare('SELECT key, value FROM settings').all() as { key: string; value: string }[];
    for (const r of rows) {
      if (!(r.key in SETTING_DEFAULTS)) continue;
      const n = Number(r.value);
      if (Number.isFinite(n)) out[r.key as SettingKey] = n;
    }
    return out;
  }

  setSetting(key: SettingKey, value: number): void {
    this.db.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').run(key, String(value), new Date().toISOString());
  }

  // ---- integrations (tracker credentials live only in this local database) ----
  getIntegration<T>(kind: string): T | undefined {
    const r = this.db.prepare('SELECT config FROM integrations WHERE kind = ?').get(kind) as { config: string } | undefined;
    return r ? (JSON.parse(r.config) as T) : undefined;
  }

  setIntegration(kind: string, config: unknown): void {
    this.db.prepare('INSERT INTO integrations (kind, config, updated_at) VALUES (?, ?, ?) ON CONFLICT(kind) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at').run(kind, JSON.stringify(config), new Date().toISOString());
  }

  deleteIntegration(kind: string): void {
    this.db.prepare('DELETE FROM integrations WHERE kind = ?').run(kind);
  }

  // ---- tickets created for findings ----
  listTickets(targetId: number): Record<string, { kind: string; key: string; url: string; createdAt: string }[]> {
    const rows = this.db.prepare('SELECT finding_id, kind, key, url, created_at FROM tickets WHERE target_id = ? ORDER BY created_at').all(targetId) as { finding_id: string; kind: string; key: string; url: string; created_at: string }[];
    const out: Record<string, { kind: string; key: string; url: string; createdAt: string }[]> = {};
    for (const r of rows) (out[r.finding_id] ??= []).push({ kind: r.kind, key: r.key, url: r.url, createdAt: r.created_at });
    return out;
  }

  addTicket(targetId: number, findingId: string, kind: string, key: string, url: string): void {
    this.db.prepare('INSERT OR REPLACE INTO tickets (target_id, finding_id, kind, key, url, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(targetId, findingId, kind, key, url, new Date().toISOString());
  }

  // ---- targets ----

  /** Every target with its newest scan, in one query. */
  listTargets(): (TargetRow & { lastScan?: ScanRow })[] {
    const rows = this.db
      .prepare(
        `SELECT t.id, t.dir, t.name, t.created_at,
                s.id AS scan_id, s.created_at AS scan_created_at, s.tool_version, s.summary
         FROM targets t
         LEFT JOIN scans s ON s.id = (SELECT id FROM scans WHERE target_id = t.id ORDER BY created_at DESC, id DESC LIMIT 1)
         ORDER BY t.name, t.dir`,
      )
      .all() as { id: number; dir: string; name: string | null; created_at: string; scan_id: number | null; scan_created_at: string | null; tool_version: string | null; summary: string | null }[];
    return rows.map((r) => {
      const t: TargetRow & { lastScan?: ScanRow } = { id: r.id, dir: r.dir, name: r.name, createdAt: r.created_at };
      if (r.scan_id !== null) t.lastScan = this.rowToScan({ id: r.scan_id, target_id: r.id, created_at: r.scan_created_at!, tool_version: r.tool_version!, summary: r.summary! });
      return t;
    });
  }

  getTarget(id: number): TargetRow | undefined {
    const r = this.db.prepare('SELECT id, dir, name, created_at FROM targets WHERE id = ?').get(id) as { id: number; dir: string; name: string | null; created_at: string } | undefined;
    return r ? { id: r.id, dir: r.dir, name: r.name, createdAt: r.created_at } : undefined;
  }

  upsertTarget(dir: string, name?: string): TargetRow {
    const existing = this.db.prepare('SELECT id FROM targets WHERE dir = ?').get(dir) as { id: number } | undefined;
    if (existing) {
      if (name) this.db.prepare('UPDATE targets SET name = ? WHERE id = ?').run(name, existing.id);
      return this.getTarget(existing.id)!;
    }
    const createdAt = new Date().toISOString();
    const res = this.db.prepare('INSERT INTO targets (dir, name, created_at) VALUES (?, ?, ?)').run(dir, name ?? null, createdAt);
    return { id: Number(res.lastInsertRowid), dir, name: name ?? null, createdAt };
  }

  /** Remove a target and everything hanging off it (scans, tickets, history) in one transaction. */
  deleteTarget(id: number): void {
    this.transaction(() => {
      this.db.prepare('DELETE FROM scans WHERE target_id = ?').run(id);
      this.db.prepare('DELETE FROM tickets WHERE target_id = ?').run(id);
      this.db.prepare('DELETE FROM finding_history WHERE target_id = ?').run(id);
      this.db.prepare('DELETE FROM targets WHERE id = ?').run(id);
    });
  }

  // ---- scans ----

  /** Store a report, roll the finding history forward and prune scans beyond the retention setting; one transaction. */
  addScan(targetId: number, report: ScanReport): ScanRow {
    return this.transaction(() => {
      const res = this.db
        .prepare('INSERT INTO scans (target_id, created_at, tool_version, summary, report) VALUES (?, ?, ?, ?, ?)')
        .run(targetId, report.generatedAt, report.tool.version, JSON.stringify(report.summary), JSON.stringify(report));
      const scanId = Number(res.lastInsertRowid);
      if (report.target.name) this.db.prepare('UPDATE targets SET name = ? WHERE id = ?').run(report.target.name, targetId);
      this.rollHistory(targetId, scanId, report);
      this.pruneScans(targetId, this.getSettings().retentionScans);
      return { id: scanId, targetId, createdAt: report.generatedAt, toolVersion: report.tool.version, summary: normalizeSummary(report.summary) };
    });
  }

  /** Keep only the newest `keep` scans of a target. */
  private pruneScans(targetId: number, keep: number): void {
    if (!Number.isFinite(keep) || keep < 1) return;
    this.db
      .prepare('DELETE FROM scans WHERE target_id = ? AND id NOT IN (SELECT id FROM scans WHERE target_id = ? ORDER BY created_at DESC, id DESC LIMIT ?)')
      .run(targetId, targetId, Math.floor(keep));
  }

  /**
   * Apply one scan to the finding history: unseen ids are inserted, seen ids updated (and
   * un-resolved if they had been resolved), open ids missing from this scan are resolved.
   */
  private rollHistory(targetId: number, scanId: number, report: ScanReport): void {
    const at = report.generatedAt;
    const upsert = this.db.prepare(
      `INSERT INTO finding_history (target_id, finding_id, first_seen_at, last_seen_at, first_scan_id, last_scan_id, resolved_at, resolved_scan_id, decision_latest)
       VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)
       ON CONFLICT(target_id, finding_id) DO UPDATE SET last_seen_at = excluded.last_seen_at, last_scan_id = excluded.last_scan_id, resolved_at = NULL, resolved_scan_id = NULL, decision_latest = excluded.decision_latest`,
    );
    const seen = new Set<string>();
    for (const f of report.findings) {
      if (seen.has(f.id)) continue;
      seen.add(f.id);
      upsert.run(targetId, f.id, at, at, scanId, scanId, f.decision);
    }
    const open = this.db.prepare('SELECT finding_id FROM finding_history WHERE target_id = ? AND resolved_at IS NULL').all(targetId) as { finding_id: string }[];
    const resolve = this.db.prepare('UPDATE finding_history SET resolved_at = ?, resolved_scan_id = ? WHERE target_id = ? AND finding_id = ?');
    for (const r of open) if (!seen.has(r.finding_id)) resolve.run(at, scanId, targetId, r.finding_id);
  }

  /** Rebuild the history table from the stored reports, oldest scan first. */
  private backfillHistory(): void {
    this.db.exec('DELETE FROM finding_history');
    const scans = this.db.prepare('SELECT id, target_id, report FROM scans ORDER BY created_at, id').all() as { id: number; target_id: number; report: string }[];
    for (const s of scans) {
      let report: ScanReport;
      try {
        report = JSON.parse(s.report) as ScanReport;
      } catch {
        continue;
      }
      if (!Array.isArray(report.findings)) continue;
      this.rollHistory(s.target_id, s.id, report);
    }
  }

  private rowToHistory(r: RawHistory): HistoryRow {
    return {
      targetId: r.target_id,
      findingId: r.finding_id,
      firstSeenAt: r.first_seen_at,
      lastSeenAt: r.last_seen_at,
      firstScanId: r.first_scan_id,
      lastScanId: r.last_scan_id,
      resolvedAt: r.resolved_at,
      resolvedScanId: r.resolved_scan_id,
      decisionLatest: r.decision_latest as Decision,
    };
  }

  listHistory(targetId: number): HistoryRow[] {
    const rows = this.db.prepare('SELECT * FROM finding_history WHERE target_id = ? ORDER BY first_seen_at, finding_id').all(targetId) as unknown as RawHistory[];
    return rows.map((r) => this.rowToHistory(r));
  }

  /** first_seen_at for every finding of a target that is still open. */
  firstSeenMap(targetId: number): Record<string, string> {
    const rows = this.db.prepare('SELECT finding_id, first_seen_at FROM finding_history WHERE target_id = ? AND resolved_at IS NULL').all(targetId) as { finding_id: string; first_seen_at: string }[];
    const out: Record<string, string> = {};
    for (const r of rows) out[r.finding_id] = r.first_seen_at;
    return out;
  }

  /** History rows plus the derived numbers the dashboards show. */
  historySummary(targetId: number, now = Date.now()): HistorySummary {
    const rows = this.listHistory(targetId);
    const settings = this.getSettings();
    const slaFor: Partial<Record<Decision, number>> = { Act: settings.slaActDays, Attend: settings.slaAttendDays };
    const bucketZero = (): Record<AgeBucket, number> => ({ '0-7': 0, '8-30': 0, '31-90': 0, '90+': 0 });
    const open: HistorySummary['open'] = { Act: bucketZero(), Attend: bucketZero(), 'Track*': bucketZero(), Track: bucketZero() };
    const pastSla: Record<Decision, number> = { ...DECISION_ZERO };
    const firstSeen: Record<string, string> = {};
    const resolveDays: number[] = [];
    let resolvedLast30 = 0;
    let introducedLast30 = 0;
    for (const r of rows) {
      const decision = r.decisionLatest in open ? r.decisionLatest : 'Track';
      if (daysBetween(r.firstSeenAt, now) <= 30) introducedLast30++;
      if (r.resolvedAt === null) {
        const age = daysBetween(r.firstSeenAt, now);
        open[decision][ageBucket(age)]++;
        const sla = slaFor[decision];
        if (sla !== undefined && age > sla) pastSla[decision]++;
        firstSeen[r.findingId] = r.firstSeenAt;
      } else {
        const since = daysBetween(r.resolvedAt, now);
        if (since <= 30) resolvedLast30++;
        if (since <= 90) resolveDays.push(Math.max(0, (Date.parse(r.resolvedAt) - Date.parse(r.firstSeenAt)) / DAY_MS));
      }
    }
    resolveDays.sort((a, b) => a - b);
    let median: number | null = null;
    if (resolveDays.length) {
      const mid = resolveDays.length >> 1;
      median = resolveDays.length % 2 ? resolveDays[mid]! : (resolveDays[mid - 1]! + resolveDays[mid]!) / 2;
      median = Math.round(median * 10) / 10;
    }
    return {
      rows,
      open,
      pastSla,
      sla: { slaActDays: settings.slaActDays, slaAttendDays: settings.slaAttendDays },
      medianDaysToResolve: median,
      resolvedLast30,
      introducedLast30,
      firstSeen,
      computedAt: new Date(now).toISOString(),
    };
  }

  private rowToScan(r: RawScan): ScanRow {
    return { id: r.id, targetId: r.target_id, createdAt: r.created_at, toolVersion: r.tool_version, summary: normalizeSummary(JSON.parse(r.summary) as Partial<ScanSummary>) };
  }

  listScans(targetId: number): ScanRow[] {
    const rows = this.db.prepare('SELECT id, target_id, created_at, tool_version, summary FROM scans WHERE target_id = ? ORDER BY created_at, id').all(targetId) as unknown as RawScan[];
    return rows.map((r) => this.rowToScan(r));
  }

  getScan(id: number): ScanRow | undefined {
    const r = this.db.prepare('SELECT id, target_id, created_at, tool_version, summary FROM scans WHERE id = ?').get(id) as RawScan | undefined;
    return r ? this.rowToScan(r) : undefined;
  }

  getReport(id: number): ScanReport | undefined {
    const r = this.db.prepare('SELECT report FROM scans WHERE id = ?').get(id) as { report: string } | undefined;
    if (!r) return undefined;
    const report = JSON.parse(r.report) as ScanReport;
    report.summary = normalizeSummary(report.summary);
    return report;
  }

  /** The newest scan of a target. */
  latestScan(targetId: number): ScanRow | undefined {
    const r = this.db.prepare('SELECT id, target_id, created_at, tool_version, summary FROM scans WHERE target_id = ? ORDER BY created_at DESC, id DESC LIMIT 1').get(targetId) as RawScan | undefined;
    return r ? this.rowToScan(r) : undefined;
  }

  previousScan(scan: ScanRow): ScanRow | undefined {
    const r = this.db
      .prepare('SELECT id, target_id, created_at, tool_version, summary FROM scans WHERE target_id = ? AND (created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT 1')
      .get(scan.targetId, scan.createdAt, scan.createdAt, scan.id) as RawScan | undefined;
    return r ? this.rowToScan(r) : undefined;
  }

  close(): void {
    this.db.close();
  }
}
