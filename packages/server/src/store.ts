import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join } from 'node:path';
import type { Decision, ReachTier, ScanReport, ScanSummary } from '../../engine/src/types.ts';
import { featureMigrations } from './features/all.ts';
import { nextfixHome } from '../../engine/src/home.ts';

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
  return join(nextfixHome(), 'nextfix.sqlite');
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
  // 3: accounts, sessions, API tokens, login throttling and the audit log.
  `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL,
      password_hash TEXT,
      disabled INTEGER NOT NULL DEFAULT 0,
      source TEXT NOT NULL DEFAULT 'local',
      oidc_provider TEXT,
      oidc_sub TEXT,
      created_at TEXT NOT NULL,
      last_login_at TEXT
    );
    CREATE INDEX IF NOT EXISTS users_oidc ON users(oidc_provider, oidc_sub);
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT
    );
    CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS api_tokens (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      scopes TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_used_at TEXT,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS login_failures (
      username TEXT NOT NULL COLLATE NOCASE,
      at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS login_failures_user ON login_failures(username, at);
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY,
      at TEXT NOT NULL,
      user_id INTEGER,
      username TEXT,
      action TEXT NOT NULL,
      target TEXT,
      detail TEXT,
      ip TEXT
    );
  `,
  // 4–7: exceptions, target owner and schedule, re-decide events, digest log (features/*.ts).
  ...featureMigrations(),
];

export type Role = 'admin' | 'analyst' | 'viewer';
export type UserSource = 'local' | 'oidc';

export interface UserRow {
  id: number;
  username: string;
  displayName: string;
  role: Role;
  disabled: boolean;
  source: UserSource;
  createdAt: string;
  lastLoginAt: string | null;
}

/** A user row plus the columns only the auth code reads. */
export interface UserRecord extends UserRow {
  passwordHash: string | null;
  oidcProvider: string | null;
  oidcSub: string | null;
}

export interface SessionRow {
  id: string;
  userId: number;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ip: string | null;
  userAgent: string | null;
}

export interface TokenRow {
  id: number;
  name: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt: string | null;
  createdBy: number | null;
}

export interface AuditRow {
  id: number;
  at: string;
  userId: number | null;
  username: string | null;
  action: string;
  target: string | null;
  detail: unknown;
  ip: string | null;
}

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
        try {
          this.db.exec(MIGRATIONS[v]!);
        } catch (err) {
          // A column added by an earlier, lazily applied feature migration is already there.
          if (!/duplicate column name/i.test(err instanceof Error ? err.message : String(err))) throw err;
        }
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

  // ---- free-form settings (JSON values beside the numeric keys above) ----

  getJsonSetting<T>(key: string): T | undefined {
    const r = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
    if (!r) return undefined;
    try {
      return JSON.parse(r.value) as T;
    } catch {
      return undefined;
    }
  }

  setJsonSetting(key: string, value: unknown): void {
    this.db.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').run(key, JSON.stringify(value), new Date().toISOString());
  }

  /** A random secret shared by every server on this database (signs the short-lived OIDC cookie). Created on first use. */
  authSecret(): Buffer {
    const existing = this.getJsonSetting<string>('auth_secret');
    if (existing) return Buffer.from(existing, 'hex');
    const secret = randomBytes(32).toString('hex');
    this.setJsonSetting('auth_secret', secret);
    return Buffer.from(secret, 'hex');
  }

  // ---- users ----

  private rowToUser(r: RawUser): UserRecord {
    return {
      id: r.id,
      username: r.username,
      displayName: r.display_name,
      role: r.role as Role,
      disabled: r.disabled === 1,
      source: r.source as UserSource,
      createdAt: r.created_at,
      lastLoginAt: r.last_login_at,
      passwordHash: r.password_hash,
      oidcProvider: r.oidc_provider,
      oidcSub: r.oidc_sub,
    };
  }

  /** The public shape of a user: no hash, no provider ids. */
  static publicUser(u: UserRecord): UserRow {
    return { id: u.id, username: u.username, displayName: u.displayName, role: u.role, disabled: u.disabled, source: u.source, createdAt: u.createdAt, lastLoginAt: u.lastLoginAt };
  }

  countUsers(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
  }

  countEnabledAdmins(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0").get() as { n: number }).n;
  }

  listUsers(): UserRow[] {
    const rows = this.db.prepare(`SELECT ${USER_COLUMNS} FROM users ORDER BY username`).all() as unknown as RawUser[];
    return rows.map((r) => Store.publicUser(this.rowToUser(r)));
  }

  getUser(id: number): UserRecord | undefined {
    const r = this.db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).get(id) as RawUser | undefined;
    return r ? this.rowToUser(r) : undefined;
  }

  getUserByUsername(username: string): UserRecord | undefined {
    const r = this.db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE username = ? COLLATE NOCASE`).get(username) as RawUser | undefined;
    return r ? this.rowToUser(r) : undefined;
  }

  getUserByOidc(provider: string, sub: string): UserRecord | undefined {
    const r = this.db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE oidc_provider = ? AND oidc_sub = ?`).get(provider, sub) as RawUser | undefined;
    return r ? this.rowToUser(r) : undefined;
  }

  createUser(u: { username: string; displayName: string; role: Role; passwordHash?: string | null; source?: UserSource; oidcProvider?: string; oidcSub?: string }): UserRecord {
    const createdAt = new Date().toISOString();
    const res = this.db
      .prepare('INSERT INTO users (username, display_name, role, password_hash, disabled, source, oidc_provider, oidc_sub, created_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)')
      .run(u.username, u.displayName, u.role, u.passwordHash ?? null, u.source ?? 'local', u.oidcProvider ?? null, u.oidcSub ?? null, createdAt);
    return this.getUser(Number(res.lastInsertRowid))!;
  }

  updateUser(id: number, patch: { role?: Role; disabled?: boolean; displayName?: string; oidcProvider?: string; oidcSub?: string }): void {
    const sets: string[] = [];
    const args: (string | number)[] = [];
    if (patch.role !== undefined) { sets.push('role = ?'); args.push(patch.role); }
    if (patch.disabled !== undefined) { sets.push('disabled = ?'); args.push(patch.disabled ? 1 : 0); }
    if (patch.displayName !== undefined) { sets.push('display_name = ?'); args.push(patch.displayName); }
    if (patch.oidcProvider !== undefined) { sets.push('oidc_provider = ?'); args.push(patch.oidcProvider); }
    if (patch.oidcSub !== undefined) { sets.push('oidc_sub = ?'); args.push(patch.oidcSub); }
    if (!sets.length) return;
    args.push(id);
    this.db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...args);
  }

  setPasswordHash(id: number, hash: string): void {
    this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
  }

  touchLogin(id: number): void {
    this.db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(new Date().toISOString(), id);
  }

  deleteUser(id: number): void {
    this.transaction(() => {
      this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
      this.db.prepare('DELETE FROM users WHERE id = ?').run(id);
    });
  }

  // ---- sessions (ids are stored hashed; the cookie holds the original) ----

  createSession(s: { id: string; userId: number; expiresAt: string; ip: string | null; userAgent: string | null }): void {
    const now = new Date().toISOString();
    this.db.prepare('INSERT INTO sessions (id, user_id, created_at, last_seen_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)').run(s.id, s.userId, now, now, s.expiresAt, s.ip, s.userAgent);
  }

  getSession(id: string): SessionRow | undefined {
    const r = this.db.prepare('SELECT id, user_id, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions WHERE id = ?').get(id) as { id: string; user_id: number; created_at: string; last_seen_at: string; expires_at: string; ip: string | null; user_agent: string | null } | undefined;
    return r ? { id: r.id, userId: r.user_id, createdAt: r.created_at, lastSeenAt: r.last_seen_at, expiresAt: r.expires_at, ip: r.ip, userAgent: r.user_agent } : undefined;
  }

  touchSession(id: string, at: string): void {
    this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(at, id);
  }

  deleteSession(id: string): void {
    this.db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
  }

  /** End every session of a user, optionally keeping one (the caller's own). */
  deleteUserSessions(userId: number, except?: string): void {
    if (except) this.db.prepare('DELETE FROM sessions WHERE user_id = ? AND id <> ?').run(userId, except);
    else this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  }

  /** Drop sessions past their absolute expiry or idle for longer than `idleMs`. */
  pruneSessions(idleMs: number, now = Date.now()): void {
    this.db.prepare('DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ?').run(new Date(now).toISOString(), new Date(now - idleMs).toISOString());
  }

  // ---- login throttling ----

  /** Timestamps of failed logins for a username since `since`, newest first. */
  loginFailures(username: string, since: string): string[] {
    this.db.prepare('DELETE FROM login_failures WHERE at < ?').run(since);
    const rows = this.db.prepare('SELECT at FROM login_failures WHERE username = ? COLLATE NOCASE AND at >= ? ORDER BY at DESC').all(username, since) as { at: string }[];
    return rows.map((r) => r.at);
  }

  addLoginFailure(username: string): void {
    this.db.prepare('INSERT INTO login_failures (username, at) VALUES (?, ?)').run(username, new Date().toISOString());
  }

  clearLoginFailures(username: string): void {
    this.db.prepare('DELETE FROM login_failures WHERE username = ? COLLATE NOCASE').run(username);
  }

  // ---- API tokens (stored hashed) ----

  private rowToToken(r: RawToken): TokenRow {
    let scopes: string[] = [];
    try {
      const parsed: unknown = JSON.parse(r.scopes);
      if (Array.isArray(parsed)) scopes = parsed.filter((x): x is string => typeof x === 'string');
    } catch {
      /* an unreadable scope list grants nothing */
    }
    return { id: r.id, name: r.name, scopes, createdAt: r.created_at, lastUsedAt: r.last_used_at, createdBy: r.created_by };
  }

  listTokens(): TokenRow[] {
    const rows = this.db.prepare('SELECT id, name, scopes, created_at, last_used_at, created_by FROM api_tokens ORDER BY created_at, id').all() as unknown as RawToken[];
    return rows.map((r) => this.rowToToken(r));
  }

  createToken(t: { name: string; hash: string; scopes: string[]; createdBy: number | null }): TokenRow {
    const res = this.db.prepare('INSERT INTO api_tokens (name, token_hash, scopes, created_at, created_by) VALUES (?, ?, ?, ?, ?)').run(t.name, t.hash, JSON.stringify(t.scopes), new Date().toISOString(), t.createdBy);
    return this.getToken(Number(res.lastInsertRowid))!;
  }

  getToken(id: number): TokenRow | undefined {
    const r = this.db.prepare('SELECT id, name, scopes, created_at, last_used_at, created_by FROM api_tokens WHERE id = ?').get(id) as RawToken | undefined;
    return r ? this.rowToToken(r) : undefined;
  }

  getTokenByHash(hash: string): TokenRow | undefined {
    const r = this.db.prepare('SELECT id, name, scopes, created_at, last_used_at, created_by FROM api_tokens WHERE token_hash = ?').get(hash) as RawToken | undefined;
    return r ? this.rowToToken(r) : undefined;
  }

  touchToken(id: number, at: string): void {
    this.db.prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').run(at, id);
  }

  deleteToken(id: number): boolean {
    return Number(this.db.prepare('DELETE FROM api_tokens WHERE id = ?').run(id).changes) === 1;
  }

  // ---- audit log ----

  addAudit(row: { userId: number | null; username: string | null; action: string; target: string | null; detail: unknown; ip: string | null }): number {
    const res = this.db
      .prepare('INSERT INTO audit (at, user_id, username, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(new Date().toISOString(), row.userId, row.username, row.action, row.target, row.detail === undefined ? null : JSON.stringify(row.detail), row.ip);
    return Number(res.lastInsertRowid);
  }

  /** Newest rows first; `before` pages backwards by id. */
  listAudit(limit: number, before?: number): AuditRow[] {
    const n = Math.max(1, Math.min(1000, Math.floor(limit)));
    const sql = 'SELECT id, at, user_id, username, action, target, detail, ip FROM audit' + (before !== undefined ? ' WHERE id < ?' : '') + ' ORDER BY id DESC LIMIT ?';
    const rows = (before !== undefined ? this.db.prepare(sql).all(before, n) : this.db.prepare(sql).all(n)) as { id: number; at: string; user_id: number | null; username: string | null; action: string; target: string | null; detail: string | null; ip: string | null }[];
    return rows.map((r) => {
      let detail: unknown = null;
      if (r.detail !== null) {
        try {
          detail = JSON.parse(r.detail);
        } catch {
          detail = r.detail;
        }
      }
      return { id: r.id, at: r.at, userId: r.user_id, username: r.username, action: r.action, target: r.target, detail, ip: r.ip };
    });
  }

  close(): void {
    this.db.close();
  }
}

const USER_COLUMNS = 'id, username, display_name, role, password_hash, disabled, source, oidc_provider, oidc_sub, created_at, last_login_at';

interface RawUser {
  id: number;
  username: string;
  display_name: string;
  role: string;
  password_hash: string | null;
  disabled: number;
  source: string;
  oidc_provider: string | null;
  oidc_sub: string | null;
  created_at: string;
  last_login_at: string | null;
}

interface RawToken {
  id: number;
  name: string;
  scopes: string;
  created_at: string;
  last_used_at: string | null;
  created_by: number | null;
}
