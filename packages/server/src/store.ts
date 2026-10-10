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
];

const DECISION_ZERO: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
const TIER_ZERO: Record<ReachTier, number> = { reachable: 0, 'called-unreached': 0, 'imported-unknown-symbol': 0, 'image-only': 0, 'imported-not-called': 0, unused: 0, 'dev-only': 0 };

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

interface RawScan {
  id: number;
  target_id: number;
  created_at: string;
  tool_version: string;
  summary: string;
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
    this.migrate();
  }

  private migrate(): void {
    const row = this.db.prepare('PRAGMA user_version').get() as { user_version: number };
    for (let v = row.user_version; v < MIGRATIONS.length; v++) {
      this.db.exec('BEGIN');
      try {
        this.db.exec(MIGRATIONS[v]!);
        this.db.exec(`PRAGMA user_version = ${v + 1}`);
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw err;
      }
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

  listTargets(): (TargetRow & { lastScan?: ScanRow })[] {
    const rows = this.db.prepare('SELECT id, dir, name, created_at FROM targets ORDER BY name, dir').all() as { id: number; dir: string; name: string | null; created_at: string }[];
    return rows.map((r) => {
      const t: TargetRow & { lastScan?: ScanRow } = { id: r.id, dir: r.dir, name: r.name, createdAt: r.created_at };
      const scans = this.listScans(r.id);
      if (scans.length) t.lastScan = scans[scans.length - 1];
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

  deleteTarget(id: number): void {
    this.db.prepare('DELETE FROM scans WHERE target_id = ?').run(id);
    this.db.prepare('DELETE FROM tickets WHERE target_id = ?').run(id);
    this.db.prepare('DELETE FROM targets WHERE id = ?').run(id);
  }

  addScan(targetId: number, report: ScanReport): ScanRow {
    const res = this.db
      .prepare('INSERT INTO scans (target_id, created_at, tool_version, summary, report) VALUES (?, ?, ?, ?, ?)')
      .run(targetId, report.generatedAt, report.tool.version, JSON.stringify(report.summary), JSON.stringify(report));
    if (report.target.name) this.db.prepare('UPDATE targets SET name = ? WHERE id = ?').run(report.target.name, targetId);
    return { id: Number(res.lastInsertRowid), targetId, createdAt: report.generatedAt, toolVersion: report.tool.version, summary: normalizeSummary(report.summary) };
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
