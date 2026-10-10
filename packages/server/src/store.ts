import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { ScanReport, ScanSummary } from '../../engine/src/types.ts';

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

export function defaultDbPath(): string {
  return join(homedir(), '.nextfix', 'nextfix.sqlite');
}

/** Scan history. One row per scan, full report kept as JSON so the UI can replay any scan. */
export class Store {
  private db: DatabaseSync;
  readonly path: string;

  constructor(path = defaultDbPath()) {
    mkdirSync(dirname(path), { recursive: true });
    this.path = path;
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
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
    `);
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
    return { id: Number(res.lastInsertRowid), targetId, createdAt: report.generatedAt, toolVersion: report.tool.version, summary: report.summary };
  }

  listScans(targetId: number): ScanRow[] {
    const rows = this.db.prepare('SELECT id, target_id, created_at, tool_version, summary FROM scans WHERE target_id = ? ORDER BY created_at, id').all(targetId) as { id: number; target_id: number; created_at: string; tool_version: string; summary: string }[];
    return rows.map((r) => ({ id: r.id, targetId: r.target_id, createdAt: r.created_at, toolVersion: r.tool_version, summary: JSON.parse(r.summary) as ScanSummary }));
  }

  getScan(id: number): ScanRow | undefined {
    const r = this.db.prepare('SELECT id, target_id, created_at, tool_version, summary FROM scans WHERE id = ?').get(id) as { id: number; target_id: number; created_at: string; tool_version: string; summary: string } | undefined;
    return r ? { id: r.id, targetId: r.target_id, createdAt: r.created_at, toolVersion: r.tool_version, summary: JSON.parse(r.summary) as ScanSummary } : undefined;
  }

  getReport(id: number): ScanReport | undefined {
    const r = this.db.prepare('SELECT report FROM scans WHERE id = ?').get(id) as { report: string } | undefined;
    return r ? (JSON.parse(r.report) as ScanReport) : undefined;
  }

  previousScan(scan: ScanRow): ScanRow | undefined {
    const r = this.db
      .prepare('SELECT id, target_id, created_at, tool_version, summary FROM scans WHERE target_id = ? AND (created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT 1')
      .get(scan.targetId, scan.createdAt, scan.createdAt, scan.id) as { id: number; target_id: number; created_at: string; tool_version: string; summary: string } | undefined;
    return r ? { id: r.id, targetId: r.target_id, createdAt: r.created_at, toolVersion: r.tool_version, summary: JSON.parse(r.summary) as ScanSummary } : undefined;
  }

  close(): void {
    this.db.close();
  }
}
