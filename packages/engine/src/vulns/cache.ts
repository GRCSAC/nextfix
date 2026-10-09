import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

/** Small TTL key/value cache on SQLite so repeat scans and offline runs do not hit the network. */
export class Cache {
  private db: DatabaseSync;
  readonly path: string;

  constructor(path = defaultCachePath()) {
    mkdirSync(dirname(path), { recursive: true });
    this.path = path;
    this.db = new DatabaseSync(path);
    this.db.exec(`CREATE TABLE IF NOT EXISTS kv (
      k TEXT PRIMARY KEY,
      v TEXT NOT NULL,
      exp INTEGER NOT NULL
    )`);
  }

  get<T>(key: string, allowExpired = false): T | undefined {
    const row = this.db.prepare('SELECT v, exp FROM kv WHERE k = ?').get(key) as { v: string; exp: number } | undefined;
    if (!row) return undefined;
    if (!allowExpired && row.exp < Date.now()) return undefined;
    return JSON.parse(row.v) as T;
  }

  set(key: string, value: unknown, ttlMs: number): void {
    this.db
      .prepare('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp')
      .run(key, JSON.stringify(value), Date.now() + ttlMs);
  }

  close(): void {
    this.db.close();
  }
}

export function defaultCachePath(): string {
  return join(homedir(), '.nextfix', 'cache.sqlite');
}

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
