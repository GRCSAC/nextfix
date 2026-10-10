import type { Cache } from '../vulns/cache.ts';
import type { SymbolEntry } from '../types.ts';

/** Derived symbol entries, persisted next to the advisory cache so every scan on this machine reuses them. */
export class DerivedStore {
  private cache: Cache;

  constructor(cache: Cache) {
    this.cache = cache;
    cache.raw().exec(`CREATE TABLE IF NOT EXISTS derived_symbols (
      advisory TEXT NOT NULL,
      package TEXT NOT NULL,
      entry TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (advisory, package)
    )`);
  }

  get(advisoryId: string, pkg: string): SymbolEntry | undefined {
    const r = this.cache.raw().prepare('SELECT entry FROM derived_symbols WHERE advisory = ? AND package = ?').get(advisoryId, pkg) as { entry: string } | undefined;
    return r ? (JSON.parse(r.entry) as SymbolEntry) : undefined;
  }

  put(entry: SymbolEntry): void {
    const key = entry.ids[0]!;
    this.cache
      .raw()
      .prepare('INSERT INTO derived_symbols (advisory, package, entry, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(advisory, package) DO UPDATE SET entry = excluded.entry, created_at = excluded.created_at')
      .run(key, entry.package, JSON.stringify(entry), new Date().toISOString());
  }

  all(): SymbolEntry[] {
    const rows = this.cache.raw().prepare('SELECT entry FROM derived_symbols ORDER BY package, advisory').all() as { entry: string }[];
    return rows.map((r) => JSON.parse(r.entry) as SymbolEntry);
  }

  remove(advisoryId: string, pkg: string): void {
    this.cache.raw().prepare('DELETE FROM derived_symbols WHERE advisory = ? AND package = ?').run(advisoryId, pkg);
  }

  /** Remembers that derivation found nothing, so scans do not retry every time. The key carries the
   * pipeline version: when derivation improves, old failures are retried automatically. */
  markFailed(advisoryId: string, pkg: string, reason: string, ttlMs: number): void {
    this.cache.set(`derive:fail:${DERIVE_VERSION}:${advisoryId}|${pkg}`, reason, ttlMs);
  }

  failedReason(advisoryId: string, pkg: string): string | undefined {
    return this.cache.get<string>(`derive:fail:${DERIVE_VERSION}:${advisoryId}|${pkg}`);
  }

  clearFailed(advisoryId: string, pkg: string): void {
    this.cache.delete(`derive:fail:${DERIVE_VERSION}:${advisoryId}|${pkg}`);
  }
}

/** Bump when derivation gets smarter, so cached "nothing derived" results are retried. */
export const DERIVE_VERSION = 4;
