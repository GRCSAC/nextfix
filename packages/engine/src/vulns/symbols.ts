import { readFileSync } from 'node:fs';
import { readAsset } from '../assets.ts';
import type { SymbolEntry } from '../types.ts';

/** Vulnerable-symbol database: curated entries from the repo plus derived entries from this machine. */
export class SymbolDb {
  private byId = new Map<string, SymbolEntry[]>();

  constructor(entries: SymbolEntry[]) {
    for (const e of entries) this.add(e);
  }

  /** The curated database from the repo (or the executable) unless a file is given. */
  static load(path?: string | URL, extra: SymbolEntry[] = []): SymbolDb {
    const text = path === undefined ? readAsset('vulnerable-symbols.json').toString('utf8') : readFileSync(path, 'utf8');
    const json = JSON.parse(text) as { entries: SymbolEntry[] };
    return new SymbolDb([...json.entries, ...extra]);
  }

  add(e: SymbolEntry): void {
    for (const id of e.ids) {
      const key = `${id}|${e.package}`;
      const list = this.byId.get(key) ?? [];
      list.push(e);
      this.byId.set(key, list);
    }
  }

  /** Curated (confirmed) entries win over derived ones for the same advisory. */
  lookup(advisoryIds: string[], pkg: string): SymbolEntry | undefined {
    let best: SymbolEntry | undefined;
    for (const id of advisoryIds) {
      for (const e of this.byId.get(`${id}|${pkg}`) ?? []) {
        if (!best || rank(e) < rank(best)) best = e;
      }
    }
    return best;
  }

  get size(): number {
    return this.byId.size;
  }
}

function rank(e: SymbolEntry): number {
  if (e.confidence === 'confirmed') return e.source === 'curated' ? 0 : 1;
  return 2;
}
