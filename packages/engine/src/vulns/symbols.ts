import { readFileSync } from 'node:fs';
import type { SymbolEntry } from '../types.ts';

/** Vulnerable-symbol database: curated entries from the repo plus derived entries from this machine. */
export class SymbolDb {
  private byId = new Map<string, SymbolEntry[]>();

  constructor(entries: SymbolEntry[]) {
    for (const e of entries) this.add(e);
  }

  static load(path = new URL('../../data/vulnerable-symbols.json', import.meta.url), extra: SymbolEntry[] = []): SymbolDb {
    const json = JSON.parse(readFileSync(path, 'utf8')) as { entries: SymbolEntry[] };
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
