import { readFileSync } from 'node:fs';
import type { SymbolEntry } from '../types.ts';

/** Vulnerable-symbol database: which functions of a package an advisory actually lives in. */
export class SymbolDb {
  private byId = new Map<string, SymbolEntry[]>();

  constructor(entries: SymbolEntry[]) {
    for (const e of entries) {
      for (const id of e.ids) {
        const key = `${id}|${e.package}`;
        const list = this.byId.get(key) ?? [];
        list.push(e);
        this.byId.set(key, list);
      }
    }
  }

  static load(path = new URL('../../data/vulnerable-symbols.json', import.meta.url)): SymbolDb {
    const json = JSON.parse(readFileSync(path, 'utf8')) as { entries: SymbolEntry[] };
    return new SymbolDb(json.entries);
  }

  lookup(advisoryIds: string[], pkg: string): SymbolEntry | undefined {
    for (const id of advisoryIds) {
      const hit = this.byId.get(`${id}|${pkg}`);
      if (hit?.length) return hit[0];
    }
    return undefined;
  }

  get size(): number {
    return this.byId.size;
  }
}
