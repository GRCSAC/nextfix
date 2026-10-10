import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

export interface GoModule {
  /** module path from the `module` line */
  path: string;
  /** directory holding the go.mod, relative to the project root ('' for the root) */
  dir: string;
  /** required module paths, with `// indirect` marks */
  requires: { path: string; version: string; indirect: boolean }[];
}

/** Parses one go.mod: module path and require lines (single or block form). */
export function parseGoMod(text: string, dir = ''): GoModule | undefined {
  const mod = /^\s*module\s+("?)([^\s"]+)\1/m.exec(text);
  if (!mod) return undefined;
  const requires: GoModule['requires'] = [];
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.trim();
    if (inBlock) {
      if (l.startsWith(')')) inBlock = false;
      else addRequire(l);
      continue;
    }
    if (/^require\s*\(/.test(l)) inBlock = true;
    else if (/^require\s+/.test(l)) addRequire(l.replace(/^require\s+/, ''));
  }
  function addRequire(l: string) {
    const m = /^("?)([^\s"]+)\1\s+(\S+)(.*)$/.exec(l);
    if (!m || l.startsWith('//')) return;
    requires.push({ path: m[2]!, version: m[3]!, indirect: /\/\/\s*indirect/.test(m[4] ?? '') });
  }
  return { path: mod[2]!, dir, requires };
}

const SKIP = new Set(['vendor', 'testdata', 'node_modules']);

/** Every go.mod under the project (the root one first), so import paths map to directories. */
export function readGoModules(rootDir: string, ignore: Set<string> = new Set()): GoModule[] {
  const out: GoModule[] = [];
  const visit = (dir: string, depth: number) => {
    const rel = relative(rootDir, dir).replace(/\\/g, '/');
    if (ignore.has(rel)) return;
    const gm = join(dir, 'go.mod');
    if (existsSync(gm)) {
      const m = parseGoMod(readFileSync(gm, 'utf8'), rel);
      if (m) out.push(m);
    }
    if (depth > 8) return;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of names) {
      if (SKIP.has(name) || name.startsWith('.') || name.startsWith('_')) continue;
      const full = join(dir, name);
      try {
        if (statSync(full).isDirectory()) visit(full, depth + 1);
      } catch {
        // unreadable entry
      }
    }
  };
  visit(rootDir, 0);
  return out.sort((a, b) => a.dir.length - b.dir.length);
}
