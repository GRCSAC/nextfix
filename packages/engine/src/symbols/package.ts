import { analyzeFile, publicNamesFor, reachingLocals, type FileFacts } from './functions.ts';

export type Fetch = (path: string) => Promise<string | undefined>;

export interface PkgFile {
  path: string;
  facts: FileFacts;
  /** resolved import target path -> local bindings */
  imports: Map<string, { local: string; imported: string }[]>;
  /** resolved re-export target path -> names */
  reexports: Map<string, 'all' | { exported: string; imported: string }[]>;
}

/** Probe order: most likely first, since every miss is a network fetch. A specifier that already has an extension is tried as-is first. */
const EXTS = ['.js', '.ts', '', '/index.js', '.mjs', '.cjs', '/index.ts', '.jsx', '.tsx', '/index.mjs'];

function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

function normalize(p: string): string {
  const out: string[] = [];
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return out.join('/');
}

/** A package's source files inside a repository at one ref, loaded lazily and bounded. */
export class PackageGraph {
  private files = new Map<string, PkgFile | null>();
  private fetches = 0;
  private fetch: Fetch;
  readonly maxFiles: number;

  constructor(fetch: Fetch, maxFiles = 200) {
    this.fetch = fetch;
    this.maxFiles = maxFiles;
  }

  /** Files actually loaded (misses are not counted). */
  get loaded(): number {
    let n = 0;
    for (const f of this.files.values()) if (f) n++;
    return n;
  }

  async exists(path: string): Promise<boolean> {
    return (await this.load(path)) !== undefined;
  }

  async load(path: string): Promise<PkgFile | undefined> {
    const p = normalize(path);
    if (this.files.has(p)) return this.files.get(p) ?? undefined;
    if (this.loaded >= this.maxFiles) return undefined;
    this.fetches++;
    const text = await this.fetch(p);
    if (text === undefined) {
      this.files.set(p, null);
      return undefined;
    }
    const facts = analyzeFile(text, p);
    const file: PkgFile = { path: p, facts, imports: new Map(), reexports: new Map() };
    this.files.set(p, file);
    return file;
  }

  /** Resolves a file's import and re-export specifiers to paths (once). Breadth-first callers drive the order. */
  async link(file: PkgFile): Promise<void> {
    if (this.linked.has(file.path)) return;
    this.linked.add(file.path);
    for (const imp of file.facts.imports) {
      const target = await this.resolve(file.path, imp.specifier);
      if (target) file.imports.set(target, [...(file.imports.get(target) ?? []), ...imp.bindings]);
    }
    for (const re of file.facts.reexports) {
      const target = await this.resolve(file.path, re.specifier);
      if (!target) continue;
      const prev = file.reexports.get(target);
      if (prev === 'all' || re.names === 'all') file.reexports.set(target, 'all');
      else file.reexports.set(target, [...(prev ?? []), ...re.names]);
    }
  }
  private linked = new Set<string>();

  /** Resolves a relative specifier to a path that exists in the repo. */
  async resolve(fromPath: string, spec: string): Promise<string | undefined> {
    if (!spec.startsWith('.') && !spec.startsWith('/')) return undefined;
    const base = normalize(`${dirname(fromPath)}/${spec}`);
    const order = /\.[cm]?[jt]sx?$/.test(spec) ? ['', ...EXTS.filter((e) => e)] : EXTS;
    for (const ext of order) {
      const cand = normalize(base + ext);
      if (cand === fromPath) continue;
      if (this.files.has(cand)) {
        if (this.files.get(cand)) return cand;
        continue;
      }
      if (await this.exists(cand)) return cand;
    }
    return undefined;
  }
}

export interface PackageJson {
  name?: string;
  main?: string;
  module?: string;
  source?: string;
  exports?: unknown;
  'jsnext:main'?: string;
}

/** Candidate entry files, source-first, relative to the package directory. */
export function entryCandidates(pkg: PackageJson, pkgName: string): string[] {
  const out: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === 'string' && !/\.(json|d\.ts|css)$/.test(v)) out.push(v.replace(/^\.\//, ''));
  };
  const base = pkgName.replace(/^@[^/]+\//, '');
  push(pkg.source);
  out.push(`src/index.js`, `src/index.ts`, `src/${base}.js`, `src/${base}.ts`, `src/index.mjs`, `src/main.js`);
  push(pkg['jsnext:main']);
  push(pkg.module);
  const ex = pkg.exports;
  const walkExports = (v: unknown, depth = 0) => {
    if (depth > 3 || v === null || v === undefined) return;
    if (typeof v === 'string') push(v);
    else if (Array.isArray(v)) v.forEach((x) => walkExports(x, depth + 1));
    else if (typeof v === 'object') {
      const o = v as Record<string, unknown>;
      for (const key of ['.', 'import', 'module', 'default', 'require', 'node', 'browser']) if (key in o) walkExports(o[key], depth + 1);
    }
  };
  walkExports(ex);
  push(pkg.main);
  out.push('index.js', 'index.ts', 'index.mjs', 'lib/index.js', 'lib/index.ts', `lib/${base}.js`, `${base}.js`);
  return [...new Set(out)];
}

/**
 * Finds the package directory (within the repo) and entry file. `touched` is a file the fix
 * changed; the package.json is searched from its directory upward.
 */
export async function findPackage(graph: { fetchText: Fetch }, touched: string, pkgName: string): Promise<{ dir: string; pkg: PackageJson } | undefined> {
  const parts = touched.split('/');
  const dirs: string[] = [];
  for (let i = parts.length - 1; i >= 0; i--) dirs.push(parts.slice(0, i).join('/'));
  for (const dir of dirs) {
    const text = await graph.fetchText(dir ? `${dir}/package.json` : 'package.json');
    if (!text) continue;
    try {
      const pkg = JSON.parse(text) as PackageJson;
      if (!pkg.name || pkg.name === pkgName || dir === '') return { dir, pkg };
    } catch {
      /* not JSON */
    }
  }
  return undefined;
}

export interface CrossFileResult {
  entry: string;
  /** public symbol of the package -> how it was reached */
  symbols: Map<string, string>;
  filesVisited: number;
}

/**
 * Carries a set of tainted local names in `startPath` up through importers and re-exports to
 * the entry file, returning the entry's public names that reach them.
 */
export async function resolveAcrossFiles(graph: PackageGraph, entry: string, startPath: string, startLocals: Set<string>, maxDepth = 6): Promise<CrossFileResult | undefined> {
  const entryFile = await graph.load(entry);
  if (!entryFile) return undefined;

  // Import graph from the entry: importer -> [target]; and reverse.
  const importers = new Map<string, Set<string>>();
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length) {
    const p = queue.shift()!;
    if (seen.has(p)) continue;
    seen.add(p);
    const f = await graph.load(p);
    if (!f) continue;
    await graph.link(f);
    for (const t of [...f.imports.keys(), ...f.reexports.keys()]) {
      (importers.get(t) ?? importers.set(t, new Set()).get(t)!).add(p);
      if (!seen.has(t)) queue.push(t);
    }
  }
  if (!seen.has(startPath)) return undefined;

  const symbols = new Map<string, string>();
  const visited = new Set<string>();
  /** `locals`: tainted local names in this file. `direct`: names already public here via re-export. */
  interface Item { path: string; locals: Set<string>; direct: Set<string>; via: string; depth: number }
  const work: Item[] = [{ path: startPath, locals: startLocals, direct: new Set(), via: startPath, depth: 0 }];

  while (work.length) {
    const { path, locals, direct, via, depth } = work.shift()!;
    const key = `${path}|${[...locals].sort().join(',')}|${[...direct].sort().join(',')}`;
    if (visited.has(key) || depth > maxDepth) continue;
    visited.add(key);
    const file = await graph.load(path);
    if (!file) continue;

    const reach = locals.size ? reachingLocals(file.facts, locals) : new Set<string>();
    const pubs = publicNamesFor(file.facts, reach);
    for (const d of direct) if (!pubs.has(d)) pubs.set(d, '(re-export)');
    if (path === entry) {
      for (const [p] of pubs) if (!symbols.has(p)) symbols.set(p, via);
      if ([...reach].some((l) => file.facts.moduleRefs.has(l)) && file.facts.defaultIsFunction && !symbols.has('default')) symbols.set('default', `${via} (module scope)`);
      continue;
    }
    if (!pubs.size) continue;

    for (const importer of importers.get(path) ?? []) {
      const imp = await graph.load(importer);
      if (!imp) continue;
      const nextLocals = new Set<string>();
      const nextDirect = new Set<string>();
      // Re-exports: our public names are public in the importer under the exported name.
      const re = imp.reexports.get(path);
      if (re === 'all') for (const [p] of pubs) nextDirect.add(p);
      else if (re) for (const { exported, imported } of re) if (imported === '*' || pubs.has(imported)) nextDirect.add(exported);
      // Imports: local bindings of the importer that refer to our public names.
      for (const b of imp.imports.get(path) ?? []) {
        if (b.imported === '*' || (b.imported === 'default' && pubs.has('default')) || pubs.has(b.imported)) nextLocals.add(b.local);
      }
      if (!nextLocals.size && !nextDirect.size) continue;
      work.push({ path: importer, locals: nextLocals, direct: nextDirect, via: `${via} → ${importer}`, depth: depth + 1 });
    }
  }
  return symbols.size ? { entry, symbols, filesVisited: seen.size } : undefined;
}
