import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { AUTH_RE, analyzeModule, type CallSite, type FunctionInfo, type ModuleInfo, type RouteReg } from './analyze.ts';
import type { EntryPoint } from '../../types.ts';

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'out', '.nextfix']);
const EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']);

export interface ProjectGraph {
  rootDir: string;
  modules: Map<string, ModuleInfo>; // keyed by rel path
  functions: Map<string, FunctionInfo>;
  /** function id -> ids of local functions it calls */
  edges: Map<string, Set<string>>;
  /** function id -> callee ids where request data was passed as an argument */
  edgeInput: Map<string, Set<string>>;
  /** function id -> callee id -> the call sites that realise that edge (containment edges have none) */
  edgeSites: Map<string, Map<string, CallSite[]>>;
  entryPoints: EntryPoint[];
  /** package name -> rel files importing it */
  packagesImported: Map<string, Set<string>>;
  rootApps: string[];
  listenLocalOnly: boolean;
}

export function discoverSourceFiles(rootDir: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      const st = statSync(full);
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(full);
      } else if (st.isFile()) {
        const dot = name.lastIndexOf('.');
        const ext = dot >= 0 ? name.slice(dot).toLowerCase() : '';
        if (EXTS.has(ext) && !name.endsWith('.d.ts')) out.push(full);
      }
    }
  };
  walk(rootDir);
  return out.sort();
}

export interface ProjectOptions {
  authGuards?: string[];
  authGuardsReplace?: boolean;
  ignore?: string[];
  internalRoutes?: string[];
}

export function analyzeProject(rootDir: string, options: ProjectOptions = {}): ProjectGraph {
  const extra = (options.authGuards ?? []).filter(Boolean);
  const authRe = extra.length
    ? new RegExp(options.authGuardsReplace ? extra.join('|') : `${AUTH_RE.source}|${extra.join('|')}`, 'i')
    : undefined;
  const ignore = new Set((options.ignore ?? []).map((d) => d.replace(/\\/g, '/').replace(/\/+$/, '')));
  const files = discoverSourceFiles(rootDir).filter((f) => {
    const rel = relative(rootDir, f).replace(/\\/g, '/');
    for (const dir of ignore) if (rel === dir || rel.startsWith(dir + '/')) return false;
    return true;
  });
  const modules = new Map<string, ModuleInfo>();
  for (const f of files) {
    const m = analyzeModule(f, rootDir, { authRe });
    modules.set(m.rel, m);
  }
  const internal = new Set((options.internalRoutes ?? []).map((r) => r.trim().toUpperCase()));
  const rel = (abs: string) => relative(rootDir, abs).replace(/\\/g, '/');

  const functions = new Map<string, FunctionInfo>();
  const packagesImported = new Map<string, Set<string>>();
  for (const m of modules.values()) {
    for (const fn of m.functions) functions.set(fn.id, fn);
    for (const b of m.imports) {
      if (b.kind !== 'package' || !b.package) continue;
      const set = packagesImported.get(b.package) ?? new Set();
      set.add(m.rel);
      packagesImported.set(b.package, set);
    }
  }

  // Resolve an export name of a module to a function id. Falls back to any function of that
  // name in the module (class methods reached through an instance, `exports` built dynamically).
  function resolveExport(mod: ModuleInfo, name: string): string | undefined {
    const v = mod.exports.get(name);
    if (v) {
      if (functions.has(v)) return v; // inline function id
      const fn = mod.functions.find((f) => f.name === v);
      if (fn) return fn.id;
    }
    if (name === 'default') return undefined;
    return mod.functions.find((f) => f.name === name)?.id;
  }
  function resolveLocalName(mod: ModuleInfo, name: string): string | undefined {
    const fn = mod.functions.find((f) => f.name === name);
    return fn?.id;
  }

  const edges = new Map<string, Set<string>>();
  const edgeInput = new Map<string, Set<string>>();
  const edgeSites = new Map<string, Map<string, CallSite[]>>();
  for (const m of modules.values()) {
    for (const fn of m.functions) {
      const set = new Set<string>();
      const input = new Set<string>();
      const sites = new Map<string, CallSite[]>();
      for (const c of fn.calls) {
        if (c.target.kind !== 'local') continue;
        let id: string | undefined;
        if (c.target.file) {
          const target = modules.get(rel(c.target.file));
          if (target) id = resolveExport(target, c.target.name);
        } else {
          id = resolveLocalName(m, c.target.name);
        }
        if (id) {
          set.add(id);
          if (c.userInput) input.add(id);
          (sites.get(id) ?? sites.set(id, []).get(id)!).push(c);
        }
      }
      if (set.size) edges.set(fn.id, set);
      if (input.size) edgeInput.set(fn.id, input);
      if (sites.size) edgeSites.set(fn.id, sites);
    }
    // A function reaches the callbacks and closures defined inside it.
    for (const fn of m.functions) {
      if (!fn.parentId) continue;
      const set = edges.get(fn.parentId) ?? new Set();
      set.add(fn.id);
      edges.set(fn.parentId, set);
    }
  }

  // A provisional mount whose target module does not export a router is really a
  // handler (or middleware) imported from another file.
  for (const m of modules.values()) {
    for (const r of m.routes) {
      if (!r.mountLocal) continue;
      const b = m.imports.find((i) => i.local === r.mountLocal);
      const child = b?.file ? modules.get(rel(b.file)) : undefined;
      if (child?.exportsRouter) continue;
      r.mountLocal = undefined;
      const id = child && b ? resolveExport(child, b.member ?? 'default') : undefined;
      if (id) r.handlerIds.push(id);
      else r.middleware.push(b?.local ?? '?');
    }
  }

  // Entry points: walk mount chains so router files get their prefix and guards.
  interface Mount { prefix: string; guards: string[]; parent: ModuleInfo }
  const mountsByChild = new Map<string, Mount[]>();
  for (const m of modules.values()) {
    for (const r of m.routes) {
      if (!r.mountLocal) continue;
      const b = m.imports.find((i) => i.local === r.mountLocal);
      if (!b?.file) continue;
      const child = rel(b.file);
      const list = mountsByChild.get(child) ?? [];
      list.push({ prefix: r.path === '*' ? '' : r.path, guards: r.guards, parent: m });
      mountsByChild.set(child, list);
    }
  }
  function chains(m: ModuleInfo, depth = 0): { prefix: string; guards: string[]; mounted: boolean }[] {
    if (m.isRootApp || depth > 6) return [{ prefix: '', guards: [], mounted: true }];
    const mounts = mountsByChild.get(m.rel);
    if (!mounts?.length) return [{ prefix: '', guards: [], mounted: false }];
    const out: { prefix: string; guards: string[]; mounted: boolean }[] = [];
    for (const mt of mounts) {
      for (const up of chains(mt.parent, depth + 1)) {
        out.push({ prefix: joinPath(up.prefix, mt.prefix), guards: [...up.guards, ...mt.guards], mounted: up.mounted });
      }
    }
    return out;
  }

  const entryPoints: EntryPoint[] = [];
  for (const m of modules.values()) {
    for (const r of m.routes) {
      if (r.mountLocal) continue;
      const unresolved = [...r.unresolved];
      const handlerIds: string[] = [];
      for (const h of r.handlerIds) {
        const id = functions.has(h) ? h : resolveHandlerRef(h);
        if (id) handlerIds.push(id);
        else unresolved.push(h.replace('#', '.'));
      }
      if (!handlerIds.length && !unresolved.length) continue;
      for (const ch of chains(m)) {
        const guards = [...ch.guards, ...r.guards];
        const method = r.method.toUpperCase();
        const path = joinPath(ch.prefix, r.path === '*' ? '/' : r.path);
        if (internal.has(`${method} ${path}`.toUpperCase())) guards.push('internal (nextfix.config.json)');
        entryPoints.push({
          method,
          path,
          file: m.rel,
          line: r.line,
          authenticated: guards.length > 0,
          guards,
          mounted: ch.mounted,
          handlerIds,
          unresolvedHandlers: unresolved.length ? unresolved : undefined,
        });
      }
    }
  }
  function resolveHandlerRef(ref: string): string | undefined {
    const [file, name] = ref.split('#');
    const mod = file ? modules.get(file) : undefined;
    return mod && name ? resolveExport(mod, name) : undefined;
  }

  const rootApps = [...modules.values()].filter((m) => m.isRootApp).map((m) => m.rel);
  const listenLocalOnly = [...modules.values()].some((m) => m.listens) && [...modules.values()].every((m) => !m.listens || m.listenLocalOnly);

  return { rootDir, modules, functions, edges, edgeInput, edgeSites, entryPoints, packagesImported, rootApps, listenLocalOnly };
}

function joinPath(a: string, b: string): string {
  const s = `${a}/${b}`.replace(/\/{2,}/g, '/');
  return s.length > 1 ? s.replace(/\/$/, '') : s || '/';
}

export type { CallSite, FunctionInfo, ModuleInfo, RouteReg };
