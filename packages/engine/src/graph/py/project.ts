import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { analyzePyModule, PY_GUARD_RE, type PyModuleInfo, type PyRoute } from './analyze.ts';
import type { ProjectGraph } from '../js/project.ts';
import type { CallSite, FunctionInfo } from '../js/analyze.ts';
import type { EntryPoint } from '../../types.ts';

const SKIP_DIRS = new Set(['node_modules', '.git', 'venv', '.venv', 'env', '__pycache__', 'site-packages', 'dist', 'build', '.tox', '.mypy_cache', '.pytest_cache', 'migrations', 'tests', 'test', 'docs']);

export function discoverPythonFiles(rootDir: string): string[] {
  const out: string[] = [];
  const walkDir = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue; // broken symlink
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name) && !name.startsWith('.')) walkDir(full);
      } else if (st.isFile() && name.endsWith('.py') && !/^(test_|conftest)/.test(name) && !/_test\.py$/.test(name)) out.push(full);
    }
  };
  walkDir(rootDir);
  return out.sort();
}

export interface PyProjectOptions {
  installed: Set<string>;
  authGuards?: string[];
  ignore?: string[];
  internalRoutes?: string[];
}

/** Builds a ProjectGraph (same shape as the JavaScript one) for a Python project. */
export async function analyzePythonProject(rootDir: string, opts: PyProjectOptions): Promise<ProjectGraph> {
  const authRe = opts.authGuards?.length ? new RegExp(opts.authGuards.join('|'), 'i') : undefined;
  const ignore = new Set((opts.ignore ?? []).map((d) => d.replace(/\\/g, '/').replace(/\/+$/, '')));
  const files = discoverPythonFiles(rootDir).filter((f) => {
    const rel = relative(rootDir, f).replace(/\\/g, '/');
    for (const dir of ignore) if (rel === dir || rel.startsWith(dir + '/')) return false;
    return true;
  });
  const modules = new Map<string, PyModuleInfo>();
  for (const f of files) {
    const m = await analyzePyModule(f, { rootDir, installed: opts.installed, authRe });
    modules.set(m.rel, m);
  }
  const rel = (abs: string) => relative(rootDir, abs).replace(/\\/g, '/');
  const internal = new Set((opts.internalRoutes ?? []).map((r) => r.trim().toUpperCase()));

  const functions = new Map<string, FunctionInfo>();
  const packagesImported = new Map<string, Set<string>>();
  for (const m of modules.values()) {
    for (const fn of m.functions) functions.set(fn.id, fn);
    for (const i of m.imports) {
      if (!i.dist) continue;
      (packagesImported.get(i.dist) ?? packagesImported.set(i.dist, new Set()).get(i.dist)!).add(m.rel);
    }
  }

  function resolveIn(mod: PyModuleInfo, name: string): string | undefined {
    if (name === 'default') return undefined;
    const d = mod.defs.get(name);
    if (d) return d;
    // re-exported through an import in this module (package __init__ style)
    const imp = mod.imports.find((i) => i.local === name);
    if (imp?.file) {
      const target = modules.get(rel(imp.file));
      if (target) return resolveIn(target, imp.member ?? name);
    }
    return mod.functions.find((f) => f.name === name && !f.parentId)?.id;
  }

  // edges
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
          const t = modules.get(rel(c.target.file));
          if (t) id = resolveIn(t, c.target.name);
        } else {
          id = resolveIn(m, c.target.name) ?? [...m.classes.values()].map((cl) => cl.methods.get(c.target.kind === 'local' ? c.target.name : '')).find((x) => x);
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
    for (const fn of m.functions) {
      if (!fn.parentId) continue;
      (edges.get(fn.parentId) ?? edges.set(fn.parentId, new Set()).get(fn.parentId)!).add(fn.id);
    }
  }

  // ---- mounts: (module, identifier) of a blueprint / router -> where it is mounted ----
  interface Mount { prefix: string; guards: string[]; parent: PyModuleInfo; parentApp: string }
  const mountsByOwner = new Map<string, Mount[]>(); // key: `${rel}|${ident}` or `${rel}|urlpatterns`
  const ownerOf = (m: PyModuleInfo, ident: string, member?: string): string => {
    // an identifier used in `m`: defined here, or imported from another module (possibly `users.router`)
    const imp = m.imports.find((i) => i.local === ident);
    if (imp?.file) {
      const target = modules.get(rel(imp.file));
      if (member) return `${rel(imp.file)}|${member}`;
      if (imp.member && target && !target.appIdents.has(imp.member)) {
        // `from app.auth import bp` where app/auth/__init__.py defines bp
        return `${rel(imp.file)}|${imp.member}`;
      }
      return `${rel(imp.file)}|${imp.member ?? ident}`;
    }
    return `${m.rel}|${member ?? ident}`;
  };
  const urlconfByDotted = (dotted: string): PyModuleInfo | undefined => {
    const parts = dotted.split('.');
    for (const m of modules.values()) {
      const r = m.rel.replace(/\.py$/, '').replace(/\/__init__$/, '').split('/');
      const tail = r.slice(-parts.length).join('.');
      if (tail === dotted || tail === `${dotted}.urls` || r.join('.').endsWith(dotted)) if (m.isUrlconf) return m;
    }
    return undefined;
  };
  for (const m of modules.values()) {
    for (const mt of m.mounts) {
      if (mt.kind === 'include') {
        const target = urlconfByDotted(mt.target) ?? urlconfByDotted(`${mt.target}.urls`);
        if (!target) continue;
        (mountsByOwner.get(`${target.rel}|urlpatterns`) ?? mountsByOwner.set(`${target.rel}|urlpatterns`, []).get(`${target.rel}|urlpatterns`)!).push({ prefix: mt.prefix, guards: mt.guards, parent: m, parentApp: 'urlpatterns' });
        continue;
      }
      const key = ownerOf(m, mt.target, mt.member);
      (mountsByOwner.get(key) ?? mountsByOwner.set(key, []).get(key)!).push({ prefix: mt.prefix, guards: mt.guards, parent: m, parentApp: mt.onto });
    }
  }

  function chains(m: PyModuleInfo, ident: string, depth = 0): { prefix: string; guards: string[]; mounted: boolean }[] {
    const app = m.appIdents.get(ident);
    if (depth > 6) return [{ prefix: '', guards: [], mounted: true }];
    if (ident === 'urlpatterns') {
      const mounts = mountsByOwner.get(`${m.rel}|urlpatterns`);
      if (!mounts?.length) return [{ prefix: '', guards: [], mounted: true }]; // root urlconf
      return mounts.flatMap((mt) => chains(mt.parent, 'urlpatterns', depth + 1).map((up) => ({ prefix: joinPath(up.prefix, mt.prefix), guards: [...up.guards, ...mt.guards], mounted: up.mounted })));
    }
    if (app?.kind === 'app') return [{ prefix: app.prefix, guards: app.guards, mounted: true }];
    const own = app ? { prefix: app.prefix, guards: app.guards } : { prefix: '', guards: [] };
    const mounts = mountsByOwner.get(`${m.rel}|${ident}`);
    if (!mounts?.length) {
      // identifier imported from elsewhere: follow to its defining module
      const imp = m.imports.find((i) => i.local === ident);
      if (imp?.file && depth < 6) {
        const target = modules.get(rel(imp.file));
        if (target) return chains(target, imp.member ?? ident, depth + 1).map((c) => ({ ...c, prefix: joinPath(c.prefix, own.prefix), guards: [...c.guards, ...own.guards] }));
      }
      return [{ prefix: own.prefix, guards: own.guards, mounted: false }];
    }
    return mounts.flatMap((mt) => chains(mt.parent, mt.parentApp, depth + 1).map((up) => ({ prefix: joinPath(joinPath(up.prefix, mt.prefix), own.prefix), guards: [...up.guards, ...mt.guards, ...own.guards], mounted: up.mounted })));
  }

  // ---- entry points ----
  const entryPoints: EntryPoint[] = [];
  const markInput = (id: string) => {
    const fn = functions.get(id);
    if (fn) fn.inputParams = fn.params;
  };
  for (const m of modules.values()) {
    for (const r of m.routes) {
      const handlerIds: string[] = [];
      const unresolved: string[] = [];
      const classGuards: string[] = [];
      let methods = r.methods;
      /** class-based views: each HTTP verb has its own method */
      const perMethod = new Map<string, string[]>();
      for (const h of r.handlerIds) {
        if (functions.has(h)) handlerIds.push(h);
        else {
          const [file, name] = h.split('#');
          const target = file ? modules.get(file) : undefined;
          const id = target && name ? resolveIn(target, name) : undefined;
          if (id) handlerIds.push(id);
          else unresolved.push(h.replace('#', '.'));
        }
      }
      for (const u of r.unresolved) {
        if (!u.startsWith('class:')) {
          unresolved.push(u);
          continue;
        }
        const clsRef = u.slice(6);
        const [objName, clsName] = clsRef.includes('.') ? clsRef.split('.') : [undefined, clsRef];
        let target: PyModuleInfo | undefined = m;
        if (objName) {
          const imp = m.imports.find((i) => i.local === objName);
          target = imp?.file ? modules.get(rel(imp.file)) : undefined;
        } else {
          const imp = m.imports.find((i) => i.local === clsName);
          if (imp?.file) target = modules.get(rel(imp.file));
        }
        const cls = target?.classes.get(clsName!);
        if (!cls) {
          unresolved.push(clsRef);
          continue;
        }
        classGuards.push(...cls.guards);
        const verbs = [...cls.methods.keys()].filter((k) => ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(k));
        if (verbs.length) {
          methods = verbs.map((v) => v.toUpperCase());
          for (const v of verbs) {
            handlerIds.push(cls.methods.get(v)!);
            perMethod.set(v.toUpperCase(), [cls.methods.get(v)!]);
          }
        } else {
          for (const id of cls.methods.values()) handlerIds.push(id);
        }
      }
      if (!handlerIds.length && !unresolved.length) continue;
      for (const id of handlerIds) {
        markInput(id);
        // decorator guards on the view itself (Django views live in another module than urls.py)
        const owner = id.split('#')[0]!;
        for (const g of modules.get(owner)?.functionGuards.get(id) ?? []) if (!classGuards.includes(g) && !r.guards.includes(g)) classGuards.push(g);
      }
      for (const ch of chains(m, r.app)) {
        for (const method of methods) {
          const guards = [...ch.guards, ...r.guards, ...classGuards];
          const path = joinPath(ch.prefix, r.path);
          if (internal.has(`${method} ${path}`.toUpperCase())) guards.push('internal (nextfix.config.json)');
          entryPoints.push({ method, path, file: m.rel, line: r.line, authenticated: guards.length > 0, guards, mounted: ch.mounted, handlerIds: perMethod.get(method) ?? handlerIds, unresolvedHandlers: unresolved.length ? unresolved : undefined });
        }
      }
    }
  }

  // Expose modules in the JS ProjectGraph shape (routes/exports unused by consumers beyond counts).
  const jsModules = new Map<string, any>();
  for (const m of modules.values()) jsModules.set(m.rel, { file: m.file, rel: m.rel, imports: [], functions: m.functions, moduleFunctionId: m.moduleFunctionId, routes: m.routes.map(pyRouteAsJs), appIdents: new Set(m.appIdents.keys()), isRootApp: m.isRootApp, exports: new Map(), reexports: [], listens: false, autoload: [], hookGuards: [] });

  const rootApps = [...modules.values()].filter((m) => m.isRootApp).map((m) => m.rel);
  return { rootDir, modules: jsModules, functions, edges, edgeInput, edgeSites, entryPoints, packagesImported, rootApps, listenLocalOnly: false };
}

function pyRouteAsJs(r: PyRoute) {
  return { method: r.methods[0]?.toLowerCase() ?? 'get', path: r.path, line: r.line, app: r.app, guards: r.guards, middleware: [], handlerIds: r.handlerIds, unresolved: r.unresolved };
}

function joinPath(a: string, b: string): string {
  const s = `${a}/${b}`.replace(/\/{2,}/g, '/');
  return s.length > 1 ? s.replace(/\/$/, '') : s || '/';
}

export { PY_GUARD_RE };
