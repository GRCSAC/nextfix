import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { analyzeGoFile, joinPath, pathBase, type GoBase, type GoFileInfo, type GoFunc, type GoGuardCand, type GoRef, type GoType, type GoTypeDecl, type GoTypeSrc } from './analyze.ts';
import { readGoModules } from './gomod.ts';
import type { ProjectGraph } from '../js/project.ts';
import { AUTH_RE, NON_GUARD_RE, NOT_GUARD_RE, compileGuardPatterns, type CallSite, type CallTarget, type FunctionInfo } from '../js/analyze.ts';
import type { EntryPoint } from '../../types.ts';

/** Guard-shaped names in Go web code, on top of the shared AUTH_RE. */
export const GO_GUARD_RE = /jwt|bearer|oauth|basic_?auth|key_?auth|api_?key|apikey|casbin|rbac|\brequire|mustbe|signed_?in|authn|authz|login_?required|session_?required|only_?admin|admin_?only|verif|token/i;
/** Middleware that sets things up and never rejects a request (qualified Go spellings). */
export const GO_NON_GUARD_RE = /^(gin\.(Logger|Recovery|ErrorLogger|CustomRecovery)|middleware\.(Recover|Recoverer|RequestID|RealIP|Timeout|Compress|CORS|Secure|BodyLimit|Gzip|Static|Rewrite|Heartbeat|Throttle|NoCache|StripSlashes|RedirectSlashes|CleanPath|GetHead|AllowContentType|SetHeader|ContentCharset|WithValue|Logger|RequestLogger|Decompress|ContextTimeout|MethodOverride|AddTrailingSlash|RemoveTrailingSlash|Proxy|RateLimiter|CSRF|BodyDump|SetRequestContextWithTimeout)\w*|cors\.|recover\.|logger\.|limiter\.|compress\.|requestid\.|cache\.|etag\.|favicon\.|pprof\.|helmet\.|csrf\.|sessions?\.|otel|ginzap|zap\.|promhttp|nosurf|gzip\.|httplog|hlog|handlers\.(LoggingHandler|CompressHandler|RecoveryHandler|CORS|ProxyHeaders|CombinedLoggingHandler))/i;

/** Resolution hops through local variables, call results and fields before giving up on a type. */
const MAX_DEPTH = 40;
const SKIP_DIRS = new Set(['vendor', 'testdata', 'node_modules', '.git', 'dist', 'build']);

export function discoverGoFiles(rootDir: string): string[] {
  const out: string[] = [];
  const walkDir = (dir: string) => {
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of names) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue; // broken symlink
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name) && !name.startsWith('.') && !name.startsWith('_')) walkDir(full);
      } else if (st.isFile() && name.endsWith('.go') && !name.endsWith('_test.go') && !name.startsWith('.') && !name.startsWith('_')) out.push(full);
    }
  };
  walkDir(rootDir);
  return out.sort();
}

export interface GoProjectOptions {
  /** module paths from go.mod (require lines) */
  installed: Set<string>;
  authGuards?: string[];
  ignore?: string[];
  internalRoutes?: string[];
}

/** A call into a package outside the project; `package` is the module (what advisories name), `packagePath` the import path. */
export interface GoExternalTarget {
  kind: 'external';
  package: string;
  symbol: string;
  altSymbols?: string[];
  packagePath: string;
}

type RType = { kind: 'project'; dir: string; name: string } | { kind: 'external'; path: string; name?: string };

interface Pkg {
  dir: string;
  files: GoFileInfo[];
  funcs: Map<string, string>;
  methods: Map<string, Map<string, string>>;
  types: Map<string, GoTypeDecl>;
  consts: Map<string, string>;
}

interface Chain {
  prefix: string;
  guards: string[];
  mounted: boolean;
}

/** Builds a ProjectGraph (same shape as the JavaScript one) for a Go project. */
export async function analyzeGoProject(rootDir: string, opts: GoProjectOptions): Promise<ProjectGraph> {
  // The patterns come from the scanned repository's nextfix.config.json: validated before use.
  const extra = compileGuardPatterns(opts.authGuards ?? []);
  const AUTH = new RegExp(`${AUTH_RE.source}|${GO_GUARD_RE.source}${extra ? '|' + extra : ''}`, 'i');
  const isGuard = (text: string): boolean => {
    const t = text.slice(0, 300);
    const last = t.replace(/\(.*$/s, '').split('.').pop() ?? t;
    if (NON_GUARD_RE.test(last) || GO_NON_GUARD_RE.test(t) || NOT_GUARD_RE.test(t)) return false;
    return AUTH.test(t);
  };
  const ignore = new Set((opts.ignore ?? []).map((d) => d.replace(/\\/g, '/').replace(/\/+$/, '')));
  const files = discoverGoFiles(rootDir).filter((f) => {
    const rel = relative(rootDir, f).replace(/\\/g, '/');
    for (const dir of ignore) if (rel === dir || rel.startsWith(dir + '/')) return false;
    return true;
  });
  const modules = readGoModules(rootDir, ignore);
  const installed = [...opts.installed].sort((a, b) => b.length - a.length);
  const internal = new Set((opts.internalRoutes ?? []).map((r) => r.trim().toUpperCase()));

  const infos: GoFileInfo[] = [];
  for (const f of files) infos.push(await analyzeGoFile(f, { rootDir }));

  // ---- packages ----
  const packages = new Map<string, Pkg>();
  const funcsById = new Map<string, GoFunc>();
  const fileOfFn = new Map<string, GoFileInfo>();
  for (const info of infos) {
    const pkg = packages.get(info.dir) ?? packages.set(info.dir, { dir: info.dir, files: [], funcs: new Map(), methods: new Map(), types: new Map(), consts: new Map() }).get(info.dir)!;
    pkg.files.push(info);
    for (const [k, v] of info.consts) pkg.consts.set(k, v);
    for (const t of info.types) pkg.types.set(t.name, t);
    funcsById.set(info.fileFunc.info.id, info.fileFunc);
    fileOfFn.set(info.fileFunc.info.id, info);
    for (const fn of info.funcs) {
      funcsById.set(fn.info.id, fn);
      fileOfFn.set(fn.info.id, info);
      if (fn.info.parentId) continue;
      if (fn.recvType) (pkg.methods.get(fn.recvType) ?? pkg.methods.set(fn.recvType, new Map()).get(fn.recvType)!).set(fn.info.name, fn.info.id);
      else if (fn.info.name !== 'init') pkg.funcs.set(fn.info.name, fn.info.id);
    }
  }
  const dirOf = (fn: GoFunc) => fileOfFn.get(fn.info.id)!.dir;

  /** project directory an import path names, when it is inside one of the project's modules */
  function dirOfImport(path: string): string | undefined {
    let best: { path: string; dir: string } | undefined;
    for (const m of modules) if ((path === m.path || path.startsWith(m.path + '/')) && (!best || m.path.length > best.path.length)) best = m;
    if (!best) return undefined;
    const sub = path.slice(best.path.length).replace(/^\//, '');
    const dir = [best.dir, sub].filter(Boolean).join('/');
    return packages.has(dir) ? dir : undefined;
  }
  /** what advisories call the package: the longest installed module path, `stdlib`, or the import path itself */
  function modulePrefix(path: string): string {
    for (const m of installed) if (path === m || path.startsWith(m + '/')) return m;
    if (!path.split('/')[0]!.includes('.')) return 'stdlib';
    return path;
  }
  function externalTarget(path: string, symbol: string, typeName?: string): GoExternalTarget {
    const alt = [`${pathBase(path)}.${symbol}`];
    if (typeName) alt.push(`${typeName}.${symbol}`, `${pathBase(path)}.${typeName}.${symbol}`);
    return { kind: 'external', package: modulePrefix(path), symbol, altSymbols: alt, packagePath: path };
  }

  // ---- types ----
  function resolveType(t: GoType | undefined, fromDir: string): RType | undefined {
    if (!t?.name) return undefined;
    if (t.pkg) {
      const dir = dirOfImport(t.pkg);
      return dir ? { kind: 'project', dir, name: t.name } : { kind: 'external', path: t.pkg, name: t.name };
    }
    return packages.get(fromDir)?.types.has(t.name) ? { kind: 'project', dir: fromDir, name: t.name } : undefined;
  }
  const declOf = (rt: RType): GoTypeDecl | undefined => (rt.kind === 'project' ? packages.get(rt.dir)?.types.get(rt.name) : undefined);
  function fieldType(rt: RType, field: string, depth: number): RType | undefined {
    if (rt.kind === 'external') return { kind: 'external', path: rt.path };
    const decl = declOf(rt);
    if (!decl) return undefined;
    const f = decl.fields.get(field);
    if (f) return resolveType(f, rt.dir);
    if (depth < 3) for (const e of decl.embedded) {
      const et = resolveType(e, rt.dir);
      const r = et ? fieldType(et, field, depth + 1) : undefined;
      if (r) return r;
    }
    return undefined;
  }
  const methodNames = (rt: RType, depth = 0): Set<string> => {
    const out = new Set<string>();
    if (rt.kind !== 'project') return out;
    for (const k of packages.get(rt.dir)?.methods.get(rt.name)?.keys() ?? []) out.add(k);
    const decl = declOf(rt);
    if (decl && depth < 3) for (const e of decl.embedded) {
      const et = resolveType(e, rt.dir);
      if (et) for (const k of methodNames(et, depth + 1)) out.add(k);
    }
    return out;
  };
  const implCache = new Map<string, RType[]>();
  /** project struct types whose method set covers the interface */
  function implementers(iface: RType & { kind: 'project' }): RType[] {
    const key = `${iface.dir}|${iface.name}`;
    const have = implCache.get(key);
    if (have) return have;
    implCache.set(key, []);
    const decl = declOf(iface);
    const need = new Set(decl?.methods ?? []);
    if (decl && decl.kind === 'interface') for (const e of decl.embedded) {
      const et = resolveType(e, iface.dir);
      const ed = et ? declOf(et) : undefined;
      for (const m of ed?.methods ?? []) need.add(m);
    }
    const out: RType[] = [];
    if (need.size) {
      for (const pkg of packages.values()) {
        for (const [name, decl2] of pkg.types) {
          if (decl2.kind === 'interface') continue;
          const rt: RType = { kind: 'project', dir: pkg.dir, name };
          const have2 = methodNames(rt);
          if ([...need].every((m) => have2.has(m))) out.push(rt);
        }
      }
    }
    implCache.set(key, out);
    return out;
  }
  function methodIds(rt: RType, name: string, depth = 0): string[] {
    if (rt.kind !== 'project') return [];
    const direct = packages.get(rt.dir)?.methods.get(rt.name)?.get(name);
    if (direct) return [direct];
    const decl = declOf(rt);
    if (!decl) return [];
    const out: string[] = [];
    if (decl.kind === 'interface') {
      for (const impl of implementers(rt)) out.push(...methodIds(impl, name, depth + 1));
      return out.slice(0, 20);
    }
    if (depth < 3) for (const e of decl.embedded) {
      const et = resolveType(e, rt.dir);
      if (et) out.push(...methodIds(et, name, depth + 1));
    }
    return out;
  }
  const parentOf = (fn: GoFunc): GoFunc | undefined => (fn.info.parentId ? funcsById.get(fn.info.parentId) : undefined);
  /** declared type of a name visible in the function: parameters, receiver, locals, enclosing functions, package-level vars */
  function envSrc(fn: GoFunc, name: string): { src: GoTypeSrc; fn: GoFunc } | undefined {
    for (let f: GoFunc | undefined = fn; f; f = parentOf(f)) {
      const src = f.localTypes.get(name);
      if (src) return { src, fn: f };
    }
    for (const file of packages.get(dirOf(fn))?.files ?? []) {
      const src = file.fileFunc.localTypes.get(name);
      if (src) return { src, fn: file.fileFunc };
    }
    return undefined;
  }
  function envType(fn: GoFunc, name: string, depth: number): RType | undefined {
    const e = envSrc(fn, name);
    return e ? typeOfSrc(e.fn, e.src, depth) : undefined;
  }
  function typeOfSrc(fn: GoFunc, src: GoTypeSrc, depth: number): RType | undefined {
    if (depth > MAX_DEPTH) return undefined;
    switch (src.kind) {
      case 'type':
        return resolveType(src.type, dirOf(fn));
      case 'literal':
        return undefined;
      case 'call':
        return callResult(fn, src.ref, src.index, depth + 1);
      case 'expr': {
        let t = baseType(fn, src.base, depth + 1);
        for (const f of src.fields) {
          if (!t) return undefined;
          t = fieldType(t, f, 0);
        }
        return t;
      }
    }
  }
  function baseType(fn: GoFunc, base: GoBase, depth: number): RType | undefined {
    switch (base.kind) {
      case 'ident':
        return envType(fn, base.name, depth);
      case 'call':
        return base.ref.kind === 'call' ? callResult(fn, base.ref.ref, 0, depth + 1) : undefined;
      case 'type':
        return resolveType(base.type, dirOf(fn));
      default:
        return undefined;
    }
  }
  /** type of the n-th result of a call */
  function callResult(fn: GoFunc, callee: GoRef, index: number, depth: number): RType | undefined {
    if (depth > MAX_DEPTH) return undefined;
    const r = resolveRef(fn, callee, depth + 1);
    const id = r.ids[0];
    if (id) {
      const target = funcsById.get(id);
      const res = target?.results[index];
      if (!target) return undefined;
      if (res) return resolveType(res, dirOf(target));
      // a conversion `T(x)` or a factory with an untyped result
      return undefined;
    }
    if (r.target?.kind === 'external') return { kind: 'external', path: (r.target as GoExternalTarget).packagePath, name: ctorTypeName(callee) };
    if (callee.kind === 'ident') {
      // conversion to a project type: `Handler(fn)`
      const rt = resolveType({ name: callee.name, text: callee.name }, dirOf(fn));
      if (rt) return rt;
    }
    return undefined;
  }

  /** the type an external constructor most likely returns, from its name (NewDecoder -> Decoder) */
  const ctorTypeName = (callee: GoRef): string | undefined => {
    const name = callee.kind === 'pkg' || callee.kind === 'method' ? callee.name : undefined;
    const m = name ? /^New([A-Z]\w*)$/.exec(name) : null;
    return m ? m[1] : undefined;
  };

  interface Resolved {
    ids: string[];
    target?: CallTarget;
  }
  const noIds: Resolved = { ids: [] };
  /** functions a reference can name, and the call target to record for it */
  function resolveRef(fn: GoFunc, ref: GoRef, depth: number): Resolved {
    if (depth > MAX_DEPTH) return noIds;
    switch (ref.kind) {
      case 'ident': {
        const e = envSrc(fn, ref.name);
        if (e?.src.kind === 'literal') return { ids: [e.src.id], target: { kind: 'local', name: '<func>' } };
        if (e?.src.kind === 'call' && e.src.ref.kind === 'literal') return { ids: [e.src.ref.id], target: { kind: 'local', name: '<func>' } };
        if (e) return { ids: [], target: { kind: 'unknown', text: ref.name } }; // a function value we cannot follow
        const id = packages.get(dirOf(fn))?.funcs.get(ref.name);
        return id ? { ids: [id], target: { kind: 'local', name: ref.name } } : { ids: [], target: { kind: 'unknown', text: ref.name } };
      }
      case 'pkg': {
        const dir = dirOfImport(ref.path);
        if (dir !== undefined) {
          const id = packages.get(dir)?.funcs.get(ref.name);
          return { ids: id ? [id] : [], target: { kind: 'local', name: ref.name, file: dir } };
        }
        return { ids: [], target: externalTarget(ref.path, ref.name) };
      }
      case 'method': {
        let t = baseType(fn, ref.base, depth + 1);
        for (const f of ref.fields) {
          if (!t) break;
          t = fieldType(t, f, 0);
        }
        if (t?.kind === 'project') {
          const ids = methodIds(t, ref.name);
          return { ids, target: { kind: 'local', name: `${t.name}.${ref.name}`, file: t.dir } };
        }
        if (t?.kind === 'external') return { ids: [], target: externalTarget(t.path, ref.name, t.name) };
        // a method on a value produced by an external call: json.NewDecoder(r.Body).Decode(&x)
        if (ref.base.kind === 'call' && ref.base.ref.kind === 'call' && !ref.fields.length) {
          const inner = resolveRef(fn, ref.base.ref.ref, depth + 1);
          if (inner.target?.kind === 'external') return { ids: [], target: externalTarget((inner.target as GoExternalTarget).packagePath, ref.name, ctorTypeName(ref.base.ref.ref)) };
        }
        const text = `${ref.base.kind === 'ident' ? ref.base.name : ref.base.kind === 'call' ? '(call)' : ref.base.kind === 'type' ? ref.base.type.name : ref.base.text}${ref.fields.map((f) => '.' + f).join('')}.${ref.name}`;
        return { ids: [], target: { kind: 'unknown', text: text.slice(0, 40) } };
      }
      case 'literal':
        return { ids: [ref.id], target: { kind: 'local', name: '<func>' } };
      case 'type': {
        const rt = resolveType(ref.type, dirOf(fn));
        return rt ? { ids: methodIds(rt, 'ServeHTTP'), target: { kind: 'local', name: `${ref.type.name}.ServeHTTP` } } : noIds;
      }
      case 'call':
        return resolveRef(fn, ref.ref, depth + 1);
      default:
        return noIds;
    }
  }

  // ---- call targets, edges ----
  const functions = new Map<string, FunctionInfo>();
  const edges = new Map<string, Set<string>>();
  const edgeInput = new Map<string, Set<string>>();
  const edgeSites = new Map<string, Map<string, CallSite[]>>();
  const allFns = [...funcsById.values()];
  for (const fn of allFns) {
    functions.set(fn.info.id, fn.info);
    const set = new Set<string>();
    const input = new Set<string>();
    const sites = new Map<string, CallSite[]>();
    fn.info.calls.forEach((c, i) => {
      const ref = fn.refs[i]!;
      const r = resolveRef(fn, ref, 0);
      if (r.target) c.target = r.target;
      for (const id of r.ids) {
        set.add(id);
        if (c.userInput) input.add(id);
        (sites.get(id) ?? sites.set(id, []).get(id)!).push(c);
      }
    });
    for (const id of fn.literals) set.add(id);
    if (set.size) edges.set(fn.info.id, set);
    if (input.size) edgeInput.set(fn.info.id, input);
    if (sites.size) edgeSites.set(fn.info.id, sites);
  }

  // ---- guards ----
  const refLabel = (ref: GoRef): string => {
    switch (ref.kind) {
      case 'ident':
        return ref.name;
      case 'pkg':
        return `${pathBase(ref.path)}.${ref.name}`;
      case 'method':
        return `${ref.base.kind === 'ident' ? ref.base.name : ref.base.kind === 'call' && ref.base.ref.kind === 'call' ? ref.base.ref.text : ''}${ref.fields.map((f) => '.' + f).join('')}.${ref.name}`;
      case 'call':
        return ref.text;
      case 'literal':
        return '<func>';
      case 'type':
        return ref.type.name;
      default:
        return ref.text;
    }
  };
  /** the guard label for a middleware expression: its text when it looks like one, or when the function it names rejects requests */
  function guardLabel(fn: GoFunc, cand: GoGuardCand): string | undefined {
    const t = cand.text.slice(0, 300);
    const last = t.replace(/\(.*$/s, '').split('.').pop() ?? t;
    if (NON_GUARD_RE.test(last) || GO_NON_GUARD_RE.test(t) || NOT_GUARD_RE.test(t)) return undefined;
    if (AUTH.test(t)) return cand.text;
    const r = resolveRef(fn, cand.ref, 0);
    if (r.ids.some((id) => funcsById.get(id)?.rejects)) return cand.text;
    return undefined;
  }
  const labels = (fn: GoFunc, cands: GoGuardCand[]): string[] => cands.map((c) => guardLabel(fn, c)).filter((x): x is string => !!x);

  // ---- mounts: function id + parameter position (or 'ret') -> router expressions handed to it ----
  const mountsByTarget = new Map<string, { fn: GoFunc; router: { ident: string; prefix: string; guards: GoGuardCand[]; line: number } }[]>();
  for (const fn of allFns) {
    for (const m of fn.mounts) {
      const r = resolveRef(fn, m.target, 0);
      for (const id of r.ids) {
        const key = `${id}|${m.returned ? 'ret' : m.paramIndex ?? 0}`;
        (mountsByTarget.get(key) ?? mountsByTarget.set(key, []).get(key)!).push({ fn, router: m.router });
      }
    }
  }
  const routerOf = (fn: GoFunc, ident: string) => {
    for (let f: GoFunc | undefined = fn; f; f = parentOf(f)) {
      const r = f.routers.get(ident);
      if (r) return { router: r, fn: f };
    }
    for (const file of packages.get(dirOf(fn))?.files ?? []) {
      const r = file.fileFunc.routers.get(ident);
      if (r) return { router: r, fn: file.fileFunc };
    }
    return undefined;
  };
  /** `Use` guards on a router identifier that apply to a registration at `atLine` */
  function useGuards(fn: GoFunc, ident: string, atLine: number, framework: string, kind: string): string[] {
    const all = framework === 'gorilla' || (framework === 'echo' && kind === 'root');
    const out: string[] = [];
    for (const u of fn.uses) if (u.ident === ident && (all || u.line < atLine)) out.push(...labels(fn, u.guards));
    return out;
  }
  const add = (chains: Chain[], prefix: string, guards: string[]): Chain[] => chains.map((c) => ({ prefix: joinPath(c.prefix, prefix), guards: [...c.guards, ...guards], mounted: c.mounted }));
  const ROOT: Chain[] = [{ prefix: '', guards: [], mounted: true }];
  function chainsOf(fn: GoFunc, ident: string, atLine: number, depth: number): Chain[] {
    if (depth > MAX_DEPTH) return ROOT;
    const found = routerOf(fn, ident);
    if (!found) {
      // a router returned by another function: api := apiRoutes(); api.Get(...)
      const e = envSrc(fn, ident);
      if (e?.src.kind === 'call') {
        const r = resolveRef(e.fn, e.src.ref, 0);
        const target = r.ids[0] ? funcsById.get(r.ids[0]) : undefined;
        if (target?.returnsIdent) return chainsOf(target, target.returnsIdent, Number.MAX_SAFE_INTEGER, depth + 1);
      }
      return ROOT;
    }
    const { router: r, fn: owner } = found;
    const own = { prefix: r.prefix, guards: [...labels(owner, r.guards), ...useGuards(owner, ident, atLine, r.framework, r.kind)] };
    let base: Chain[];
    if (r.mountedOn) base = add(chainsOf(owner, r.mountedOn.ident, r.mountedOn.line, depth + 1), r.mountedOn.prefix, []);
    else if (r.kind === 'group' && r.parent) base = chainsOf(owner, r.parent, r.line, depth + 1);
    else if (r.kind === 'param') {
      const mounts = mountsByTarget.get(`${owner.info.id}|${r.paramIndex ?? 0}`) ?? [];
      base = mounts.length ? mounts.flatMap((m) => add(chainsOf(m.fn, m.router.ident, m.router.line, depth + 1), m.router.prefix, labels(m.fn, m.router.guards))) : [{ prefix: '', guards: [], mounted: false }];
    } else {
      const mounts = owner.returnsIdent === ident ? mountsByTarget.get(`${owner.info.id}|ret`) ?? [] : [];
      base = mounts.length ? mounts.flatMap((m) => add(chainsOf(m.fn, m.router.ident, m.router.line, depth + 1), m.router.prefix, labels(m.fn, m.router.guards))) : ROOT;
    }
    return add(base, own.prefix, own.guards);
  }

  // ---- handlers ----
  interface Handler {
    ids: string[];
    guards: string[];
    unresolved: string[];
  }
  function resolveHandler(fn: GoFunc, ref: GoRef, depth: number): Handler {
    const none = (text: string): Handler => ({ ids: [], guards: [], unresolved: [text.slice(0, 60)] });
    if (depth > 6) return none(refLabel(ref));
    if (ref.kind === 'call') {
      const callee = ref.ref;
      if (callee.kind === 'pkg' && callee.path === 'net/http') {
        if ((callee.name === 'HandlerFunc' || callee.name === 'TimeoutHandler' || callee.name === 'MaxBytesHandler') && ref.args[0]) return resolveHandler(fn, ref.args[0], depth + 1);
        if (callee.name === 'StripPrefix' && ref.args[1]) return resolveHandler(fn, ref.args[1], depth + 1);
        return none(ref.text);
      }
      // a wrapper: mw(handler) / mid.Use(handler, mid.RequirePermission(...)); otherwise a factory returning the handler
      const guards: string[] = [];
      const inner = ref.args.map((a) => {
        if (a.kind === 'none') return none('');
        const g = guardLabel(fn, { text: refLabel(a), ref: a });
        if (g) {
          guards.push(g);
          return none('');
        }
        return resolveHandler(fn, a, depth + 1);
      });
      const wrapped = inner.filter((h) => h.ids.length);
      if (wrapped.length) {
        const g = guardLabel(fn, { text: refLabel(callee), ref: callee });
        if (g) guards.unshift(g);
        // mid.Use(handler, mw...): the first function argument is the handler, the rest are middleware
        const [handler, ...rest] = wrapped;
        for (const mw of rest) for (const id of mw.ids) if (funcsById.get(id)?.rejects) guards.push(mw.unresolved[0] ?? refLabel(ref.args[inner.indexOf(mw)]!));
        return { ids: handler!.ids, guards: [...guards, ...handler!.guards], unresolved: [] };
      }
      const r = resolveRef(fn, callee, depth + 1);
      if (r.ids.length) return { ids: r.ids, guards: [], unresolved: [] };
      // a value whose type implements http.Handler: router.PathPrefix("/api/").Handler(api.NewServer(...))
      const rt = callResult(fn, callee, 0, depth + 1);
      const serve = rt ? methodIds(rt, 'ServeHTTP') : [];
      return serve.length ? { ids: serve, guards: [], unresolved: [] } : none(ref.text);
    }
    const r = resolveRef(fn, ref, depth + 1);
    if (r.ids.length) return { ids: r.ids, guards: [], unresolved: [] };
    // a value (variable or field) whose type implements http.Handler
    let rt: RType | undefined;
    if (ref.kind === 'ident') rt = envType(fn, ref.name, depth + 1);
    else if (ref.kind === 'method') {
      rt = baseType(fn, ref.base, depth + 1);
      for (const f of [...ref.fields, ref.name]) rt = rt ? fieldType(rt, f, 0) : undefined;
    }
    const serve = rt ? methodIds(rt, 'ServeHTTP') : [];
    return serve.length ? { ids: serve, guards: [], unresolved: [] } : none(refLabel(ref));
  }

  // ---- entry points ----
  const entryPoints: EntryPoint[] = [];
  for (const fn of allFns) {
    const file = fileOfFn.get(fn.info.id)!;
    for (const route of fn.routes) {
      const handlerIds: string[] = [];
      const unresolved: string[] = [];
      const routeGuards = labels(fn, route.guards);
      for (const h of route.handlers) {
        const r = resolveHandler(fn, h, 0);
        for (const id of r.ids) if (!handlerIds.includes(id)) handlerIds.push(id);
        routeGuards.push(...r.guards);
        unresolved.push(...r.unresolved.filter((u) => u));
      }
      if (!handlerIds.length && !unresolved.length) continue;
      const found = routerOf(fn, route.ident);
      const uses = found ? [] : useGuards(fn, route.ident, route.line, 'unknown', 'root');
      const chains = route.ident ? chainsOf(fn, route.ident, route.line, 0) : ROOT;
      for (const ch of chains) {
        for (const method of route.methods) {
          const guards = [...new Set([...ch.guards, ...uses, ...routeGuards])];
          const path = joinPath(ch.prefix, route.path);
          if (internal.has(`${method} ${path}`.toUpperCase())) guards.push('internal (nextfix.config.json)');
          entryPoints.push({ method, path, file: file.rel, line: route.line, authenticated: guards.length > 0, guards, mounted: ch.mounted, handlerIds, unresolvedHandlers: unresolved.length ? unresolved : undefined });
        }
      }
    }
  }

  // ---- packages imported, modules, listen ----
  const packagesImported = new Map<string, Set<string>>();
  const jsModules = new Map<string, any>();
  const rootApps: string[] = [];
  let listens = 0;
  let localListens = 0;
  for (const info of infos) {
    for (const i of info.imports) {
      if (dirOfImport(i.path) !== undefined) continue;
      const key = modulePrefix(i.path);
      (packagesImported.get(key) ?? packagesImported.set(key, new Set()).get(key)!).add(info.rel);
    }
    listens += info.listens.length;
    localListens += info.listens.filter((l) => l).length;
    const fns = [info.fileFunc, ...info.funcs];
    const appIdents = new Set<string>();
    const routes: any[] = [];
    for (const fn of fns) {
      for (const [name, r] of fn.routers) if (r.kind === 'root' && r.framework !== 'unknown') appIdents.add(name);
      for (const r of fn.routes) routes.push({ method: r.methods[0]?.toLowerCase() ?? 'get', path: r.path, line: r.line, app: r.ident, guards: r.guards.map((g) => g.text), middleware: [], handlerIds: [], unresolved: r.unresolved });
    }
    const isRootApp = appIdents.size > 0;
    if (isRootApp) rootApps.push(info.rel);
    jsModules.set(info.rel, { file: info.file, rel: info.rel, imports: [], functions: fns.map((f) => f.info), moduleFunctionId: info.fileFunc.info.id, routes, appIdents, isRootApp, exports: new Map(), reexports: [], listens: info.listens.length > 0, autoload: [], hookGuards: [] });
  }

  return { rootDir, modules: jsModules, functions, edges, edgeInput, edgeSites, entryPoints, packagesImported, rootApps, listenLocalOnly: listens > 0 && localListens === listens };
}
