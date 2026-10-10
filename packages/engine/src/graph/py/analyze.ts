import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { parsePython, stringValue, walk, type Node } from './parser.ts';
import { distForModule } from './packages.ts';
import type { CallArg, CallSite, CallTarget, FunctionInfo } from '../js/analyze.ts';

/** Guard-shaped names in Python web code (decorators, dependencies, mixins, permission classes). */
export const PY_GUARD_RE = /auth|login_?required|logged|permission|role|current_?user|active_?user|superuser|token|jwt|oauth|bearer|api_?key|is_?admin|require|protect|guard|verify|session_?required|staff_?member/i;
const PY_NOT_GUARD_RE = /unauthenticated|allow_?any|anonymous|optional|unprotected|public|requestform|passwordrequest/i;
const GUARD_BODY_RE = /abort\(\s*40[13]|40[13]|unauthorized|forbidden|PermissionDenied|HTTPException|raise\b|redirect\(url_for\(['"][\w.]*login/i;
const HTTP = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace']);
const REQ = new Set(['request', 'req', 'ctx']);

export interface PyImport {
  local: string;
  /** dotted module as written, resolved against the importing file for relative imports */
  module: string;
  /** imported member (from X import member); undefined when the whole module is bound */
  member?: string;
  /** file the module resolves to, when it is project code */
  file?: string;
  /** top-level distribution when it is an installed package */
  dist?: string;
  line: number;
}

export interface PyRoute {
  methods: string[];
  path: string;
  line: number;
  /** app / blueprint / router identifier the route is registered on */
  app: string;
  guards: string[];
  handlerIds: string[];
  unresolved: string[];
  kind: 'flask' | 'fastapi' | 'django';
}

export interface PyMount {
  kind: 'blueprint' | 'router' | 'include';
  /** identifier (same file or imported) of the blueprint / router, or dotted module for include() */
  target: string;
  /** member on an imported module (`users.router`) */
  member?: string;
  prefix: string;
  guards: string[];
  onto: string;
  line: number;
}

export interface PyAppIdent {
  kind: 'app' | 'blueprint' | 'router';
  framework: 'flask' | 'fastapi' | 'django';
  prefix: string;
  guards: string[];
}

export interface PyClassInfo {
  name: string;
  bases: string[];
  guards: string[];
  /** method name -> function id */
  methods: Map<string, string>;
}

export interface PyModuleInfo {
  file: string;
  rel: string;
  imports: PyImport[];
  functions: FunctionInfo[];
  moduleFunctionId: string;
  routes: PyRoute[];
  mounts: PyMount[];
  appIdents: Map<string, PyAppIdent>;
  /** names defined at module level (functions, classes, assignments) -> function id when it is a function */
  defs: Map<string, string | undefined>;
  classes: Map<string, PyClassInfo>;
  /** before_request-style hooks with a rejecting body, by app identifier */
  hookGuards: Map<string, string[]>;
  /** guard decorators per function id (Django views are routed from another module) */
  functionGuards: Map<string, string[]>;
  /** Django: this module defines urlpatterns */
  isUrlconf: boolean;
  isRootApp: boolean;
}

export interface PyAnalyzeOptions {
  rootDir: string;
  installed: Set<string>;
  authRe?: RegExp;
}

function isFunctionLike(n: Node): boolean {
  return n.type === 'function_definition' || n.type === 'lambda';
}

/** Candidate directories a dotted import is resolved against. */
function pythonRoots(file: string, rootDir: string): string[] {
  const roots = new Set<string>();
  // the package root above this file (walk up while __init__.py exists)
  let dir = dirname(file);
  while (existsSync(join(dir, '__init__.py')) && dir !== rootDir && dir.length > rootDir.length) dir = dirname(dir);
  roots.add(dir);
  roots.add(rootDir);
  for (const sub of ['src', 'app', 'backend', 'server', 'api']) roots.add(join(rootDir, sub));
  return [...roots];
}

export function resolveModule(dotted: string, fromFile: string, rootDir: string): string | undefined {
  const parts = dotted.split('.');
  for (const root of pythonRoots(fromFile, rootDir)) {
    const base = join(root, ...parts);
    for (const cand of [`${base}.py`, join(base, '__init__.py')]) {
      if (existsSync(cand) && statSync(cand).isFile()) return cand;
    }
  }
  return undefined;
}

/** `.models` / `..utils` relative to the importing file's package. */
function absolutize(module: string, fromFile: string, rootDir: string): string {
  const m = /^(\.+)(.*)$/.exec(module);
  if (!m) return module;
  let dir = dirname(fromFile);
  for (let i = 1; i < m[1]!.length; i++) dir = dirname(dir);
  const rest = m[2] ?? '';
  const relDir = relative(rootDir, dir).replace(/\\/g, '/').split('/').filter(Boolean);
  return [...relDir, ...(rest ? rest.split('.') : [])].join('.');
}

/** Django `users/<int:pk>/` → `/users/:pk`. */
export function djangoPath(p: string): string {
  const s = p.replace(/<(?:[\w.]+:)?(\w+)>/g, ':$1').replace(/^\^/, '').replace(/\$$/, '').replace(/\(\?P<(\w+)>[^)]*\)/g, ':$1');
  return '/' + s.replace(/^\/+/, '').replace(/\/+$/, '');
}

export async function analyzePyModule(file: string, opts: PyAnalyzeOptions): Promise<PyModuleInfo> {
  const { rootDir } = opts;
  const AUTH = opts.authRe ? new RegExp(`${PY_GUARD_RE.source}|${opts.authRe.source}`, 'i') : PY_GUARD_RE;
  const isGuard = (t: string) => !PY_NOT_GUARD_RE.test(t) && AUTH.test(t);
  const text = readFileSync(file, 'utf8');
  const tree = await parsePython(text);
  const root = tree.rootNode;
  const rel = relative(rootDir, file).replace(/\\/g, '/');
  const line = (n: Node) => n.startPosition.row + 1;
  const col = (n: Node) => n.startPosition.column + 1;

  const mod: PyModuleInfo = {
    file,
    rel,
    imports: [],
    functions: [],
    moduleFunctionId: `${rel}#<module>`,
    routes: [],
    mounts: [],
    appIdents: new Map(),
    defs: new Map(),
    classes: new Map(),
    hookGuards: new Map(),
    functionGuards: new Map(),
    isUrlconf: false,
    isRootApp: false,
  };
  const importsByLocal = new Map<string, PyImport>();

  // ---- imports ----
  const addImport = (local: string, module: string, member: string | undefined, ln: number) => {
    let abs = absolutize(module, file, rootDir);
    let mem = member;
    // `from app.api.routes import users`: the member may itself be a module.
    let file2 = member && member !== '*' ? resolveModule(`${abs}.${member}`, file, rootDir) : undefined;
    if (file2) {
      abs = `${abs}.${member}`;
      mem = undefined;
    } else file2 = resolveModule(abs, file, rootDir);
    const top = abs.split('.')[0]!;
    const imp: PyImport = { local, module: abs, member: mem, file: file2, dist: file2 ? undefined : distForModule(top, opts.installed), line: ln };
    mod.imports.push(imp);
    importsByLocal.set(local, imp);
  };
  walk(root, (n) => {
    if (n.type === 'import_statement') {
      for (const c of n.namedChildren) {
        if (c.type === 'dotted_name') addImport(c.text.split('.')[0]!, c.text, undefined, line(n));
        else if (c.type === 'aliased_import') {
          const name = c.childForFieldName('name')?.text ?? '';
          const alias = c.childForFieldName('alias')?.text ?? name;
          addImport(alias, name, undefined, line(n));
        }
      }
      return false;
    }
    if (n.type === 'import_from_statement') {
      const modName = n.childForFieldName('module_name')?.text ?? '';
      const names = n.namedChildren.filter((c) => c !== n.childForFieldName('module_name'));
      if (n.text.includes('import *')) addImport('*', modName, '*', line(n));
      for (const c of names) {
        if (c.type === 'dotted_name') addImport(c.text, modName, c.text, line(n));
        else if (c.type === 'aliased_import') {
          const name = c.childForFieldName('name')?.text ?? '';
          const alias = c.childForFieldName('alias')?.text ?? name;
          addImport(alias, modName, name, line(n));
        }
      }
      return false;
    }
    // imports inside functions (Flask create_app factories) count too
    return true;
  });

  // ---- functions, classes, module-level definitions ----
  const fnByNode = new Map<number, FunctionInfo>(); // keyed by node id: tree-sitter wrappers are not identity-stable
  const moduleFn: FunctionInfo = { id: mod.moduleFunctionId, name: '<module>', file: rel, line: 1, col: 1, params: [], calls: [] };
  mod.functions.push(moduleFn);
  const fnStack: FunctionInfo[] = [];
  const classStack: PyClassInfo[] = [];
  const paramsOf = (fn: Node): string[] => {
    const ps = fn.childForFieldName('parameters');
    if (!ps) return [];
    const out: string[] = [];
    for (const p of ps.namedChildren) {
      const id = p.type === 'identifier' ? p : p.childForFieldName('name') ?? p.namedChildren.find((c) => c.type === 'identifier');
      if (id && id.type === 'identifier' && id.text !== 'self' && id.text !== 'cls') out.push(id.text);
    }
    return out;
  };
  const visitDefs = (n: Node) => {
    if (n.type === 'class_definition') {
      const name = n.childForFieldName('name')?.text ?? '<class>';
      const bases = (n.childForFieldName('superclasses')?.namedChildren ?? []).map((b) => b.text);
      const info: PyClassInfo = { name, bases, guards: bases.filter((b) => isGuard(b) && /mixin|permission|auth/i.test(b)), methods: new Map() };
      mod.classes.set(name, info);
      if (!fnStack.length) mod.defs.set(name, undefined);
      classStack.push(info);
      for (const c of n.childForFieldName('body')?.namedChildren ?? []) visitDefs(c);
      classStack.pop();
      return;
    }
    if (n.type === 'decorated_definition') {
      const def = n.childForFieldName('definition');
      const decorators = n.namedChildren.filter((c) => c.type === 'decorator');
      if (def?.type === 'class_definition') {
        visitDefs(def);
        const cls = mod.classes.get(def.childForFieldName('name')?.text ?? '');
        for (const d of decorators) {
          const t = d.text.slice(1);
          if (cls && /method_decorator\(/.test(t) && isGuard(t)) cls.guards.push(t);
        }
        return;
      }
      if (def?.type === 'function_definition') {
        visitFunction(def, decorators);
        return;
      }
    }
    if (n.type === 'function_definition') {
      visitFunction(n, []);
      return;
    }
    if (n.type === 'expression_statement') {
      const a = n.namedChildren[0];
      if (a?.type === 'assignment') {
        const left = a.childForFieldName('left');
        const right = a.childForFieldName('right');
        if (left?.type === 'identifier') {
          // `app = Flask(__name__)` counts inside a create_app() factory too; module-level names only become defs
          if (!fnStack.length) mod.defs.set(left.text, undefined);
          if (right) classifyAssignment(left.text, right);
          if (left.text === 'urlpatterns' && !fnStack.length) mod.isUrlconf = true;
        }
      } else if (a?.type === 'augmented_assignment' && a.childForFieldName('left')?.text === 'urlpatterns' && !fnStack.length) mod.isUrlconf = true;
    }
    if (n.type === 'lambda') {
      visitFunction(n, []);
      return;
    }
    for (const c of n.namedChildren) visitDefs(c);
  };
  const fnNodes: Node[] = [];
  function visitFunction(def: Node, decorators: Node[]) {
    fnNodes.push(def);
    const name = def.type === 'lambda' ? '<lambda>' : def.childForFieldName('name')?.text ?? '<anon>';
    const info: FunctionInfo = { id: `${rel}#${classStack.length ? classStack[classStack.length - 1]!.name + '.' : ''}${name}@${line(def)}:${col(def)}`, name, file: rel, line: line(def), col: col(def), params: paramsOf(def), calls: [], parentId: fnStack[fnStack.length - 1]?.id };
    fnByNode.set(def.id, info);
    mod.functions.push(info);
    const cls = classStack[classStack.length - 1];
    if (cls && !fnStack.length) cls.methods.set(name, info.id);
    else if (!fnStack.length && !cls) mod.defs.set(name, info.id);
    for (const d of decorators) handleDecorator(d, info, def);
    fnStack.push(info);
    for (const c of def.childForFieldName('body')?.namedChildren ?? []) visitDefs(c);
    fnStack.pop();
  }

  // ---- app / blueprint / router identifiers ----
  function classifyAssignment(name: string, right: Node) {
    if (right.type !== 'call') return;
    const fn = right.childForFieldName('function');
    const callee = fn?.text ?? '';
    const args = right.childForFieldName('arguments');
    const kw = (k: string) => args?.namedChildren.find((c) => c.type === 'keyword_argument' && c.childForFieldName('name')?.text === k)?.childForFieldName('value');
    const bound = fn?.type === 'identifier' ? importsByLocal.get(fn.text) : fn?.type === 'attribute' ? importsByLocal.get(fn.childForFieldName('object')?.text ?? '') : undefined;
    const fromDist = bound?.dist ?? (fn?.type === 'attribute' ? fn.childForFieldName('object')?.text : undefined);
    const last = callee.split('.').pop() ?? '';
    const prefix = stringValue(kw('url_prefix') ?? kw('prefix')) ?? (kw('prefix') ? `/{${kw('prefix')!.text.split('.').pop()}}` : '');
    const guards = dependencyGuards(kw('dependencies'));
    if (last === 'Flask' && (fromDist === 'flask' || !bound)) {
      mod.appIdents.set(name, { kind: 'app', framework: 'flask', prefix: '', guards: [] });
      mod.isRootApp = true;
    } else if (last === 'Blueprint') {
      mod.appIdents.set(name, { kind: 'blueprint', framework: 'flask', prefix, guards: [] });
    } else if (last === 'FastAPI') {
      mod.appIdents.set(name, { kind: 'app', framework: 'fastapi', prefix: '', guards });
      mod.isRootApp = true;
    } else if (last === 'APIRouter') {
      mod.appIdents.set(name, { kind: 'router', framework: 'fastapi', prefix, guards });
    }
  }
  function dependencyGuards(v: Node | null | undefined): string[] {
    if (!v) return [];
    const out: string[] = [];
    walk(v, (c) => {
      if (c.type === 'call' && /\bDepends$/.test(c.childForFieldName('function')?.text ?? '')) {
        const t = c.text.replace(/\s+/g, ' ').slice(0, 80);
        if (isGuard(t)) out.push(t);
        return false;
      }
      return true;
    });
    return out;
  }

  // ---- decorators: routes, guards, hooks ----
  function appOf(ident: string): PyAppIdent | undefined {
    const own = mod.appIdents.get(ident);
    if (own) return own;
    const imp = importsByLocal.get(ident);
    if (imp?.file) return { kind: 'blueprint', framework: 'flask', prefix: '', guards: [] }; // resolved at project level
    if (/^(app|bp|blueprint|router|api_router|api)$/i.test(ident)) return { kind: 'app', framework: 'flask', prefix: '', guards: [] };
    return undefined;
  }
  function handleDecorator(d: Node, info: FunctionInfo, def: Node) {
    const expr = d.namedChildren[0];
    if (!expr) return;
    const t = d.text.slice(1).replace(/\s+/g, ' ');
    const isCall = expr.type === 'call';
    const fnNode = isCall ? expr.childForFieldName('function') : expr;
    const args = isCall ? expr.childForFieldName('arguments') : null;
    const kw = (k: string) => args?.namedChildren.find((c) => c.type === 'keyword_argument' && c.childForFieldName('name')?.text === k)?.childForFieldName('value');
    const positional = args?.namedChildren.filter((c) => c.type !== 'keyword_argument') ?? [];

    if (fnNode?.type === 'attribute') {
      const recv = fnNode.childForFieldName('object')?.text ?? '';
      const attr = fnNode.childForFieldName('attribute')?.text ?? '';
      const app = appOf(recv);
      if (app && (attr === 'route' || attr === 'api_route' || HTTP.has(attr) || attr === 'websocket')) {
        // Flask `<int:id>` / `<username>` → `:id` / `:username`; FastAPI keeps `{item_id}`
        const raw = stringValue(positional[0]) ?? (positional[0] ? `{${positional[0].text.slice(0, 30)}}` : '/');
        const path = app.framework === 'fastapi' ? raw : raw.replace(/<(?:[\w.]+:)?(\w+)>/g, ':$1');
        let methods: string[] = HTTP.has(attr) ? [attr.toUpperCase()] : ['GET'];
        const m = kw('methods');
        if (m) methods = m.namedChildren.map((c) => stringValue(c)?.toUpperCase()).filter((x): x is string => !!x);
        const guards = [...dependencyGuards(kw('dependencies')), ...(mod.hookGuards.get(recv) ?? [])];
        mod.routes.push({ methods, path, line: line(d), app: recv, guards, handlerIds: [info.id], unresolved: [], kind: app.framework === 'fastapi' ? 'fastapi' : 'flask' });
        return;
      }
      if (app && /^before_(app_)?request$/.test(attr)) {
        if (GUARD_BODY_RE.test(def.text)) {
          const list = mod.hookGuards.get(recv) ?? [];
          list.push(`${info.name}() (${rel}:${info.line})`);
          mod.hookGuards.set(recv, list);
        }
        return;
      }
    }
    // guard decorators: @login_required, @jwt_required(), @auth.login_required, @permission_required('x'),
    // DRF @permission_classes([IsAuthenticated]); not @api_view, @require_http_methods, @csrf_exempt
    if (/permission_classes\(/.test(t)) {
      if (!/AllowAny/.test(t)) pendingGuards(info).push(t);
      return;
    }
    if (isGuard(t) && !/^(api_view|require_http_methods|csrf_exempt|require_(GET|POST)|cache_page|ratelimit)/.test(t)) pendingGuards(info).push(t);
  }
  const guardsByFn = mod.functionGuards;
  const pendingGuards = (info: FunctionInfo) => guardsByFn.get(info.id) ?? guardsByFn.set(info.id, []).get(info.id)!;

  visitDefs(root);
  // decorators are visited before the route is pushed in some orders; attach function-level guards now
  for (const r of mod.routes) for (const h of r.handlerIds) for (const g of guardsByFn.get(h) ?? []) if (!r.guards.includes(g)) r.guards.push(g);
  // FastAPI: a handler parameter with Depends(...) or an Annotated CurrentUser-style type is a guard
  for (const r of mod.routes) {
    const defNode = fnNodes.find((d) => fnByNode.get(d.id)?.id === r.handlerIds[0]);
    const ps = defNode?.childForFieldName('parameters');
    for (const p of ps?.namedChildren ?? []) {
      const txt = p.text.replace(/\s+/g, ' ');
      if (/Depends\(/.test(txt) || /:\s*\w*(Current|Active)?(User|Admin|Superuser)\b/.test(txt)) if (isGuard(txt) && !r.guards.includes(txt)) r.guards.push(txt.slice(0, 80));
    }
  }

  // ---- calls, mounts, Django urlpatterns ----
  function enclosing(n: Node): { fn: FunctionInfo; node?: Node } {
    let cur = n.parent;
    while (cur) {
      const f = fnByNode.get(cur.id);
      if (f) return { fn: f, node: cur };
      cur = cur.parent;
    }
    return { fn: moduleFn };
  }
  function baseIdentifiers(n: Node, out: Set<string>) {
    switch (n.type) {
      case 'identifier':
        out.add(n.text);
        return;
      case 'attribute':
        baseIdentifiers(n.childForFieldName('object')!, out);
        return;
      case 'subscript':
        baseIdentifiers(n.childForFieldName('value')!, out);
        for (const s of n.namedChildren.slice(1)) baseIdentifiers(s, out);
        return;
      case 'call': {
        const f = n.childForFieldName('function');
        if (f?.type === 'attribute') baseIdentifiers(f.childForFieldName('object')!, out);
        for (const a of n.childForFieldName('arguments')?.namedChildren ?? []) baseIdentifiers(a, out);
        return;
      }
      case 'keyword_argument':
        baseIdentifiers(n.childForFieldName('value')!, out);
        return;
      case 'lambda':
      case 'function_definition':
        return;
      default:
        for (const c of n.namedChildren) baseIdentifiers(c, out);
    }
  }
  const flowByFn = new Map<number, { locals: Map<string, Set<string>>; origins: Map<string, string> }>();
  function flow(fnNode: Node | undefined): { locals: Map<string, Set<string>>; origins: Map<string, string> } {
    const key = fnNode?.id ?? -1;
    let f = flowByFn.get(key);
    if (f) return f;
    const raw = new Map<string, Set<string>>();
    const origins = new Map<string, string>();
    const scope = fnNode ?? root;
    walk(scope, (x) => {
      if (x !== scope && isFunctionLike(x)) return false;
      if (x.type === 'assignment' || x.type === 'augmented_assignment') {
        const left = x.childForFieldName('left');
        const right = x.childForFieldName('right');
        if (!left || !right) return true;
        const ids = new Set<string>();
        baseIdentifiers(right, ids);
        const targets = left.type === 'identifier' ? [left.text] : left.namedChildren.filter((c) => c.type === 'identifier').map((c) => c.text);
        const fromReq = [...ids].some((i) => REQ.has(i));
        for (const tgt of targets) {
          raw.set(tgt, new Set([...(raw.get(tgt) ?? []), ...ids]));
          if (fromReq && !origins.has(tgt)) origins.set(tgt, right.text.replace(/\s+/g, ' ').slice(0, 60));
          else if (!origins.has(tgt)) for (const i of ids) if (origins.has(i)) origins.set(tgt, origins.get(i)!);
        }
      }
      if (x.type === 'for_statement') {
        const left = x.childForFieldName('left');
        const right = x.childForFieldName('right');
        if (left?.type === 'identifier' && right) {
          const ids = new Set<string>();
          baseIdentifiers(right, ids);
          raw.set(left.text, new Set([...(raw.get(left.text) ?? []), ...ids]));
        }
      }
      return true;
    });
    const locals = new Map<string, Set<string>>();
    const res = (name: string, depth: number, seen: Set<string>): Set<string> => {
      if (locals.has(name)) return locals.get(name)!;
      const direct = raw.get(name);
      if (!direct) return new Set([name]);
      if (depth > 6 || seen.has(name)) return new Set();
      seen.add(name);
      const out = new Set<string>();
      for (const d of direct) if (d !== name) for (const r of res(d, depth + 1, seen)) out.add(r);
      locals.set(name, out);
      return out;
    };
    for (const k of raw.keys()) res(k, 0, new Set());
    f = { locals, origins };
    flowByFn.set(key, f);
    return f;
  }
  function callArgs(call: Node, fnNode: Node | undefined): CallArg[] {
    const f = flow(fnNode);
    return (call.childForFieldName('arguments')?.namedChildren ?? []).map((a) => {
      const ids = new Set<string>();
      baseIdentifiers(a, ids);
      const roots = new Set<string>();
      for (const id of ids) {
        const r = f.locals.get(id);
        if (r) for (const x of r) roots.add(x);
        else roots.add(id);
      }
      const origin = [...ids].map((i) => f.origins.get(i)).find((o) => o);
      return { text: a.text.replace(/\s+/g, ' ').slice(0, 60), roots: [...roots], origin };
    });
  }
  function targetFor(fnNode: Node): CallTarget | undefined {
    if (fnNode.type === 'identifier') {
      const imp = importsByLocal.get(fnNode.text);
      if (imp?.dist) return { kind: 'external', package: imp.dist, symbol: imp.member ?? 'default' };
      if (imp?.file) return { kind: 'local', name: imp.member ?? 'default', file: imp.file };
      return { kind: 'local', name: fnNode.text };
    }
    if (fnNode.type === 'attribute') {
      const obj = fnNode.childForFieldName('object');
      const attr = fnNode.childForFieldName('attribute')?.text ?? '';
      if (obj?.type === 'identifier') {
        const imp = importsByLocal.get(obj.text);
        if (imp?.dist) return { kind: 'external', package: imp.dist, symbol: imp.member ? `${imp.member}.${attr}` : attr };
        if (imp?.file) return { kind: 'local', name: attr, file: imp.file };
        if (obj.text === 'self' || obj.text === 'cls') return { kind: 'local', name: attr };
        return { kind: 'unknown', text: `${obj.text}.${attr}` };
      }
      if (obj?.type === 'attribute') {
        // pkg.sub.func(): resolve the leftmost identifier
        const ids = new Set<string>();
        baseIdentifiers(obj, ids);
        const first = [...ids][0];
        const imp = first ? importsByLocal.get(first) : undefined;
        if (imp?.dist) return { kind: 'external', package: imp.dist, symbol: attr };
        if (imp?.file) return { kind: 'local', name: attr, file: imp.file };
      }
      return { kind: 'unknown', text: fnNode.text.slice(0, 40) };
    }
    return undefined;
  }
  function mountFromCall(call: Node, enclosingFn: FunctionInfo) {
    const fn = call.childForFieldName('function');
    if (fn?.type !== 'attribute') return false;
    const recv = fn.childForFieldName('object')?.text ?? '';
    const attr = fn.childForFieldName('attribute')?.text ?? '';
    const args = call.childForFieldName('arguments');
    const kw = (k: string) => args?.namedChildren.find((c) => c.type === 'keyword_argument' && c.childForFieldName('name')?.text === k)?.childForFieldName('value');
    const positional = args?.namedChildren.filter((c) => c.type !== 'keyword_argument') ?? [];
    if (attr === 'register_blueprint' && positional[0]) {
      const target = positional[0];
      const prefix = stringValue(kw('url_prefix')) ?? '';
      if (target.type === 'identifier') mod.mounts.push({ kind: 'blueprint', target: target.text, prefix, guards: [...(mod.hookGuards.get(recv) ?? [])], onto: recv, line: line(call) });
      else if (target.type === 'attribute') mod.mounts.push({ kind: 'blueprint', target: target.childForFieldName('object')?.text ?? '', member: target.childForFieldName('attribute')?.text, prefix, guards: [...(mod.hookGuards.get(recv) ?? [])], onto: recv, line: line(call) });
      return true;
    }
    if (attr === 'include_router' && positional[0]) {
      const target = positional[0];
      const prefix = stringValue(kw('prefix')) ?? (kw('prefix') ? `/{${kw('prefix')!.text.split('.').pop()}}` : '');
      const guards = dependencyGuards(kw('dependencies'));
      if (target.type === 'identifier') mod.mounts.push({ kind: 'router', target: target.text, prefix, guards, onto: recv, line: line(call) });
      else if (target.type === 'attribute') mod.mounts.push({ kind: 'router', target: target.childForFieldName('object')?.text ?? '', member: target.childForFieldName('attribute')?.text, prefix, guards, onto: recv, line: line(call) });
      return true;
    }
    void enclosingFn;
    return false;
  }
  walk(root, (n) => {
    if (n.type === 'call') {
      const { fn, node } = enclosing(n);
      if (mountFromCall(n, fn)) return true;
      const callee = n.childForFieldName('function');
      if (!callee) return true;
      const target = targetFor(callee);
      if (target) {
        const args = callArgs(n, node);
        fn.calls.push({ line: line(n), col: col(n), text: callee.text.replace(/\s+/g, ' ').slice(0, 80), target, userInput: args.some((a) => a.roots.some((r) => REQ.has(r))), args });
      }
    }
    return true;
  });

  // ---- Django urlpatterns ----
  if (mod.isUrlconf) {
    walk(root, (n) => {
      if (n.type === 'call') {
        const callee = n.childForFieldName('function')?.text ?? '';
        const last = callee.split('.').pop();
        if (last !== 'path' && last !== 're_path' && last !== 'url') return true;
        const args = n.childForFieldName('arguments')?.namedChildren.filter((c) => c.type !== 'keyword_argument') ?? [];
        const route = stringValue(args[0]);
        const view = args[1];
        if (route === undefined || !view) return true;
        const p = djangoPath(route);
        if (view.type === 'call' && /\binclude$/.test(view.childForFieldName('function')?.text ?? '')) {
          const inc = view.childForFieldName('arguments')?.namedChildren[0];
          const dotted = stringValue(inc);
          if (dotted) mod.mounts.push({ kind: 'include', target: dotted, prefix: p, guards: [], onto: 'urlpatterns', line: line(n) });
          else if (inc?.type === 'attribute' || inc?.type === 'identifier') mod.mounts.push({ kind: 'include', target: inc.text.replace(/\.urls$/, ''), prefix: p, guards: [], onto: 'urlpatterns', line: line(n) });
          return false;
        }
        const r: PyRoute = { methods: ['ANY'], path: p, line: line(n), app: 'urlpatterns', guards: [], handlerIds: [], unresolved: [], kind: 'django' };
        if (view.type === 'call' && /\.as_view$/.test(view.childForFieldName('function')?.text ?? '')) {
          const cls = view.childForFieldName('function')!.childForFieldName('object')!;
          r.unresolved.push(`class:${cls.text}`); // resolved to the class's methods at project level
        } else if (view.type === 'identifier') {
          const imp = importsByLocal.get(view.text);
          const def = mod.defs.get(view.text);
          if (def) r.handlerIds.push(def);
          else if (imp?.file) r.handlerIds.push(`${relative(rootDir, imp.file).replace(/\\/g, '/')}#${imp.member ?? 'default'}`);
          else r.unresolved.push(view.text);
        } else if (view.type === 'attribute') {
          const obj = view.childForFieldName('object')?.text ?? '';
          const attr = view.childForFieldName('attribute')?.text ?? '';
          const imp = importsByLocal.get(obj);
          if (imp?.file) r.handlerIds.push(`${relative(rootDir, imp.file).replace(/\\/g, '/')}#${attr}`);
          else r.unresolved.push(view.text);
        } else r.unresolved.push(view.text.slice(0, 40));
        mod.routes.push(r);
        return false;
      }
      return true;
    });
  }
  return mod;
}

export { resolve as resolvePath };
export type { CallSite };
