import { readFileSync } from 'node:fs';
import { dirname, relative } from 'node:path';
import { col, line, parseGo, stringValue, walk, type Node } from './parser.ts';
import type { CallArg, CallSite, CallTarget, FunctionInfo } from '../js/analyze.ts';

export type Framework = 'nethttp' | 'gin' | 'echo' | 'chi' | 'fiber' | 'gorilla' | 'httprouter' | 'unknown';

/** A Go type as written: `pkg` is the import path when qualified, undefined for the current package and builtins. */
export interface GoType {
  pkg?: string;
  name: string;
  ptr?: boolean;
  text: string;
}

export interface GoParam {
  name: string;
  type?: GoType;
}

export interface GoImport {
  local: string;
  path: string;
  line: number;
}

export interface GoTypeDecl {
  name: string;
  kind: 'struct' | 'interface' | 'other';
  fields: Map<string, GoType>;
  embedded: GoType[];
  /** interface method names */
  methods: string[];
  line: number;
}

/** How an expression names a function, a method or a value; resolved against the project in project.ts. */
export type GoRef =
  | { kind: 'ident'; name: string }
  | { kind: 'pkg'; path: string; name: string }
  | { kind: 'method'; base: GoBase; fields: string[]; name: string }
  | { kind: 'literal'; id: string }
  | { kind: 'type'; type: GoType }
  | { kind: 'call'; ref: GoRef; args: GoRef[]; text: string }
  | { kind: 'none'; text: string };

export type GoBase = { kind: 'ident'; name: string } | { kind: 'call'; ref: GoRef } | { kind: 'type'; type: GoType } | { kind: 'other'; text: string };

/** Where a local variable's type comes from. */
export type GoTypeSrc = { kind: 'type'; type: GoType } | { kind: 'call'; ref: GoRef; index: number } | { kind: 'expr'; base: GoBase; fields: string[] } | { kind: 'literal'; id: string };

export interface GoGuardCand {
  text: string;
  ref: GoRef;
}

export interface GoRouter {
  name: string;
  framework: Framework;
  kind: 'root' | 'group' | 'param';
  prefix: string;
  guards: GoGuardCand[];
  /** router identifier this group was created from */
  parent?: string;
  /** the group was mounted on another router of this function (`r.Mount("/api", api)`) */
  mountedOn?: { ident: string; prefix: string; line: number };
  line: number;
  paramIndex?: number;
}

/** A router expression handed to another function or a literal: `v1.Group("/users", mw)` or plain `r`. */
export interface GoRouterExpr {
  ident: string;
  prefix: string;
  guards: GoGuardCand[];
  line: number;
}

export interface GoMount {
  /** the function (or literal) receiving the router */
  target: GoRef;
  /** parameter position the router lands in; undefined when the target returns the router instead */
  paramIndex?: number;
  returned?: boolean;
  router: GoRouterExpr;
  line: number;
}

export interface GoUse {
  ident: string;
  guards: GoGuardCand[];
  line: number;
}

export interface GoRoute {
  methods: string[];
  path: string;
  line: number;
  /** router identifier the route is registered on ('' when unknown) */
  ident: string;
  framework: Framework;
  guards: GoGuardCand[];
  handlers: GoRef[];
  unresolved: string[];
}

export interface GoFunc {
  info: FunctionInfo;
  /** parallel to info.calls */
  refs: GoRef[];
  recvType?: string;
  params: GoParam[];
  results: GoType[];
  /** parameters carrying the request (`r *http.Request`, `c *gin.Context`, ...) */
  reqNames: string[];
  /** the body writes a 401/403 somewhere */
  rejects: boolean;
  /** identifier returned by the function (router factories) */
  returnsIdent?: string;
  routers: Map<string, GoRouter>;
  routes: GoRoute[];
  uses: GoUse[];
  mounts: GoMount[];
  localTypes: Map<string, GoTypeSrc>;
  /** nested function literals, by id */
  literals: string[];
}

export interface GoFileInfo {
  file: string;
  rel: string;
  /** package directory relative to the project root ('' for the root) */
  dir: string;
  pkgName: string;
  imports: GoImport[];
  funcs: GoFunc[];
  /** package-level statements (var initialisers) */
  fileFunc: GoFunc;
  types: GoTypeDecl[];
  consts: Map<string, string>;
  /** one entry per listen call found: true when bound to loopback */
  listens: boolean[];
}

export interface GoAnalyzeOptions {
  rootDir: string;
}

const BUILTINS = new Set(['len', 'cap', 'append', 'make', 'new', 'panic', 'recover', 'print', 'println', 'delete', 'copy', 'close', 'complex', 'real', 'imag', 'string', 'int', 'int8', 'int16', 'int32', 'int64', 'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'float32', 'float64', 'byte', 'rune', 'bool', 'error', 'min', 'max', 'clear', 'any']);
const VERBS: Record<string, string> = { GET: 'GET', POST: 'POST', PUT: 'PUT', DELETE: 'DELETE', PATCH: 'PATCH', HEAD: 'HEAD', OPTIONS: 'OPTIONS', CONNECT: 'CONNECT', TRACE: 'TRACE', Get: 'GET', Post: 'POST', Put: 'PUT', Delete: 'DELETE', Patch: 'PATCH', Head: 'HEAD', Options: 'OPTIONS', Connect: 'CONNECT', Trace: 'TRACE', Any: 'ANY', ANY: 'ANY', All: 'ANY', ALL: 'ANY' };
const LISTEN = new Set(['ListenAndServe', 'ListenAndServeTLS', 'Run', 'RunTLS', 'Start', 'StartTLS', 'Listen', 'ListenTLS', 'Serve', 'ServeTLS']);
/** import-path basename -> constructor names that return a root router */
const ROOT_CTORS: Record<string, { names: string[]; framework: Framework }> = {
  gin: { names: ['Default', 'New'], framework: 'gin' },
  echo: { names: ['New'], framework: 'echo' },
  chi: { names: ['NewRouter', 'NewMux'], framework: 'chi' },
  fiber: { names: ['New'], framework: 'fiber' },
  mux: { names: ['NewRouter'], framework: 'gorilla' },
  http: { names: ['NewServeMux'], framework: 'nethttp' },
  httprouter: { names: ['New'], framework: 'httprouter' },
};
/** import-path basename -> router type names */
const ROUTER_TYPES: Record<string, { names: string[]; framework: Framework }> = {
  gin: { names: ['Engine', 'RouterGroup', 'IRouter', 'IRoutes'], framework: 'gin' },
  echo: { names: ['Echo', 'Group'], framework: 'echo' },
  chi: { names: ['Router', 'Mux'], framework: 'chi' },
  fiber: { names: ['App', 'Router', 'Group'], framework: 'fiber' },
  mux: { names: ['Router'], framework: 'gorilla' },
  http: { names: ['ServeMux'], framework: 'nethttp' },
  httprouter: { names: ['Router'], framework: 'httprouter' },
};
const REQ_TYPES: Record<string, string[]> = { http: ['Request'], gin: ['Context'], echo: ['Context'], fiber: ['Ctx'], fasthttp: ['RequestCtx'], httprouter: ['Params'] };
export const GO_GUARD_BODY_RE = /StatusUnauthorized|StatusForbidden|\b40[13]\b|ErrUnauthorized|ErrForbidden|unauthorized|forbidden|Redirect\([^)]*login/i;

export function frameworkOfPath(path: string): Framework {
  if (path === 'net/http') return 'nethttp';
  if (/gin-gonic\/gin/.test(path)) return 'gin';
  if (/labstack\/echo/.test(path)) return 'echo';
  if (/go-chi\/chi/.test(path)) return 'chi';
  if (/gofiber\/fiber/.test(path)) return 'fiber';
  if (/gorilla\/mux/.test(path)) return 'gorilla';
  if (/julienschmidt\/httprouter/.test(path)) return 'httprouter';
  return 'unknown';
}

/** basename of an import path without a major-version suffix (`github.com/go-chi/chi/v5` -> `chi`, `gopkg.in/yaml.v2` -> `yaml`). */
export function pathBase(path: string): string {
  const parts = path.split('/').filter((p) => !/^v\d+$/.test(p));
  return (parts[parts.length - 1] ?? path).replace(/\.v\d+$/, '');
}

/** Package names a path is commonly imported as when the clause differs from the basename (`go-sqlite3` -> `sqlite3`). */
function packageNameGuesses(path: string): string[] {
  const base = pathBase(path);
  const out = [base];
  const stripped = base.replace(/^go-/, '').replace(/-go$/, '').replace(/[-.]/g, '');
  if (stripped && stripped !== base) out.push(stripped);
  return out;
}

export function joinPath(a: string, b: string): string {
  const s = `${a}/${b}`.replace(/\/{2,}/g, '/');
  return s.length > 1 ? s.replace(/\/$/, '') : s || '/';
}

export async function analyzeGoFile(file: string, opts: GoAnalyzeOptions): Promise<GoFileInfo> {
  const { rootDir } = opts;
  const text = readFileSync(file, 'utf8');
  const tree = await parseGo(text);
  const root = tree.rootNode;
  const rel = relative(rootDir, file).replace(/\\/g, '/');
  const dir = relative(rootDir, dirname(file)).replace(/\\/g, '/');
  const importsByLocal = new Map<string, GoImport>();
  const fileFunc = newFunc(`${rel}#<file>`, '<file>', 1, 1);
  const info: GoFileInfo = { file, rel, dir, pkgName: '', imports: [], funcs: [], fileFunc, types: [], consts: new Map(), listens: [] };

  function newFunc(id: string, name: string, ln: number, cl: number, parentId?: string): GoFunc {
    return { info: { id, name, file: rel, line: ln, col: cl, params: [], calls: [], parentId }, refs: [], params: [], results: [], reqNames: [], rejects: false, routers: new Map(), routes: [], uses: [], mounts: [], localTypes: new Map(), literals: [] };
  }

  // ---- package, imports, consts, types ----
  for (const n of root.namedChildren) {
    if (n.type === 'package_clause') info.pkgName = n.namedChildren[0]?.text ?? '';
    if (n.type === 'import_declaration') {
      walk(n, (s) => {
        if (s.type !== 'import_spec') return true;
        const path = stringValue(s.childForFieldName('path')) ?? '';
        const name = s.childForFieldName('name')?.text;
        const local = name && name !== '_' && name !== '.' ? name : pathBase(path);
        const imp: GoImport = { local, path, line: line(s) };
        info.imports.push(imp);
        if (name !== '_') {
          importsByLocal.set(local, imp);
          if (!name) for (const g of packageNameGuesses(path)) if (!importsByLocal.has(g)) importsByLocal.set(g, imp);
        }
        return false;
      });
    }
    if (n.type === 'const_declaration') {
      for (const spec of n.namedChildren.filter((c) => c.type === 'const_spec')) {
        const names = spec.namedChildren.filter((c) => c.type === 'identifier').map((c) => c.text);
        const vals = spec.childForFieldName('value')?.namedChildren ?? [];
        names.forEach((nm, i) => {
          const v = stringValue(vals[i]);
          if (v !== undefined) info.consts.set(nm, v);
        });
      }
    }
    if (n.type === 'type_declaration') {
      for (const spec of n.namedChildren.filter((c) => c.type === 'type_spec')) {
        const name = spec.childForFieldName('name')?.text ?? '';
        const t = spec.childForFieldName('type');
        const decl: GoTypeDecl = { name, kind: 'other', fields: new Map(), embedded: [], methods: [], line: line(spec) };
        if (t?.type === 'struct_type') {
          decl.kind = 'struct';
          for (const f of t.namedChildren[0]?.namedChildren.filter((c) => c.type === 'field_declaration') ?? []) {
            const ft = f.childForFieldName('type');
            const names = f.namedChildren.filter((c) => c.type === 'field_identifier').map((c) => c.text);
            if (!ft) continue;
            const ty = typeOf(ft);
            if (!names.length) decl.embedded.push(ty);
            for (const nm of names) decl.fields.set(nm, ty);
          }
        } else if (t?.type === 'interface_type') {
          decl.kind = 'interface';
          for (const m of t.namedChildren) {
            if (m.type === 'method_elem' || m.type === 'method_spec') decl.methods.push(m.childForFieldName('name')?.text ?? '');
            else if (m.type === 'type_elem' || m.type === 'type_identifier' || m.type === 'qualified_type') decl.embedded.push(typeOf(m.type === 'type_elem' ? m.namedChildren[0] ?? m : m));
          }
        }
        info.types.push(decl);
      }
    }
  }

  function typeOf(n: Node): GoType {
    switch (n.type) {
      case 'pointer_type':
        return { ...typeOf(n.namedChildren[0]!), ptr: true, text: n.text };
      case 'parenthesized_type':
      case 'type_elem':
        return n.namedChildren[0] ? typeOf(n.namedChildren[0]) : { name: '', text: n.text };
      case 'generic_type':
        return typeOf(n.childForFieldName('type') ?? n.namedChildren[0]!);
      case 'qualified_type': {
        const alias = n.childForFieldName('package')?.text ?? '';
        return { pkg: importsByLocal.get(alias)?.path ?? alias, name: n.childForFieldName('name')?.text ?? '', text: n.text };
      }
      case 'type_identifier':
        return { name: n.text, text: n.text };
      default:
        return { name: '', text: n.text.slice(0, 60) };
    }
  }

  const isReqType = (t: GoType | undefined): boolean => {
    if (!t?.pkg) return false;
    return (REQ_TYPES[pathBase(t.pkg)] ?? []).includes(t.name);
  };
  const routerType = (t: GoType | undefined): Framework | undefined => {
    if (!t?.pkg) return undefined;
    const r = ROUTER_TYPES[pathBase(t.pkg)];
    return r && r.names.includes(t.name) && frameworkOfPath(t.pkg) === r.framework ? r.framework : undefined;
  };

  // ---- functions ----
  const fnByNode = new Map<number, GoFunc>();
  const fnNodes: Node[] = [];
  const paramsOf = (list: Node | null): GoParam[] => {
    const out: GoParam[] = [];
    for (const p of list?.namedChildren ?? []) {
      if (p.type !== 'parameter_declaration' && p.type !== 'variadic_parameter_declaration') continue;
      const t = p.childForFieldName('type');
      const names = p.namedChildren.filter((c) => c.type === 'identifier').map((c) => c.text);
      const ty = t ? typeOf(t) : undefined;
      if (!names.length) out.push({ name: '', type: ty });
      for (const nm of names) out.push({ name: nm, type: ty });
    }
    return out;
  };
  const resultsOf = (n: Node | null): GoType[] => {
    if (!n) return [];
    if (n.type === 'parameter_list') return paramsOf(n).map((p) => p.type ?? { name: '', text: '' });
    return [typeOf(n)];
  };
  const declare = (node: Node, parent: GoFunc | undefined, name: string, recvType?: string) => {
    const id = `${rel}#${recvType ? recvType + '.' : ''}${name}@${line(node)}:${col(node)}`;
    const fn = newFunc(id, name, line(node), col(node), parent?.info.id);
    fn.recvType = recvType;
    fn.params = paramsOf(node.childForFieldName('parameters'));
    fn.results = resultsOf(node.childForFieldName('result'));
    fn.info.params = fn.params.map((p) => p.name);
    fn.reqNames = fn.params.filter((p) => p.name && isReqType(p.type)).map((p) => p.name);
    if (fn.reqNames.length) fn.info.inputParams = [...fn.reqNames];
    fn.params.forEach((p, i) => {
      if (!p.name || !p.type) return;
      fn.localTypes.set(p.name, { kind: 'type', type: p.type });
      const fw = routerType(p.type);
      if (fw) fn.routers.set(p.name, { name: p.name, framework: fw, kind: 'param', prefix: '', guards: [], line: line(node), paramIndex: i });
    });
    const body = node.childForFieldName('body');
    if (body) {
      fn.rejects = GO_GUARD_BODY_RE.test(body.text.slice(0, 40_000));
      // the identifier a router factory returns
      walk(body, (s) => {
        if (s !== body && s.type === 'func_literal') return false;
        if (s.type === 'return_statement') {
          const e = s.namedChildren[0];
          if (e?.type === 'expression_list' && e.namedChildren.length === 1 && e.namedChildren[0]!.type === 'identifier') fn.returnsIdent ??= e.namedChildren[0]!.text;
        }
        return true;
      });
    }
    fnByNode.set(node.id, fn);
    fnNodes.push(node);
    info.funcs.push(fn);
    if (parent) parent.literals.push(id);
    return fn;
  };
  const visitFns = (n: Node, parent: GoFunc | undefined) => {
    let fn = parent;
    if (n.type === 'function_declaration') fn = declare(n, undefined, n.childForFieldName('name')?.text ?? '<anon>');
    else if (n.type === 'method_declaration') {
      const recv = paramsOf(n.childForFieldName('receiver'))[0];
      const rt = recv?.type?.name || '<recv>';
      fn = declare(n, undefined, n.childForFieldName('name')?.text ?? '<anon>', rt);
      if (recv?.name && recv.type) fn.localTypes.set(recv.name, { kind: 'type', type: recv.type });
    } else if (n.type === 'func_literal') fn = declare(n, parent ?? fileFunc, '<func>');
    for (const c of n.namedChildren) visitFns(c, fn);
  };
  visitFns(root, undefined);

  function enclosing(n: Node): GoFunc {
    let cur = n.parent;
    while (cur) {
      const f = fnByNode.get(cur.id);
      if (f) return f;
      cur = cur.parent;
    }
    return fileFunc;
  }
  function scopeNode(fn: GoFunc): Node | undefined {
    for (const n of fnNodes) if (fnByNode.get(n.id) === fn) return n;
    return undefined;
  }

  // ---- expressions -> refs ----
  function refOf(n: Node | null | undefined): GoRef {
    if (!n) return { kind: 'none', text: '' };
    switch (n.type) {
      case 'identifier':
        return { kind: 'ident', name: n.text };
      case 'parenthesized_expression':
        return refOf(n.namedChildren[0]);
      case 'unary_expression':
        return n.text.startsWith('&') ? refOf(n.childForFieldName('operand')) : { kind: 'none', text: n.text.slice(0, 40) };
      case 'func_literal':
        return { kind: 'literal', id: fnByNode.get(n.id)!.info.id };
      case 'composite_literal': {
        const t = n.childForFieldName('type');
        return t ? { kind: 'type', type: typeOf(t) } : { kind: 'none', text: n.text.slice(0, 40) };
      }
      case 'call_expression': {
        const fnNode = n.childForFieldName('function');
        const args = (n.childForFieldName('arguments')?.namedChildren ?? []).map((a) => refOf(a));
        return { kind: 'call', ref: refOf(fnNode), args, text: n.text.replace(/\s+/g, ' ').slice(0, 80) };
      }
      case 'selector_expression': {
        const chain = selectorChain(n);
        const name = chain.fields.pop()!;
        if (chain.base.kind === 'ident' && !chain.fields.length) {
          const imp = importsByLocal.get(chain.base.name);
          if (imp && !isLocalName(n, chain.base.name)) return { kind: 'pkg', path: imp.path, name };
        }
        return { kind: 'method', base: chain.base, fields: chain.fields, name };
      }
      case 'generic_function':
      case 'index_expression':
        return refOf(n.childForFieldName('function') ?? n.childForFieldName('operand'));
      default:
        return { kind: 'none', text: n.text.replace(/\s+/g, ' ').slice(0, 40) };
    }
  }
  /** `a.b.c` -> base `a`, fields [b, c] */
  function selectorChain(n: Node): { base: GoBase; fields: string[] } {
    const fields: string[] = [];
    let cur: Node = n;
    while (cur.type === 'selector_expression') {
      fields.unshift(cur.childForFieldName('field')?.text ?? '');
      cur = cur.childForFieldName('operand')!;
      while (cur.type === 'parenthesized_expression' && cur.namedChildren[0]) cur = cur.namedChildren[0];
    }
    let base: GoBase;
    if (cur.type === 'identifier') base = { kind: 'ident', name: cur.text };
    else if (cur.type === 'call_expression') base = { kind: 'call', ref: refOf(cur) };
    else if (cur.type === 'composite_literal' && cur.childForFieldName('type')) base = { kind: 'type', type: typeOf(cur.childForFieldName('type')!) };
    else if (cur.type === 'unary_expression' && cur.text.startsWith('&')) {
      const r = refOf(cur);
      base = r.kind === 'type' ? { kind: 'type', type: r.type } : r.kind === 'ident' ? { kind: 'ident', name: r.name } : { kind: 'other', text: cur.text.slice(0, 40) };
    } else base = { kind: 'other', text: cur.text.slice(0, 40) };
    return { base, fields };
  }
  /** a name that shadows an import inside this function (parameter or local) */
  function isLocalName(at: Node, name: string): boolean {
    const fn = enclosing(at);
    return fn.localTypes.has(name) || fn.params.some((p) => p.name === name);
  }

  // ---- local variable types, routers, mounts, routes ----
  const typeSrcOf = (rhs: Node, index: number): GoTypeSrc | undefined => {
    let n = rhs;
    while (n.type === 'parenthesized_expression' && n.namedChildren[0]) n = n.namedChildren[0];
    if (n.type === 'unary_expression' && n.text.startsWith('&')) n = n.childForFieldName('operand') ?? n;
    if (n.type === 'composite_literal') {
      const t = n.childForFieldName('type');
      return t ? { kind: 'type', type: typeOf(t) } : undefined;
    }
    if (n.type === 'func_literal') return { kind: 'literal', id: fnByNode.get(n.id)!.info.id };
    if (n.type === 'call_expression') {
      const f = n.childForFieldName('function');
      if (f?.type === 'identifier' && f.text === 'new') {
        const t = n.childForFieldName('arguments')?.namedChildren[0];
        return t ? { kind: 'type', type: { ...typeOf(t), ptr: true } } : undefined;
      }
      if (f?.type === 'identifier' && BUILTINS.has(f.text)) return undefined;
      // a type conversion `T(x)` on a project type reads like a call; the resolver treats a missing function as unknown
      return { kind: 'call', ref: refOf(f), index };
    }
    if (n.type === 'selector_expression') {
      const c = selectorChain(n);
      if (c.base.kind === 'ident' && !c.fields.length) return undefined; // pkg.Const or plain alias
      if (c.base.kind === 'ident' && c.fields.length === 1 && importsByLocal.has(c.base.name) && !isLocalName(n, c.base.name)) return undefined;
      return { kind: 'expr', base: c.base, fields: c.fields };
    }
    if (n.type === 'type_assertion_expression') {
      const t = n.childForFieldName('type');
      return t ? { kind: 'type', type: typeOf(t) } : undefined;
    }
    return undefined;
  };
  const serverAddr = new Map<string, boolean>(); // local `&http.Server{Addr: ...}` -> bound to loopback
  function isLocalAddr(n: Node | undefined, fn: GoFunc): boolean {
    if (!n) return false;
    let s = stringValue(n);
    if (s === undefined && n.type === 'identifier') s = info.consts.get(n.text);
    void fn;
    return s !== undefined && /^(127\.0\.0\.1|localhost|\[::1\]):\d+$/.test(s);
  }
  function recordAssignment(lhs: Node[], rhs: Node[], fn: GoFunc, stmt: Node) {
    const single = rhs.length === 1 && lhs.length > 1;
    lhs.forEach((l, i) => {
      if (l.type !== 'identifier' || l.text === '_' || l.text === 'err') return;
      const r = single ? rhs[0] : rhs[i];
      if (!r) return;
      const src = typeSrcOf(r, single ? i : 0);
      if (src && !fn.localTypes.has(l.text)) fn.localTypes.set(l.text, src);
      if (src?.kind === 'type' && src.type.pkg === 'net/http' && src.type.name === 'Server') {
        const body = (r.type === 'unary_expression' ? r.childForFieldName('operand') : r)?.childForFieldName('body');
        const addr = body?.namedChildren.find((k) => k.type === 'keyed_element' && k.childForFieldName('key')?.text === 'Addr')?.childForFieldName('value')?.namedChildren[0];
        serverAddr.set(l.text, isLocalAddr(addr, fn));
      }
      if (lhs.length === 1 || single) {
        const router = routerFromExpr(r, fn);
        if (router) fn.routers.set(l.text, { ...router, name: l.text, line: line(stmt) });
      }
    });
  }

  interface Link {
    method: string;
    args: Node[];
    node: Node;
  }
  /** `a.M1(x).M2(y)` -> base a, links [M1, M2] */
  function callChain(call: Node): { base: Node; links: Link[] } | undefined {
    const links: Link[] = [];
    let cur: Node = call;
    while (cur.type === 'call_expression') {
      const f = cur.childForFieldName('function');
      if (f?.type !== 'selector_expression') return undefined;
      links.unshift({ method: f.childForFieldName('field')?.text ?? '', args: cur.childForFieldName('arguments')?.namedChildren ?? [], node: cur });
      cur = f.childForFieldName('operand')!;
      while (cur.type === 'parenthesized_expression' && cur.namedChildren[0]) cur = cur.namedChildren[0];
    }
    return { base: cur, links };
  }
  function routerIdent(base: Node, fn: GoFunc): GoRouter | undefined {
    if (base.type !== 'identifier') return undefined;
    const r = fn.routers.get(base.text);
    if (r) return r;
    for (let p = fn.info.parentId ? info.funcs.find((f) => f.info.id === fn.info.parentId) : undefined; p; p = p.info.parentId ? info.funcs.find((f) => f.info.id === p!.info.parentId) : undefined) {
      const pr = p.routers.get(base.text);
      if (pr) return pr;
    }
    const pkgLevel = fileFunc.routers.get(base.text);
    if (pkgLevel) return pkgLevel;
    const imp = importsByLocal.get(base.text);
    if (imp?.path === 'net/http' && !isLocalName(base, base.text)) return { name: base.text, framework: 'nethttp', kind: 'root', prefix: '', guards: [], line: 0 };
    return undefined;
  }
  const guardCands = (nodes: Node[]): GoGuardCand[] => nodes.map((a) => ({ text: a.text.replace(/\s+/g, ' ').slice(0, 80), ref: refOf(a) }));
  const pathArg = (n: Node | undefined): string => {
    if (!n) return '/';
    const s = stringValue(n);
    if (s !== undefined) return s;
    if (n.type === 'identifier') return info.consts.get(n.text) ?? `{${n.text}}`;
    return `{${n.text.replace(/\s+/g, ' ').slice(0, 30)}}`;
  };
  /** `r.Group("/api", mw)`, `r.PathPrefix("/api").Subrouter()`, `r.With(mw)`, `gin.Default()` ... as a router value */
  function routerFromExpr(rhs: Node, fn: GoFunc): Omit<GoRouter, 'name' | 'line'> | undefined {
    let n = rhs;
    while (n.type === 'parenthesized_expression' && n.namedChildren[0]) n = n.namedChildren[0];
    if (n.type !== 'call_expression') return undefined;
    const chain = callChain(n);
    if (!chain) return undefined;
    let out: Omit<GoRouter, 'name' | 'line'> | undefined;
    let i = 0;
    // root constructor
    if (chain.base.type === 'identifier' && chain.links[0]) {
      const imp = importsByLocal.get(chain.base.text);
      const ctor = imp ? ROOT_CTORS[pathBase(imp.path)] : undefined;
      if (imp && ctor && ctor.names.includes(chain.links[0].method) && frameworkOfPath(imp.path) === ctor.framework) {
        out = { framework: ctor.framework, kind: 'root', prefix: '', guards: [] };
        i = 1;
      }
    }
    if (!out) {
      const parent = routerIdent(chain.base, fn);
      if (!parent) return undefined;
      out = { framework: parent.framework, kind: 'group', prefix: '', guards: [], parent: parent.name };
    }
    for (; i < chain.links.length; i++) {
      const l = chain.links[i]!;
      switch (l.method) {
        case 'Group':
          if (l.args[0]?.type === 'func_literal') return undefined; // chi: r.Group(func(r chi.Router) {...}) has no value
          out.prefix = joinPath(out.prefix, pathArg(l.args[0]));
          out.guards.push(...guardCands(l.args.slice(1)));
          break;
        case 'PathPrefix':
        case 'Path':
          out.prefix = joinPath(out.prefix, pathArg(l.args[0]));
          break;
        case 'Subrouter':
        case 'Name':
        case 'Host':
        case 'Schemes':
        case 'Headers':
        case 'Queries':
        case 'Methods':
          break;
        case 'With':
        case 'Use':
          out.guards.push(...guardCands(l.args));
          break;
        default:
          return undefined; // r.Group("/x").GET(...) is a route, not a router value
      }
    }
    return out;
  }

  function routeFromChain(call: Node, fn: GoFunc): boolean {
    const chain = callChain(call);
    if (!chain) return false;
    const base = chain.base;
    const known = routerIdent(base, fn);
    const framework: Framework = known?.framework ?? 'unknown';
    const last = chain.links[chain.links.length - 1]!;
    // listen calls
    if (LISTEN.has(last.method)) {
      const imp = base.type === 'identifier' ? importsByLocal.get(base.text) : undefined;
      const onHttp = imp?.path === 'net/http' && chain.links.length === 1;
      if (onHttp || known) info.listens.push(isLocalAddr(last.args[0], fn));
      else if (base.type === 'identifier' && serverAddr.has(base.text)) info.listens.push(serverAddr.get(base.text)!);
      return false;
    }
    if (!known && base.type === 'identifier' && importsByLocal.has(base.text)) return false; // pkg.Func(...) chains
    let prefix = '';
    const guards: GoGuardCand[] = [];
    let methods: string[] | undefined;
    let path: string | undefined;
    let handlerArgs: Node[] = [];
    let seen = false;
    const ident = known?.name ?? (base.type === 'identifier' || base.type === 'selector_expression' ? base.text : '');
    for (const l of chain.links) {
      const m = l.method;
      if (m === 'Use' && l === last) {
        if (!known) return false;
        if (chain.links.length === 1) fn.uses.push({ ident, guards: guardCands(l.args), line: line(call) });
        return true;
      }
      if (m === 'Group' || m === 'Route') {
        if (l.args[0]?.type === 'func_literal' || l.args[1]?.type === 'func_literal') {
          if (!known) return false;
          const lit = l.args[0]?.type === 'func_literal' ? l.args[0] : l.args[1]!;
          const p = m === 'Route' ? pathArg(l.args[0]) : '';
          fn.mounts.push({ target: { kind: 'literal', id: fnByNode.get(lit.id)!.info.id }, paramIndex: 0, router: { ident, prefix: joinPath(prefix, p), guards: [...guards], line: line(call) }, line: line(call) });
          return true;
        }
        prefix = joinPath(prefix, pathArg(l.args[0]));
        guards.push(...guardCands(l.args.slice(1)));
        continue;
      }
      if (m === 'Mount') {
        if (!known || l.args.length < 2) return false;
        const target = l.args[1]!;
        mountExpr(target, { ident, prefix: joinPath(prefix, pathArg(l.args[0])), guards: [...guards], line: line(call) }, fn);
        return true;
      }
      if (m === 'With') {
        guards.push(...guardCands(l.args));
        continue;
      }
      if (m === 'PathPrefix') {
        prefix = joinPath(prefix, pathArg(l.args[0]));
        path ??= '/*';
        continue;
      }
      if (m === 'Path') {
        path = pathArg(l.args[0]);
        continue;
      }
      if (m === 'Methods') {
        methods = l.args.map((a) => stringValue(a)?.toUpperCase() ?? 'ANY');
        continue;
      }
      if (m === 'Subrouter' || m === 'Name' || m === 'Host' || m === 'Schemes' || m === 'Headers' || m === 'Queries' || m === 'HeadersRegexp' || m === 'MatcherFunc') continue;
      if (m === 'HandleFunc' || m === 'Handle') {
        const a0 = stringValue(l.args[0]);
        if (l.args.length >= 3 && a0 && /^[A-Z]+$/.test(a0)) {
          // gin: Handle(method, path, handlers...)
          methods = [a0];
          path = pathArg(l.args[1]);
          handlerArgs = l.args.slice(2);
        } else {
          if (!known && (!a0 || !a0.startsWith('/') || l.args.length !== 2)) return false;
          path = pathArg(l.args[0]);
          handlerArgs = l.args.slice(1);
        }
        seen = true;
        continue;
      }
      if (m === 'Handler' || m === 'HandlerFunc') {
        const a0 = stringValue(l.args[0]);
        if (l.args.length >= 3 && a0 && /^[A-Z]+$/.test(a0)) {
          // httprouter: Handler(method, path, handler)
          methods = [a0];
          path = pathArg(l.args[1]);
          handlerArgs = l.args.slice(2);
        } else {
          if (!known && !seen && path === undefined) return false;
          handlerArgs = l.args.slice(0, 1);
        }
        seen = true;
        continue;
      }
      if (m === 'Method' || m === 'MethodFunc' || m === 'Add' || m === 'Match') {
        if (!known) return false;
        const a0 = l.args[0];
        methods = a0 && a0.type === 'composite_literal' ? (a0.childForFieldName('body')?.namedChildren.map((x) => stringValue(x.namedChildren[0] ?? x)?.toUpperCase() ?? 'ANY') ?? ['ANY']) : [stringValue(a0)?.toUpperCase() ?? 'ANY'];
        path = pathArg(l.args[1]);
        handlerArgs = l.args.slice(2);
        seen = true;
        continue;
      }
      const verb = VERBS[m];
      if (verb) {
        if (known?.framework === 'nethttp') return false; // http.Get / mux.Get are not registrations
        const a0 = stringValue(l.args[0]);
        if (!known && (l.args.length < 2 || !a0 || !(a0.startsWith('/') || /^[A-Z]+ \//.test(a0)))) return false;
        if (!known && framework === 'unknown' && l.args.length < 2) return false;
        methods = [verb];
        path = pathArg(l.args[0]);
        handlerArgs = l.args.slice(1);
        seen = true;
        continue;
      }
      if (m === 'Static' || m === 'StaticFS' || m === 'StaticFile' || m === 'File' || m === 'NoRoute' || m === 'NotFound' || m === 'MethodNotAllowed' || m === 'NoMethod') return !!known;
      return false; // some other method on the router (or not a router at all)
    }
    if (path === undefined || !handlerArgs.length) return false;
    // Go 1.22 patterns: "GET /users/{id}" and host-prefixed patterns
    const pm = /^([A-Z]+)\s+(\S+)$/.exec(path);
    if (pm) {
      methods = [pm[1]!];
      path = pm[2]!;
    }
    const fw = known?.framework ?? framework;
    const [handlers, mws] = splitHandlers(handlerArgs, fw);
    fn.routes.push({ methods: methods ?? ['ANY'], path: joinPath(prefix, path), line: line(call), ident, framework: fw, guards: [...guards, ...guardCands(mws)], handlers: handlers.map((h) => refOf(h)), unresolved: [] });
    return true;
  }
  /** which registration arguments are the handler and which are middleware */
  function splitHandlers(args: Node[], fw: Framework): [Node[], Node[]] {
    if (args.length <= 1) return [args, []];
    if (fw === 'echo') return [[args[0]!], args.slice(1)];
    if (fw === 'chi' || fw === 'nethttp' || fw === 'gorilla' || fw === 'httprouter') return [[args[0]!], args.slice(1)];
    return [[args[args.length - 1]!], args.slice(0, -1)];
  }
  /** `r.Mount(prefix, X)`: X is a router of this function, or a call returning one */
  function mountExpr(target: Node, router: GoRouterExpr, fn: GoFunc) {
    let t = target;
    while (t.type === 'parenthesized_expression' && t.namedChildren[0]) t = t.namedChildren[0];
    if (t.type === 'identifier') {
      const r = fn.routers.get(t.text);
      if (r) {
        r.mountedOn = { ident: router.ident, prefix: router.prefix, line: router.line };
        r.guards.push(...router.guards);
        return;
      }
      const src = fn.localTypes.get(t.text);
      if (src?.kind === 'call') {
        fn.mounts.push({ target: src.ref, returned: true, router, line: router.line });
        return;
      }
    }
    if (t.type === 'call_expression') {
      const chain = callChain(t);
      const f = t.childForFieldName('function');
      // http.StripPrefix("/api", sub)
      if (chain && chain.base.type === 'identifier' && importsByLocal.get(chain.base.text)?.path === 'net/http' && chain.links[0]?.method === 'StripPrefix' && chain.links[0].args[1]) {
        mountExpr(chain.links[0].args[1]!, router, fn);
        return;
      }
      fn.mounts.push({ target: refOf(f), returned: true, router, line: router.line });
    }
  }

  // statement-level pass: assignments (types, routers), then calls (routes, mounts, uses, call sites)
  walk(root, (n) => {
    if (n.type === 'short_var_declaration' || (n.type === 'assignment_statement' && n.children.some((c) => c.type === '='))) {
      const fn = enclosing(n);
      recordAssignment(n.childForFieldName('left')?.namedChildren ?? [], n.childForFieldName('right')?.namedChildren ?? [], fn, n);
    } else if (n.type === 'var_spec') {
      const fn = enclosing(n);
      const names = n.namedChildren.filter((c) => c.type === 'identifier');
      const t = n.childForFieldName('type');
      const vals = n.childForFieldName('value')?.namedChildren ?? [];
      if (t) for (const nm of names) fn.localTypes.set(nm.text, { kind: 'type', type: typeOf(t) });
      else recordAssignment(names, vals, fn, n);
    }
    return true;
  });

  // ---- request-data flow per function ----
  function baseIdentifiers(n: Node, out: Set<string>) {
    switch (n.type) {
      case 'identifier':
        out.add(n.text);
        return;
      case 'selector_expression': {
        const op = n.childForFieldName('operand')!;
        if (op.type === 'identifier' && importsByLocal.has(op.text) && !isLocalName(n, op.text)) return;
        baseIdentifiers(op, out);
        return;
      }
      case 'call_expression': {
        const f = n.childForFieldName('function');
        if (f?.type === 'selector_expression') baseIdentifiers(f, out);
        for (const a of n.childForFieldName('arguments')?.namedChildren ?? []) baseIdentifiers(a, out);
        return;
      }
      case 'func_literal':
      case 'type_identifier':
      case 'qualified_type':
      case 'pointer_type':
      case 'interpreted_string_literal':
      case 'raw_string_literal':
        return;
      default:
        for (const c of n.namedChildren) baseIdentifiers(c, out);
    }
  }
  interface Flow {
    locals: Map<string, Set<string>>;
    origins: Map<string, string>;
  }
  const flowByFn = new Map<string, Flow>();
  function flow(fn: GoFunc): Flow {
    let f = flowByFn.get(fn.info.id);
    if (f) return f;
    const raw = new Map<string, Set<string>>();
    const origins = new Map<string, string>();
    const req = new Set(fn.reqNames);
    const scope = scopeNode(fn) ?? root;
    const bind = (tgt: string, ids: Set<string>, rhsText: string) => {
      if (tgt === '_') return;
      raw.set(tgt, new Set([...(raw.get(tgt) ?? []), ...ids]));
      const fromReq = [...ids].some((i) => req.has(i));
      if (fromReq && !origins.has(tgt)) origins.set(tgt, rhsText.replace(/\s+/g, ' ').slice(0, 60));
      else if (!origins.has(tgt)) for (const i of ids) if (origins.has(i)) origins.set(tgt, origins.get(i)!);
    };
    walk(scope, (x) => {
      if (x !== scope && (x.type === 'func_literal' || x.type === 'function_declaration' || x.type === 'method_declaration')) return false;
      if (x.type === 'short_var_declaration' || x.type === 'assignment_statement' || x.type === 'var_spec') {
        const lhs = x.type === 'var_spec' ? x.namedChildren.filter((c) => c.type === 'identifier') : x.childForFieldName('left')?.namedChildren ?? [];
        const rhs = x.type === 'var_spec' ? x.childForFieldName('value')?.namedChildren ?? [] : x.childForFieldName('right')?.namedChildren ?? [];
        if (!rhs.length) return true;
        const allIds = new Set<string>();
        for (const r of rhs) baseIdentifiers(r, allIds);
        lhs.forEach((l, i) => {
          if (l.type !== 'identifier') return;
          const r = rhs.length === lhs.length ? rhs[i]! : undefined;
          const ids = new Set<string>();
          if (r) baseIdentifiers(r, ids);
          bind(l.text, r ? ids : allIds, (r ?? rhs[0]!).text);
        });
      }
      if (x.type === 'range_clause') {
        const right = x.childForFieldName('right');
        const ids = new Set<string>();
        if (right) baseIdentifiers(right, ids);
        for (const l of x.childForFieldName('left')?.namedChildren ?? []) if (l.type === 'identifier') bind(l.text, ids, right?.text ?? '');
      }
      if (x.type === 'call_expression') {
        // output arguments: json.NewDecoder(r.Body).Decode(&in), c.ShouldBindJSON(&req), json.Unmarshal(body, &v)
        const args = x.childForFieldName('arguments')?.namedChildren ?? [];
        const outs = args.filter((a) => a.type === 'unary_expression' && a.text.startsWith('&') && a.childForFieldName('operand')?.type === 'identifier');
        if (outs.length) {
          const ids = new Set<string>();
          const f = x.childForFieldName('function');
          if (f?.type === 'selector_expression') baseIdentifiers(f, ids);
          for (const a of args) if (!outs.includes(a)) baseIdentifiers(a, ids);
          for (const o of outs) ids.delete(o.childForFieldName('operand')!.text);
          for (const o of outs) bind(o.childForFieldName('operand')!.text, ids, x.text);
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
    flowByFn.set(fn.info.id, f);
    fn.info.locals = [...locals].map(([name, roots]) => ({ name, roots: [...roots], origin: origins.get(name) }));
    return f;
  }
  function callArgs(call: Node, fn: GoFunc): CallArg[] {
    const f = flow(fn);
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

  // ---- calls ----
  walk(root, (n) => {
    if (n.type !== 'call_expression') return true;
    const fn = enclosing(n);
    const callee = n.childForFieldName('function');
    if (!callee) return true;
    // the outermost call of a method chain decides whether it is a route registration
    const inChain = n.parent?.type === 'selector_expression' && n.parent.parent?.type === 'call_expression' && n.parent.parent.childForFieldName('function')?.id === n.parent.id;
    const isRoute = !inChain && callee.type === 'selector_expression' && routeFromChain(n, fn);
    if (callee.type === 'identifier' && BUILTINS.has(callee.text)) return true;
    if (callee.type === 'parenthesized_expression' || callee.type === 'func_literal') return true;
    const ref = refOf(callee);
    if (ref.kind === 'none') return true;
    // a router handed to another function: users.Register(v1.Group("/users")), setup(r)
    if (!isRoute) {
      (n.childForFieldName('arguments')?.namedChildren ?? []).forEach((a, i) => {
        const own = routerIdent(a, fn);
        if (own) {
          fn.mounts.push({ target: ref, paramIndex: i, router: { ident: own.name, prefix: '', guards: [], line: line(n) }, line: line(n) });
          return;
        }
        const g = a.type === 'call_expression' ? routerFromExpr(a, fn) : undefined;
        if (g?.kind === 'group' && g.parent) fn.mounts.push({ target: ref, paramIndex: i, router: { ident: g.parent, prefix: g.prefix, guards: g.guards, line: line(n) }, line: line(n) });
      });
    }
    const args = callArgs(n, fn);
    const req = new Set(fn.reqNames);
    const target: CallTarget = { kind: 'unknown', text: callee.text.replace(/\s+/g, ' ').slice(0, 40) };
    const site: CallSite = { line: line(n), col: col(n), text: callee.text.replace(/\s+/g, ' ').slice(0, 80), target, userInput: args.some((a) => a.roots.some((r) => req.has(r))), args };
    fn.info.calls.push(site);
    fn.refs.push(ref);
    return true;
  });
  for (const fn of info.funcs) flow(fn);
  return info;
}

export type { CallSite, FunctionInfo };
