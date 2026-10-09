import ts from 'typescript';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, relative, resolve } from 'node:path';

export const HTTP_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'all', 'use', 'options', 'head']);
/** Heuristic: an argument whose text looks like an auth guard. Configurable later. */
export const AUTH_RE = /auth|login|session|jwt|token|passport|protect|guard|requireuser|isadmin|role|permission|verify|ensure/i;
const REQ_NAMES = new Set(['req', 'request']);
const RES_NAMES = new Set(['res', 'response']);

export interface ImportBinding {
  local: string;
  kind: 'package' | 'local';
  specifier: string;
  package?: string;
  /** Named member imported (or subpath). undefined = whole module / default object. */
  member?: string;
  file?: string;
  line: number;
}

export type CallTarget =
  | { kind: 'external'; package: string; symbol: string }
  | { kind: 'framework'; package: 'express'; receiver: 'Response'; symbol: string }
  | { kind: 'local'; name: string; file?: string }
  | { kind: 'unknown'; text: string };

export interface CallSite {
  line: number;
  col: number;
  text: string;
  target: CallTarget;
  userInput: boolean;
}

export interface FunctionInfo {
  id: string;
  name: string;
  file: string;
  line: number;
  col: number;
  params: string[];
  calls: CallSite[];
}

export interface RouteReg {
  method: string;
  path: string;
  line: number;
  app: string;
  guards: string[];
  middleware: string[];
  handlerIds: string[];
  /** Local import name of a router mounted by app.use(path, router). */
  mountLocal?: string;
}

export interface ModuleInfo {
  file: string;
  rel: string;
  imports: ImportBinding[];
  functions: FunctionInfo[];
  moduleFunctionId: string;
  routes: RouteReg[];
  appIdents: Set<string>;
  isRootApp: boolean;
  /** export name -> local identifier (or a function id for inline functions) */
  exports: Map<string, string>;
  exportsRouter?: string;
  listenLocalOnly?: boolean;
  listens: boolean;
}

export function splitSpecifier(spec: string): { pkg: string; sub?: string } {
  const parts = spec.split('/');
  if (spec.startsWith('@') && parts.length >= 2) {
    return { pkg: `${parts[0]}/${parts[1]}`, sub: parts.length > 2 ? parts.slice(2).join('/') : undefined };
  }
  return { pkg: parts[0]!, sub: parts.length > 1 ? parts.slice(1).join('/') : undefined };
}

function resolveLocal(fromFile: string, spec: string): string | undefined {
  const base = resolve(dirname(fromFile), spec);
  const candidates = [base, `${base}.js`, `${base}.ts`, `${base}.mjs`, `${base}.cjs`, `${base}/index.js`, `${base}/index.ts`];
  for (const c of candidates) {
    if (existsSync(c) && statSync(c).isFile()) return c;
  }
  return undefined;
}

function scriptKind(file: string): ts.ScriptKind {
  const ext = extname(file).toLowerCase();
  if (ext === '.ts' || ext === '.mts' || ext === '.cts') return ts.ScriptKind.TS;
  if (ext === '.tsx') return ts.ScriptKind.TSX;
  if (ext === '.jsx') return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

function isFunctionLike(n: ts.Node): n is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(n) ||
    ts.isFunctionExpression(n) ||
    ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n) ||
    ts.isGetAccessorDeclaration(n) ||
    ts.isSetAccessorDeclaration(n) ||
    ts.isConstructorDeclaration(n)
  );
}

function requireSpec(init: ts.Expression | undefined): { spec: string; member?: string } | undefined {
  if (!init) return undefined;
  if (ts.isCallExpression(init) && ts.isIdentifier(init.expression) && init.expression.text === 'require') {
    const a = init.arguments[0];
    if (a && ts.isStringLiteralLike(a)) return { spec: a.text };
  }
  if (ts.isPropertyAccessExpression(init)) {
    const inner = requireSpec(init.expression);
    if (inner && !inner.member) return { spec: inner.spec, member: init.name.text };
  }
  return undefined;
}

export interface AnalyzeOptions {
  authRe?: RegExp;
}

export function analyzeModule(file: string, rootDir: string, options: AnalyzeOptions = {}): ModuleInfo {
  const AUTH = options.authRe ?? AUTH_RE;
  const text = readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKind(file));
  const rel = relative(rootDir, file).replace(/\\/g, '/');
  const pos = (n: ts.Node) => {
    const p = sf.getLineAndCharacterOfPosition(n.getStart(sf));
    return { line: p.line + 1, col: p.character + 1 };
  };

  const mod: ModuleInfo = {
    file,
    rel,
    imports: [],
    functions: [],
    moduleFunctionId: `${rel}#<module>`,
    routes: [],
    appIdents: new Set(),
    isRootApp: false,
    exports: new Map(),
    listens: false,
  };
  const importsByLocal = new Map<string, ImportBinding>();

  function addImport(local: string, spec: string, member: string | undefined, line: number) {
    let b: ImportBinding;
    if (spec.startsWith('.') || spec.startsWith('/')) {
      b = { local, kind: 'local', specifier: spec, member, file: resolveLocal(file, spec), line };
    } else {
      const { pkg, sub } = splitSpecifier(spec.startsWith('node:') ? spec.slice(5) : spec);
      b = { local, kind: 'package', specifier: spec, package: pkg, member: member ?? sub, line };
    }
    mod.imports.push(b);
    importsByLocal.set(local, b);
  }

  // ---- pass 0: imports (top level only) ----
  for (const st of sf.statements) {
    if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
      const spec = st.moduleSpecifier.text;
      const ic = st.importClause;
      const { line } = pos(st);
      if (!ic) continue;
      if (ic.name) addImport(ic.name.text, spec, 'default', line);
      if (ic.namedBindings) {
        if (ts.isNamespaceImport(ic.namedBindings)) addImport(ic.namedBindings.name.text, spec, undefined, line);
        else for (const el of ic.namedBindings.elements) addImport(el.name.text, spec, (el.propertyName ?? el.name).text, line);
      }
    } else if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) {
        const req = requireSpec(d.initializer);
        if (!req) continue;
        const { line } = pos(d);
        if (ts.isIdentifier(d.name)) addImport(d.name.text, req.spec, req.member, line);
        else if (ts.isObjectBindingPattern(d.name)) {
          for (const el of d.name.elements) {
            if (!ts.isIdentifier(el.name)) continue;
            const member = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
            addImport(el.name.text, req.spec, member, line);
          }
        }
      }
    }
  }

  // ---- pass 1: app/router identifiers ----
  const expressLocals = new Set(
    mod.imports.filter((b) => b.kind === 'package' && b.package === 'express' && (b.member === undefined || b.member === 'default')).map((b) => b.local),
  );
  const routerLocals = new Set(
    mod.imports.filter((b) => b.kind === 'package' && b.package === 'express' && b.member === 'Router').map((b) => b.local),
  );
  const visitApps = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isCallExpression(n.initializer)) {
      const callee = n.initializer.expression;
      if (ts.isIdentifier(callee) && expressLocals.has(callee.text)) {
        mod.appIdents.add(n.name.text);
        mod.isRootApp = true;
      } else if (ts.isIdentifier(callee) && routerLocals.has(callee.text)) {
        mod.appIdents.add(n.name.text);
      } else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && expressLocals.has(callee.expression.text) && callee.name.text === 'Router') {
        mod.appIdents.add(n.name.text);
      }
    }
    ts.forEachChild(n, visitApps);
  };
  visitApps(sf);

  // ---- pass 2: functions ----
  const fnByNode = new Map<ts.Node, FunctionInfo>();
  const fnByName = new Map<string, FunctionInfo>();
  const moduleFn: FunctionInfo = { id: mod.moduleFunctionId, name: '<module>', file: rel, line: 1, col: 1, params: [], calls: [] };
  mod.functions.push(moduleFn);

  function nameFor(n: ts.FunctionLikeDeclaration): string {
    if (n.name && ts.isIdentifier(n.name)) return n.name.text;
    if (n.name && ts.isStringLiteral(n.name)) return n.name.text;
    const p = n.parent;
    if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
    if (p && ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) return p.name.text;
    if (p && ts.isCallExpression(p)) return '<handler>';
    return '<anon>';
  }
  const visitFns = (n: ts.Node) => {
    if (isFunctionLike(n)) {
      const { line, col } = pos(n);
      const name = nameFor(n);
      const info: FunctionInfo = {
        id: `${rel}#${name}@${line}:${col}`,
        name,
        file: rel,
        line,
        col,
        params: n.parameters.map((p) => (ts.isIdentifier(p.name) ? p.name.text : '<pattern>')),
        calls: [],
      };
      fnByNode.set(n, info);
      mod.functions.push(info);
      if (!name.startsWith('<') && !fnByName.has(name)) fnByName.set(name, info);
    }
    ts.forEachChild(n, visitFns);
  };
  visitFns(sf);

  function enclosing(n: ts.Node): { fn: FunctionInfo; node?: ts.Node } {
    let cur: ts.Node | undefined = n.parent;
    while (cur) {
      const f = fnByNode.get(cur);
      if (f) return { fn: f, node: cur };
      cur = cur.parent;
    }
    return { fn: moduleFn };
  }

  function hasParam(fromNode: ts.Node | undefined, name: string): boolean {
    let cur: ts.Node | undefined = fromNode;
    while (cur) {
      const f = fnByNode.get(cur);
      if (f && f.params.includes(name)) return true;
      cur = cur.parent;
    }
    return false;
  }

  // Identifiers inside a function assigned from req.* (one level of taint).
  const taintedByFn = new Map<ts.Node | undefined, Set<string>>();
  function mentionsReq(n: ts.Node): boolean {
    let hit = false;
    const walk = (x: ts.Node) => {
      if (hit) return;
      if (ts.isPropertyAccessExpression(x) || ts.isElementAccessExpression(x)) {
        let root: ts.Node = x;
        while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) root = root.expression;
        if (ts.isIdentifier(root) && REQ_NAMES.has(root.text)) {
          hit = true;
          return;
        }
      }
      ts.forEachChild(x, walk);
    };
    walk(n);
    return hit;
  }
  function tainted(fnNode: ts.Node | undefined): Set<string> {
    let set = taintedByFn.get(fnNode);
    if (set) return set;
    set = new Set();
    const scope = fnNode ?? sf;
    const walk = (x: ts.Node) => {
      if (x !== scope && isFunctionLike(x)) return;
      if (ts.isVariableDeclaration(x) && ts.isIdentifier(x.name) && x.initializer && mentionsReq(x.initializer)) set!.add(x.name.text);
      ts.forEachChild(x, walk);
    };
    walk(scope);
    taintedByFn.set(fnNode, set);
    return set;
  }
  function argsUseInput(call: ts.CallExpression, fnNode: ts.Node | undefined): boolean {
    const t = tainted(fnNode);
    for (const a of call.arguments) {
      if (mentionsReq(a)) return true;
      let found = false;
      const walk = (x: ts.Node) => {
        if (found) return;
        if (ts.isIdentifier(x) && t.has(x.text)) found = true;
        else ts.forEachChild(x, walk);
      };
      walk(a);
      if (found) return true;
    }
    return false;
  }

  // ---- pass 3: calls, routes, exports ----
  const globalGuards = new Map<string, string[]>();

  function describeArg(a: ts.Expression): string {
    return a.getText(sf).replace(/\s+/g, ' ').slice(0, 80);
  }

  function classifyHandlerArg(a: ts.Expression, route: RouteReg) {
    if (ts.isArrayLiteralExpression(a)) {
      a.elements.forEach((e) => classifyHandlerArg(e, route));
      return;
    }
    if (isFunctionLike(a)) {
      const f = fnByNode.get(a);
      if (f) route.handlerIds.push(f.id);
      return;
    }
    if (ts.isIdentifier(a)) {
      const b = importsByLocal.get(a.text);
      if (AUTH.test(a.text)) {
        route.guards.push(a.text);
        return;
      }
      if (b?.kind === 'local' && route.method === 'use' && !route.mountLocal) {
        // Provisional: project-level analysis confirms the target module exports a router.
        route.mountLocal = a.text;
        return;
      }
      const f = fnByName.get(a.text);
      if (f) {
        route.handlerIds.push(f.id);
        return;
      }
      if (b?.kind === 'local' && b.file) {
        // handler exported by another module: resolved at project level via a synthetic id
        route.handlerIds.push(`${relative(rootDir, b.file).replace(/\\/g, '/')}#${b.member ?? 'default'}`);
        return;
      }
      route.middleware.push(a.text);
      return;
    }
    const text = describeArg(a);
    if (AUTH.test(text)) route.guards.push(text);
    else route.middleware.push(text);
  }

  /** `app.route('/x').get(h).post(h2)`: walks the chain back to route(path) on an app ident. */
  function routeChainPath(expr: ts.Expression): string | undefined {
    let cur: ts.Expression = expr;
    for (let i = 0; i < 12; i++) {
      if (!ts.isCallExpression(cur) || !ts.isPropertyAccessExpression(cur.expression)) return undefined;
      const recv = cur.expression.expression;
      const name = cur.expression.name.text;
      if (name === 'route' && ts.isIdentifier(recv) && (mod.appIdents.has(recv.text) || recv.text === 'app' || recv.text === 'router')) {
        const a = cur.arguments[0];
        return a && ts.isStringLiteralLike(a) ? a.text : '*';
      }
      if (!HTTP_METHODS.has(name)) return undefined;
      cur = recv;
    }
    return undefined;
  }

  const visitCalls = (n: ts.Node) => {
    if (ts.isCallExpression(n)) {
      const { fn, node: fnNode } = enclosing(n);
      const callee = n.expression;
      const { line, col } = pos(n);
      let handled = false;

      if (ts.isPropertyAccessExpression(callee) && !ts.isIdentifier(callee.expression) && HTTP_METHODS.has(callee.name.text)) {
        // Chained form: app.route('/x').get(handler).post(handler)
        const chainPath = routeChainPath(callee.expression);
        if (chainPath !== undefined) {
          handled = true;
          const route: RouteReg = { method: callee.name.text, path: chainPath, line, app: 'route', guards: [], middleware: [], handlerIds: [] };
          for (const a of n.arguments) classifyHandlerArg(a, route);
          if (route.handlerIds.length || route.guards.length) mod.routes.push(route);
        }
      }

      if (!handled && ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
        const recv = callee.expression.text;
        const m = callee.name.text;
        const isApp = mod.appIdents.has(recv) || (!importsByLocal.has(recv) && (recv === 'app' || recv === 'router'));
        if (isApp && HTTP_METHODS.has(m)) {
          handled = true;
          const route: RouteReg = { method: m, path: '*', line, app: recv, guards: [...(globalGuards.get(recv) ?? [])], middleware: [], handlerIds: [] };
          const args = n.arguments;
          let i = 0;
          if (args[0] && ts.isStringLiteralLike(args[0])) {
            route.path = args[0].text;
            i = 1;
          }
          for (; i < args.length; i++) classifyHandlerArg(args[i]!, route);
          if (m === 'use' && route.path === '*' && !route.mountLocal && !route.handlerIds.length) {
            // app.use(guard) with no path: applies to every route registered afterwards.
            if (route.guards.length) globalGuards.set(recv, [...(globalGuards.get(recv) ?? []), ...route.guards]);
          } else {
            mod.routes.push(route);
          }
        } else if (isApp && m === 'listen') {
          handled = true;
          mod.listens = true;
          const local = n.arguments.some((a) => ts.isStringLiteralLike(a) && /^(127\.0\.0\.1|localhost|::1)$/.test(a.text));
          mod.listenLocalOnly = local;
        }
      }

      if (!handled) {
        let target: CallTarget | undefined;
        if (ts.isIdentifier(callee)) {
          const b = importsByLocal.get(callee.text);
          if (b?.kind === 'package') target = { kind: 'external', package: b.package!, symbol: b.member ?? 'default' };
          else if (b?.kind === 'local') target = { kind: 'local', name: b.member ?? 'default', file: b.file };
          else if (callee.text !== 'require') target = { kind: 'local', name: callee.text };
        } else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
          const recv = callee.expression.text;
          const m = callee.name.text;
          const b = importsByLocal.get(recv);
          if (b?.kind === 'package') {
            const named = b.member && b.member !== 'default';
            target = { kind: 'external', package: b.package!, symbol: named ? `${b.member}.${m}` : m };
          } else if (b?.kind === 'local') target = { kind: 'local', name: m, file: b.file };
          else if (RES_NAMES.has(recv) && hasParam(fnNode, recv)) target = { kind: 'framework', package: 'express', receiver: 'Response', symbol: m };
          else target = { kind: 'unknown', text: `${recv}.${m}` };
        }
        if (target) {
          fn.calls.push({ line, col, text: callee.getText(sf).replace(/\s+/g, ' ').slice(0, 80), target, userInput: argsUseInput(n, fnNode) });
        }
      }
    }

    // exports
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const lhs = n.left.getText(sf).replace(/\s+/g, '');
      if (lhs === 'module.exports' || lhs === 'exports') recordExportObject(n.right);
      else if (/^(module\.exports|exports)\.[A-Za-z_$][\w$]*$/.test(lhs)) recordExport(lhs.split('.').pop()!, n.right);
    }
    ts.forEachChild(n, visitCalls);
  };

  function exportValue(e: ts.Expression): string | undefined {
    if (ts.isIdentifier(e)) return e.text;
    if (isFunctionLike(e)) return fnByNode.get(e)?.id;
    return undefined;
  }
  function recordExport(name: string, e: ts.Expression) {
    const v = exportValue(e);
    if (v) mod.exports.set(name, v);
  }
  function recordExportObject(e: ts.Expression) {
    if (ts.isObjectLiteralExpression(e)) {
      for (const p of e.properties) {
        if (ts.isShorthandPropertyAssignment(p)) mod.exports.set(p.name.text, p.name.text);
        else if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) recordExport(p.name.text, p.initializer);
        else if (ts.isMethodDeclaration(p) && ts.isIdentifier(p.name)) {
          const f = fnByNode.get(p);
          if (f) mod.exports.set(p.name.text, f.id);
        }
      }
      return;
    }
    if (ts.isIdentifier(e) && mod.appIdents.has(e.text)) {
      mod.exportsRouter = e.text;
      return;
    }
    recordExport('default', e);
  }
  for (const st of sf.statements) {
    const mods = ts.canHaveModifiers(st) ? ts.getModifiers(st) : undefined;
    const isExport = mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    const isDefault = mods?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword);
    if (isExport && ts.isFunctionDeclaration(st) && st.name) mod.exports.set(isDefault ? 'default' : st.name.text, st.name.text);
    else if (isExport && ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name)) mod.exports.set(d.name.text, d.name.text);
    } else if (ts.isExportAssignment(st) && !st.isExportEquals) recordExportObject(st.expression);
  }
  visitCalls(sf);

  return mod;
}
