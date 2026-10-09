import ts from 'typescript';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, relative, resolve } from 'node:path';

export const HTTP_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'all', 'use', 'options', 'head']);
/**
 * Heuristic: an argument whose text looks like an auth guard (something that rejects a request
 * when the caller is not who they should be). Extended per project via nextfix.config.json.
 */
export const AUTH_RE = /auth(enticat|oriz|ed|z)?|logged|loginrequired|requirelogin|ensurelogin|checklogin|signedin|requireuser|requireadmin|isadmin|isuser|protect|guard|\brole|permission|permit|verifytoken|checktoken|requiretoken|validatetoken|jwt\(|expressjwt|checksession|requiresession|ensuresession|mustbe|denyall|\bacl\b/i;
/** Names that say the opposite of a guard. */
export const NOT_GUARD_RE = /unprotected|unauthenticated|optionalauth|noauth|public(router|routes)/i;
/** Common middleware that merely sets things up and never rejects a request. Checked before AUTH_RE. */
export const NON_GUARD_RE = /^(session|cookiesession|expresssession|passport\.(initialize|session)|flash|cookieparser|helmet|cors|morgan|compression|bodyparser|express\.(json|urlencoded|static|raw|text)|lusca|csrf|csurf|logger|errorhandler|methodoverride|servestatic|favicon|multer|upload|limiter|ratelimit|i18n|robots|securitytxt|timeout|responsetime)\b/i;
/** Parameter names that carry the HTTP request: Express/Fastify `req`/`request`, Koa `ctx`. */
export const REQ_NAMES = new Set(['req', 'request', 'ctx', 'context']);
const RES_NAMES = new Set(['res', 'response']);
/** Identifiers assumed to be an app or router when nothing better is known (plugin parameters). */
const APP_NAMES = new Set(['app', 'router', 'fastify', 'server', 'instance', 'api', 'koa']);
const FASTIFY_HOOKS = new Set(['onRequest', 'preParsing', 'preValidation', 'preHandler', 'preSerialization']);

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

export interface CallArg {
  /** Argument expression, abbreviated. */
  text: string;
  /** Names the argument derives from: the function's parameters, `req`/`request`, or free (captured) identifiers. */
  roots: string[];
}

export interface CallSite {
  line: number;
  col: number;
  text: string;
  target: CallTarget;
  /** Some argument derives directly from `req.*` in this function. */
  userInput: boolean;
  args: CallArg[];
}

export interface FunctionInfo {
  id: string;
  name: string;
  file: string;
  line: number;
  col: number;
  params: string[];
  calls: CallSite[];
  /** Enclosing function (callbacks and returned closures are reachable from it). */
  parentId?: string;
}

export interface RouteReg {
  method: string;
  path: string;
  line: number;
  app: string;
  guards: string[];
  middleware: string[];
  handlerIds: string[];
  /** Handler expressions that could not be resolved to a function (e.g. `login()`, `ctrl.index` on an unknown object). */
  unresolved: string[];
  /** Local import name of a router / plugin mounted by app.use(path, router) or fastify.register(plugin, { prefix }). */
  mountLocal?: string;
  /** Name of the function the registration sits in (Fastify plugins defined in the same file). */
  inFunction?: string;
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
  /** `export { x as y } from './f'` / `export * from './f'`: exported name ('*' for all) -> imported name and file */
  reexports: { exported: string; imported: string; file: string }[];
  exportsRouter?: string;
  listenLocalOnly?: boolean;
  listens: boolean;
  /** Fastify `@fastify/autoload` registrations: every route module under `dir` is mounted at its folder path. */
  autoload: { dir: string; prefix: string }[];
  /** Guards installed with `addHook` anywhere in this module (autohooks files apply them to their folder). */
  hookGuards: string[];
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
  const isGuard = (t: string) => !NON_GUARD_RE.test(t) && !NOT_GUARD_RE.test(t) && AUTH.test(t);
  /** An inline hook/middleware whose body rejects requests (401/403, unauthorized, throw) is a guard. */
  const GUARD_BODY_RE = /unauthorized|forbidden|\b40[13]\b|\.status\(\s*40[13]|\.code\(\s*40[13]|ctx\.throw\(|\bthrow\b/i;
  const isGuardNode = (a: ts.Node) => {
    const text = a.getText(sf).replace(/\s+/g, ' ');
    if (isGuard(text.slice(0, 80))) return true;
    if (isFunctionLike(a)) return GUARD_BODY_RE.test(text) && !NON_GUARD_RE.test(text.slice(0, 80));
    return false;
  };
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
    reexports: [],
    listens: false,
    autoload: [],
    hookGuards: [],
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

  // ---- pass 1: app/router identifiers (Express, Fastify, Koa), and `const x = new Y()` instances of imported classes ----
  const instanceOf = new Map<string, ImportBinding>();
  /** Koa router prefix (`new Router({ prefix })` / `router.prefix()`), by router identifier. */
  const routerPrefix = new Map<string, string>();
  const pkgLocals = (pkgs: string[], members: (string | undefined)[]) =>
    new Set(mod.imports.filter((b) => b.kind === 'package' && pkgs.includes(b.package!) && members.includes(b.member)).map((b) => b.local));
  const expressLocals = pkgLocals(['express'], [undefined, 'default']);
  const routerLocals = pkgLocals(['express'], ['Router']);
  const fastifyLocals = pkgLocals(['fastify'], [undefined, 'default', 'fastify']);
  const koaLocals = pkgLocals(['koa'], [undefined, 'default']);
  const koaRouterLocals = pkgLocals(['@koa/router', 'koa-router'], [undefined, 'default', 'Router']);
  const prefixOf = (arg: ts.Expression | undefined): string | undefined => {
    if (!arg || !ts.isObjectLiteralExpression(arg)) return undefined;
    for (const p of arg.properties) {
      if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === 'prefix' && ts.isStringLiteralLike(p.initializer)) return p.initializer.text;
    }
    return undefined;
  };
  const visitApps = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isNewExpression(n.initializer)) {
      const ctor = n.initializer.expression;
      const b = ts.isIdentifier(ctor) ? importsByLocal.get(ctor.text) : ts.isPropertyAccessExpression(ctor) && ts.isIdentifier(ctor.expression) ? importsByLocal.get(ctor.expression.text) : undefined;
      if (b?.kind === 'local') instanceOf.set(n.name.text, b);
      if (ts.isIdentifier(ctor) && koaLocals.has(ctor.text)) {
        mod.appIdents.add(n.name.text);
        mod.isRootApp = true;
      } else if (ts.isIdentifier(ctor) && (koaRouterLocals.has(ctor.text) || (importsByLocal.get(ctor.text)?.kind === 'package' && /router$/i.test(ctor.text)))) {
        // `new Router()` from @koa/router, or any package class named …Router (koa-swagger-decorator's SwaggerRouter, …)
        mod.appIdents.add(n.name.text);
        const p = prefixOf(n.initializer.arguments?.[0]);
        if (p) routerPrefix.set(n.name.text, p);
      }
    }
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isCallExpression(n.initializer)) {
      const callee = n.initializer.expression;
      if (ts.isIdentifier(callee) && (expressLocals.has(callee.text) || fastifyLocals.has(callee.text))) {
        mod.appIdents.add(n.name.text);
        mod.isRootApp = true;
      } else if (ts.isIdentifier(callee) && routerLocals.has(callee.text)) {
        mod.appIdents.add(n.name.text);
      } else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && expressLocals.has(callee.expression.text) && callee.name.text === 'Router') {
        mod.appIdents.add(n.name.text);
      } else if (ts.isCallExpression(callee) && requireSpec(callee)?.spec === 'fastify') {
        // const fastify = require('fastify')({ logger: true })
        mod.appIdents.add(n.name.text);
        mod.isRootApp = true;
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
    // `this.handleLogin = (req, res) => …` / `exports.home = …` / `obj.x = function () {}`
    if (p && ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(p.left)) return p.left.name.text;
    if (p && ts.isCallExpression(p)) return '<handler>';
    if (p && ts.isReturnStatement(p)) return '<returned>';
    return '<anon>';
  }
  const fnStack: FunctionInfo[] = [];
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
        parentId: fnStack[fnStack.length - 1]?.id,
      };
      fnByNode.set(n, info);
      mod.functions.push(info);
      if (!name.startsWith('<') && !fnByName.has(name)) fnByName.set(name, info);
      fnStack.push(info);
      ts.forEachChild(n, visitFns);
      fnStack.pop();
      return;
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

  // ---- data flow inside a function: which names does each expression derive from? ----
  // Roots are the function's parameters, `req`/`request`, and free (captured) identifiers.
  // Local variables are resolved to the roots of what they were assigned from.
  const flowByFn = new Map<ts.Node | undefined, { locals: Map<string, Set<string>>; params: Set<string> }>();

  function baseIdentifiers(n: ts.Node, out: Set<string>) {
    if (ts.isIdentifier(n)) {
      out.add(n.text);
      return;
    }
    if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
      baseIdentifiers(n.expression, out);
      if (ts.isElementAccessExpression(n)) baseIdentifiers(n.argumentExpression, out);
      return;
    }
    if (ts.isCallExpression(n) || ts.isNewExpression(n)) {
      // The result of a call derives from its arguments (and its receiver for method calls).
      for (const a of n.arguments ?? []) baseIdentifiers(a, out);
      if (ts.isPropertyAccessExpression(n.expression)) baseIdentifiers(n.expression.expression, out);
      return;
    }
    if (isFunctionLike(n)) return; // a function value is not data
    ts.forEachChild(n, (c) => baseIdentifiers(c, out));
  }
  function flow(fnNode: ts.Node | undefined) {
    let f = flowByFn.get(fnNode);
    if (f) return f;
    const scope = fnNode ?? sf;
    const params = new Set<string>();
    if (fnNode && isFunctionLike(fnNode)) for (const p of fnNode.parameters) if (ts.isIdentifier(p.name)) params.add(p.name.text);
    const raw = new Map<string, Set<string>>(); // local -> direct base identifiers of its initializer
    const bind = (name: ts.BindingName, init: ts.Node | undefined) => {
      if (!init) return;
      const ids = new Set<string>();
      baseIdentifiers(init, ids);
      if (ts.isIdentifier(name)) raw.set(name.text, new Set([...(raw.get(name.text) ?? []), ...ids]));
      else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
        for (const el of name.elements) if (ts.isBindingElement(el) && ts.isIdentifier(el.name)) raw.set(el.name.text, new Set([...(raw.get(el.name.text) ?? []), ...ids]));
      }
    };
    const walk = (x: ts.Node) => {
      if (x !== scope && isFunctionLike(x)) return;
      if (ts.isVariableDeclaration(x)) bind(x.name, x.initializer);
      else if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(x.left)) bind(x.left, x.right);
      ts.forEachChild(x, walk);
    };
    walk(scope);
    // Resolve local chains to roots (params / req / free names), bounded.
    const locals = new Map<string, Set<string>>();
    const resolve = (name: string, depth: number, seen: Set<string>): Set<string> => {
      if (locals.has(name)) return locals.get(name)!;
      const direct = raw.get(name);
      if (!direct) return new Set([name]); // param or free identifier: a root
      if (depth > 6 || seen.has(name)) return new Set();
      seen.add(name);
      const out = new Set<string>();
      for (const d of direct) {
        if (d === name) continue;
        for (const r of resolve(d, depth + 1, seen)) out.add(r);
      }
      locals.set(name, out);
      return out;
    };
    for (const name of raw.keys()) resolve(name, 0, new Set());
    f = { locals, params };
    flowByFn.set(fnNode, f);
    return f;
  }
  function rootsOf(expr: ts.Node, fnNode: ts.Node | undefined): Set<string> {
    const f = flow(fnNode);
    const ids = new Set<string>();
    baseIdentifiers(expr, ids);
    const out = new Set<string>();
    for (const id of ids) {
      const r = f.locals.get(id);
      if (r) for (const x of r) out.add(x);
      else out.add(id);
    }
    return out;
  }
  function callArgs(call: ts.CallExpression, fnNode: ts.Node | undefined): CallArg[] {
    return call.arguments.map((a) => ({ text: a.getText(sf).replace(/\s+/g, ' ').slice(0, 60), roots: [...rootsOf(a, fnNode)] }));
  }
  function argsUseInput(args: CallArg[]): boolean {
    return args.some((a) => a.roots.some((r) => REQ_NAMES.has(r)));
  }

  // ---- pass 3: calls, routes, exports ----
  const globalGuards = new Map<string, string[]>();
  /** Fastify plugins defined in this file and registered with a prefix: routes inside them get it. */
  const localPluginPrefix = new Map<string, { prefix: string; guards: string[] }>();
  /** Koa routers of this file mounted on an app or another router of this file. */
  const mountSame: { router: string; prefix: string; guards: string[]; onto: string }[] = [];

  /** `x.routes()` / `x.middleware()` of a Koa router: same-file router or local import. */
  function koaRoutesOf(a: ts.Expression): { kind: 'same' | 'local'; name: string } | undefined {
    if (!ts.isCallExpression(a) || !ts.isPropertyAccessExpression(a.expression) || !ts.isIdentifier(a.expression.expression)) return undefined;
    if (!['routes', 'middleware', 'allowedMethods'].includes(a.expression.name.text)) return undefined;
    if (a.expression.name.text === 'allowedMethods') return undefined;
    const x = a.expression.expression.text;
    const b = importsByLocal.get(x);
    if (b?.kind === 'local') return { kind: 'local', name: x };
    if (mod.appIdents.has(x) || APP_NAMES.has(x)) return { kind: 'same', name: x };
    return undefined;
  }

  /** Fastify hook values (`preHandler: auth`, `onRequest: [a, b]`): guards or middleware, never handlers. */
  function classifyHook(v: ts.Expression, route: RouteReg) {
    if (ts.isArrayLiteralExpression(v)) {
      v.elements.forEach((e) => classifyHook(e, route));
      return;
    }
    const text = describeArg(v);
    if (isGuardNode(v)) route.guards.push(text);
    else route.middleware.push(text);
  }

  /** Directory named by an autoload `dir:` option: a string, or `path.join(__dirname, 'routes')`-style call. */
  function autoloadDir(opts: ts.Expression | undefined): string | undefined {
    if (!opts || !ts.isObjectLiteralExpression(opts)) return undefined;
    const dirProp = opts.properties.find((p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === 'dir');
    if (!dirProp) return undefined;
    const v = dirProp.initializer;
    if (ts.isStringLiteralLike(v)) return resolve(dirname(file), v.text);
    if (ts.isCallExpression(v)) {
      const parts = v.arguments.filter((a): a is ts.StringLiteralLike => ts.isStringLiteralLike(a)).map((a) => a.text);
      if (parts.length) return resolve(dirname(file), ...parts);
    }
    return undefined;
  }
  function autoloadPrefix(opts: ts.Expression | undefined): string {
    if (!opts || !ts.isObjectLiteralExpression(opts)) return '';
    const direct = prefixOf(opts);
    if (direct) return direct;
    const inner = opts.properties.find((p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === 'options');
    return inner ? prefixOf(inner.initializer) ?? '' : '';
  }

  function describeArg(a: ts.Expression): string {
    if (isFunctionLike(a)) return `inline check (${rel}:${pos(a).line})`;
    return a.getText(sf).replace(/\s+/g, ' ').slice(0, 80);
  }

  const relOf = (abs: string) => relative(rootDir, abs).replace(/\\/g, '/');

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
      if (isGuard(a.text)) {
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
        route.handlerIds.push(`${relOf(b.file)}#${b.member ?? 'default'}`);
        return;
      }
      if (b?.kind === 'package') route.middleware.push(a.text);
      else route.unresolved.push(a.text);
      return;
    }
    const text = describeArg(a);
    if (isGuard(text)) {
      route.guards.push(text);
      return;
    }
    // `controller.method` / `instance.method`: a handler living in another module. When the
    // receiver is a named import (`import { user } from './controller'`), keep the member so a
    // barrel re-export can be followed: file#user.getUsers.
    if (ts.isPropertyAccessExpression(a) && ts.isIdentifier(a.expression)) {
      const recv = a.expression.text;
      const b = importsByLocal.get(recv) ?? instanceOf.get(recv);
      if (b?.kind === 'local' && b.file) {
        const member = b.member && b.member !== 'default' && importsByLocal.has(recv) ? `${b.member}.` : '';
        route.handlerIds.push(`${relOf(b.file)}#${member}${a.name.text}`);
        return;
      }
      if (b?.kind === 'package') {
        route.middleware.push(text);
        return;
      }
      route.unresolved.push(text);
      return;
    }
    if (ts.isCallExpression(a)) {
      // `login()` / `ctrl.handler(opts)`: a factory returning the handler; the factory's body
      // (and the closure it returns) is what runs. `wrap(handler())` unwraps to the inner call.
      const ref = factoryRef(a);
      if (ref) route.handlerIds.push(ref);
      else if (NON_GUARD_RE.test(text)) route.middleware.push(text);
      else route.unresolved.push(text);
      return;
    }
    route.unresolved.push(text);
  }

  /**
   * Function id / cross-module ref for a factory call. A handler-shaped argument (a call, a
   * function, a resolvable reference) means the callee is a wrapper such as asyncHandler(fn);
   * otherwise the callee itself is the factory.
   */
  function factoryRef(call: ts.CallExpression, depth = 0): string | undefined {
    if (depth < 2) {
      for (const arg of call.arguments) {
        if (ts.isCallExpression(arg)) {
          const r = factoryRef(arg, depth + 1);
          if (r) return r;
        } else if (ts.isPropertyAccessExpression(arg) && ts.isIdentifier(arg.expression)) {
          const b = importsByLocal.get(arg.expression.text) ?? instanceOf.get(arg.expression.text);
          if (b?.kind === 'local' && b.file) return `${relOf(b.file)}#${arg.name.text}`;
        } else if (ts.isIdentifier(arg)) {
          const f = fnByName.get(arg.text);
          if (f) return f.id;
          const b = importsByLocal.get(arg.text);
          if (b?.kind === 'local' && b.file) return `${relOf(b.file)}#${b.member ?? 'default'}`;
        } else if (isFunctionLike(arg)) {
          const f = fnByNode.get(arg);
          if (f) return f.id;
        }
      }
    }
    const callee = call.expression;
    if (ts.isIdentifier(callee)) {
      const b = importsByLocal.get(callee.text);
      if (b?.kind === 'local' && b.file) return `${relOf(b.file)}#${b.member ?? 'default'}`;
      const f = fnByName.get(callee.text);
      if (f) return f.id;
    } else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
      const b = importsByLocal.get(callee.expression.text) ?? instanceOf.get(callee.expression.text);
      if (b?.kind === 'local' && b.file) return `${relOf(b.file)}#${callee.name.text}`;
    }
    return undefined;
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
          const route: RouteReg = { method: callee.name.text, path: chainPath, line, app: 'route', guards: [], middleware: [], handlerIds: [], unresolved: [] };
          for (const a of n.arguments) classifyHandlerArg(a, route);
          if (route.handlerIds.length || route.unresolved.length) mod.routes.push(route);
        }
      }

      if (!handled && ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
        const recv = callee.expression.text;
        const m = callee.name.text;
        const isApp = mod.appIdents.has(recv) || (!importsByLocal.has(recv) && (APP_NAMES.has(recv) || /router$/i.test(recv)));
        const newRoute = (method: string): RouteReg => ({ method, path: '*', line, app: recv, guards: [...(globalGuards.get(recv) ?? [])], middleware: [], handlerIds: [], unresolved: [], inFunction: fn.name });
        if (isApp && m === 'route' && n.arguments[0] && ts.isObjectLiteralExpression(n.arguments[0])) {
          // Fastify: fastify.route({ method: 'GET', url: '/x', preHandler: [...], handler })
          handled = true;
          const route = newRoute('get');
          for (const p of n.arguments[0].properties) {
            if (!ts.isPropertyAssignment(p) || !ts.isIdentifier(p.name)) continue;
            const key = p.name.text;
            if (key === 'method') route.method = ts.isStringLiteralLike(p.initializer) ? p.initializer.text.toLowerCase() : ts.isArrayLiteralExpression(p.initializer) ? p.initializer.elements.map((e) => (ts.isStringLiteralLike(e) ? e.text.toLowerCase() : '?')).join('|') : 'all';
            else if (key === 'url' || key === 'path') route.path = ts.isStringLiteralLike(p.initializer) ? p.initializer.text : '*';
            else if (key === 'handler') classifyHandlerArg(p.initializer, route);
            else if (FASTIFY_HOOKS.has(key)) classifyHook(p.initializer, route);
          }
          mod.routes.push(route);
        } else if (isApp && m === 'register') {
          // Fastify: fastify.register(plugin, { prefix: '/x' })
          handled = true;
          const [plugin, opts] = n.arguments;
          const prefix = prefixOf(opts) ?? '';
          const spec = plugin ? requireSpec(plugin)?.spec : undefined;
          if (plugin && ts.isIdentifier(plugin)) {
            const b = importsByLocal.get(plugin.text);
            if (b?.kind === 'package' && b.package === '@fastify/autoload') {
              const dir = autoloadDir(opts);
              if (dir) mod.autoload.push({ dir, prefix: autoloadPrefix(opts) });
            } else if (b?.kind === 'local') mod.routes.push({ ...newRoute('use'), path: prefix || '*', mountLocal: plugin.text, guards: [...(globalGuards.get(recv) ?? [])] });
            else if (!b && fnByName.has(plugin.text)) localPluginPrefix.set(plugin.text, { prefix, guards: [...(globalGuards.get(recv) ?? [])] });
          } else if (spec && (spec.startsWith('.') || spec.startsWith('/'))) {
            const local = `<register:${spec}>`;
            addImport(local, spec, undefined, line);
            mod.routes.push({ ...newRoute('use'), path: prefix || '*', mountLocal: local, guards: [...(globalGuards.get(recv) ?? [])] });
          } else if (plugin && (isFunctionLike(plugin) || ts.isArrowFunction(plugin))) {
            const f = fnByNode.get(plugin);
            if (f) localPluginPrefix.set(f.name, { prefix, guards: [...(globalGuards.get(recv) ?? [])] });
          }
        } else if (isApp && m === 'addHook' && n.arguments[0] && ts.isStringLiteralLike(n.arguments[0]) && FASTIFY_HOOKS.has(n.arguments[0].text) && n.arguments[1]) {
          // Fastify: fastify.addHook('onRequest', fastify.authenticate) applies to later routes in this scope.
          handled = true;
          const text = describeArg(n.arguments[1]);
          if (isGuardNode(n.arguments[1])) {
            globalGuards.set(recv, [...(globalGuards.get(recv) ?? []), text]);
            mod.hookGuards.push(text);
          }
        } else if (isApp && m === 'prefix' && n.arguments[0] && ts.isStringLiteralLike(n.arguments[0])) {
          handled = true;
          routerPrefix.set(recv, n.arguments[0].text);
        } else if (isApp && HTTP_METHODS.has(m)) {
          handled = true;
          const route = newRoute(m);
          const args = n.arguments;
          let i = 0;
          if (args[0] && ts.isStringLiteralLike(args[0])) {
            route.path = args[0].text;
            i = 1;
            // Koa named route: router.get('users', '/users', handler)
            if (args[1] && ts.isStringLiteralLike(args[1]) && !args[0].text.startsWith('/') && args[1].text.startsWith('/')) {
              route.path = args[1].text;
              i = 2;
            }
          } else if (args[0] && ts.isArrayLiteralExpression(args[0]) && args[0].elements.every((e) => ts.isStringLiteralLike(e))) {
            route.path = args[0].elements.map((e) => (e as ts.StringLiteralLike).text).join(' | ');
            i = 1;
          } else if (args[0] && (ts.isRegularExpressionLiteral(args[0]) || ts.isArrayLiteralExpression(args[0]))) {
            route.path = args[0].getText(sf).slice(0, 60);
            i = 1;
          }
          // Fastify route options: fastify.get('/x', { preHandler: [auth], schema }, handler)
          if (i > 0 && args[i] && ts.isObjectLiteralExpression(args[i]!) && m !== 'use') {
            for (const p of (args[i] as ts.ObjectLiteralExpression).properties) {
              if (!ts.isPropertyAssignment(p) || !ts.isIdentifier(p.name)) continue;
              if (p.name.text === 'handler') classifyHandlerArg(p.initializer, route);
              else if (FASTIFY_HOOKS.has(p.name.text)) classifyHook(p.initializer, route);
            }
            i++;
          }
          // Koa: app.use(router.routes()) / router.use('/p', sub.routes()) mounts a router; that
          // argument is a mount, never a guard or handler.
          const mounted = m === 'use' ? args.map((a) => koaRoutesOf(a)).find((x) => x) : undefined;
          for (; i < args.length; i++) if (!(m === 'use' && koaRoutesOf(args[i]!))) classifyHandlerArg(args[i]!, route);
          if (m === 'use' && !route.mountLocal) {
            if (mounted) {
              const prefix = route.path === '*' ? '' : route.path;
              if (mounted.kind === 'same') mountSame.push({ router: mounted.name, prefix, guards: route.guards, onto: recv });
              else mod.routes.push({ ...route, path: prefix || '*', mountLocal: mounted.name });
            } else {
              // app.use(guard) with no path applies to every route registered afterwards; anything
              // else passed to app.use is middleware, not an entry point.
              const scoped = route.path !== '*' && route.path !== '/';
              if (route.guards.length && !scoped) globalGuards.set(recv, [...(globalGuards.get(recv) ?? []), ...route.guards]);
              else if (scoped && (route.handlerIds.length || route.unresolved.length)) mod.routes.push(route);
            }
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
        if (ts.isPropertyAccessExpression(callee) && callee.expression.kind === ts.SyntaxKind.ThisKeyword) {
          // this.method(): a call within the same class / object
          target = { kind: 'local', name: callee.name.text };
        } else if (ts.isIdentifier(callee)) {
          const b = importsByLocal.get(callee.text);
          if (b?.kind === 'package') target = { kind: 'external', package: b.package!, symbol: b.member ?? 'default' };
          else if (b?.kind === 'local') target = { kind: 'local', name: b.member ?? 'default', file: b.file };
          else if (callee.text !== 'require') target = { kind: 'local', name: callee.text };
        } else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
          const recv = callee.expression.text;
          const m = callee.name.text;
          const b = importsByLocal.get(recv) ?? instanceOf.get(recv);
          if (b?.kind === 'package') {
            const named = b.member && b.member !== 'default';
            target = { kind: 'external', package: b.package!, symbol: named ? `${b.member}.${m}` : m };
          } else if (b?.kind === 'local') target = { kind: 'local', name: m, file: b.file };
          else if (recv === 'this' || fnByName.has(m)) target = { kind: 'local', name: m };
          else if (RES_NAMES.has(recv) && hasParam(fnNode, recv)) target = { kind: 'framework', package: 'express', receiver: 'Response', symbol: m };
          else target = { kind: 'unknown', text: `${recv}.${m}` };
        }
        if (target) {
          const args = callArgs(n, fnNode);
          fn.calls.push({ line, col, text: callee.getText(sf).replace(/\s+/g, ' ').slice(0, 80), target, userInput: argsUseInput(args), args });
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
    if (ts.isExportDeclaration(st)) {
      const spec = st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier) ? st.moduleSpecifier.text : undefined;
      if (spec) {
        // `export { default as user } from './user'` / `export * from './x'`: a barrel.
        const target = resolveLocal(file, spec);
        if (target) {
          if (!st.exportClause) mod.reexports.push({ exported: '*', imported: '*', file: target });
          else if (ts.isNamedExports(st.exportClause)) for (const el of st.exportClause.elements) mod.reexports.push({ exported: el.name.text, imported: (el.propertyName ?? el.name).text, file: target });
          else if (ts.isNamespaceExport(st.exportClause)) mod.reexports.push({ exported: st.exportClause.name.text, imported: '*', file: target });
        }
      } else if (st.exportClause && ts.isNamedExports(st.exportClause)) {
        // `export { protectedRouter, helper as h }`
        for (const el of st.exportClause.elements) mod.exports.set(el.name.text, (el.propertyName ?? el.name).text);
      }
      continue;
    }
    if (isExport && ts.isClassDeclaration(st) && st.name) mod.exports.set(isDefault ? 'default' : st.name.text, st.name.text);
    else if (isExport && ts.isFunctionDeclaration(st) && st.name) mod.exports.set(isDefault ? 'default' : st.name.text, st.name.text);
    else if (isExport && ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name)) mod.exports.set(d.name.text, d.name.text);
    } else if (ts.isExportAssignment(st) && !st.isExportEquals) recordExportObject(st.expression);
  }
  visitCalls(sf);

  // Fastify plugins defined and registered in this file: apply their prefix and guards.
  for (const r of mod.routes) {
    const plugin = r.inFunction ? localPluginPrefix.get(r.inFunction) : undefined;
    if (!plugin) continue;
    r.path = joinPaths(plugin.prefix, r.path);
    r.guards = [...plugin.guards, ...r.guards];
  }
  // Koa routers: a router's own prefix, then the prefix and guards of whatever mounted it in this file.
  const mountedRouters = new Set<string>();
  for (const r of mod.routes) {
    if (r.mountLocal) continue;
    const own = routerPrefix.get(r.app);
    if (own) r.path = joinPaths(own, r.path);
  }
  for (const mt of mountSame) {
    mountedRouters.add(mt.router);
    for (const r of mod.routes) {
      if (r.app !== mt.router || r.mountLocal) continue;
      r.path = joinPaths(mt.prefix, r.path);
      r.guards = [...mt.guards, ...r.guards];
      r.app = mt.onto;
    }
  }
  // A router created in this file and exported (default or named) is a router module.
  if (!mod.exportsRouter) {
    for (const v of mod.exports.values()) {
      if (mod.appIdents.has(v)) {
        mod.exportsRouter = v;
        break;
      }
    }
  }

  return mod;
}

function joinPaths(prefix: string, path: string): string {
  if (!prefix) return path;
  const p = path === '*' ? '' : path;
  const s = `${prefix}/${p}`.replace(/\/{2,}/g, '/');
  return s.length > 1 ? s.replace(/\/$/, '') : s || '/';
}
