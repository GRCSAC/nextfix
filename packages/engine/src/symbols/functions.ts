import ts from 'typescript';

export interface FnRange {
  /** Name as written in source; synthetic for anonymous functions assigned to a property. */
  name: string;
  startLine: number;
  endLine: number;
  /** Property this function was assigned to (e.g. `res.redirect = function redirect`). */
  assignedTo?: string;
  /** Class this method belongs to. */
  className?: string;
}

export interface ImportRef {
  specifier: string;
  /** local name -> imported name ('default', '*' for a namespace, or the export name) */
  bindings: { local: string; imported: string }[];
}

export interface ReExport {
  specifier: string;
  /** 'all' for `export * from` / `module.exports = require()`, else exported -> imported */
  names: 'all' | { exported: string; imported: string }[];
}

export interface FileFacts {
  functions: FnRange[];
  /** public name -> local name (function, variable or import binding) */
  publicByName: Map<string, string>;
  /** local name -> public names it is exported as */
  publicByFn: Map<string, Set<string>>;
  /** function name -> identifiers it calls */
  calls: Map<string, Set<string>>;
  /** function name -> every identifier it references (imports, module variables, functions) */
  refs: Map<string, Set<string>>;
  /** identifiers referenced at module level (outside any function) */
  moduleRefs: Set<string>;
  /** top-level variable name -> identifiers referenced in its initializer (outside nested functions) */
  varRefs: Map<string, Set<string>>;
  /** top-level variable / class declarations with their line ranges */
  topLevel: { name: string; startLine: number; endLine: number; kind: 'var' | 'class' | 'function' }[];
  imports: ImportRef[];
  reexports: ReExport[];
  /** `module.exports = function` or `export default function`: the package is one callable. */
  defaultIsFunction: boolean;
}

function isFunctionLike(n: ts.Node): n is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n) || ts.isConstructorDeclaration(n);
}

function propName(n: ts.PropertyName | ts.MemberName): string | undefined {
  if (ts.isIdentifier(n) || ts.isStringLiteral(n) || ts.isNumericLiteral(n) || ts.isPrivateIdentifier(n)) return n.text;
  return undefined;
}

function requireSpec(e: ts.Expression | undefined): string | undefined {
  if (!e) return undefined;
  if (ts.isCallExpression(e) && ts.isIdentifier(e.expression) && e.expression.text === 'require') {
    const a = e.arguments[0];
    if (a && ts.isStringLiteralLike(a)) return a.text;
  }
  return undefined;
}

/** Parses one source file: function ranges, public surface, imports/re-exports, and who references what. */
export function analyzeFile(text: string, fileName = 'file.js'): FileFacts {
  const kind = /\.tsx?$/.test(fileName) ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind);
  const line = (pos: number) => sf.getLineAndCharacterOfPosition(pos).line + 1;
  const facts: FileFacts = { functions: [], publicByName: new Map(), publicByFn: new Map(), calls: new Map(), refs: new Map(), moduleRefs: new Set(), varRefs: new Map(), topLevel: [], imports: [], reexports: [], defaultIsFunction: false };
  const byNode = new Map<ts.Node, FnRange>();

  function assignedProp(p: ts.Node | undefined): string | undefined {
    if (!p || !ts.isBinaryExpression(p) || p.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return undefined;
    const lhs = p.left.getText(sf).replace(/\s+/g, '');
    if (lhs === 'module.exports' || lhs === 'exports') return undefined;
    if (ts.isPropertyAccessExpression(p.left)) return p.left.name.text;
    if (ts.isElementAccessExpression(p.left) && ts.isStringLiteral(p.left.argumentExpression)) return p.left.argumentExpression.text;
    return undefined;
  }
  function nameFor(n: ts.FunctionLikeDeclaration): { name: string; assignedTo?: string } {
    if (ts.isConstructorDeclaration(n)) return { name: 'constructor' };
    const p = n.parent;
    // `var parseKeys = function parseQueryStringKeys () {}`: callers use the variable's name.
    if (ts.isFunctionExpression(n) && n.name && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return { name: p.name.text };
    if (n.name && (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name))) return { name: n.name.text, assignedTo: assignedProp(n.parent) };
    if (ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return { name: p.name.text };
    // `{ html: function () {} }` is a callback inside an object literal, not public API.
    if (ts.isPropertyAssignment(p) && propName(p.name)) return { name: propName(p.name)! };
    const assigned = assignedProp(p);
    if (assigned) return { name: assigned, assignedTo: assigned };
    // `var pick = flatRest(function (object, paths) { … })`: the wrapped function takes the variable's name.
    if (ts.isCallExpression(p) && p.parent && ts.isVariableDeclaration(p.parent) && ts.isIdentifier(p.parent.name)) return { name: p.parent.name.text };
    if (ts.isCallExpression(p) && p.parent) {
      const a = assignedProp(p.parent);
      if (a) return { name: a, assignedTo: a };
    }
    return { name: `<anon@${line(n.getStart(sf))}>` };
  }
  function enclosingClassName(n: ts.Node): string | undefined {
    let cur: ts.Node | undefined = n.parent;
    while (cur) {
      if (ts.isClassDeclaration(cur) || ts.isClassExpression(cur)) {
        if (cur.name) return cur.name.text;
        const p = cur.parent;
        if (ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
        return undefined;
      }
      if (isFunctionLike(cur)) return undefined;
      cur = cur.parent;
    }
    return undefined;
  }

  // ---- pass 1: functions, classes, top-level declarations ----
  const walk = (n: ts.Node) => {
    if (isFunctionLike(n) && n.body) {
      const { name, assignedTo } = nameFor(n);
      const r: FnRange = { name, startLine: line(n.getStart(sf)), endLine: line(n.getEnd()), assignedTo, className: ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n) ? enclosingClassName(n) : undefined };
      facts.functions.push(r);
      byNode.set(n, r);
    }
    ts.forEachChild(n, walk);
  };
  walk(sf);
  for (const st of sf.statements) {
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name)) facts.topLevel.push({ name: d.name.text, startLine: line(st.getStart(sf)), endLine: line(st.getEnd()), kind: 'var' });
    } else if (ts.isClassDeclaration(st) && st.name) {
      facts.topLevel.push({ name: st.name.text, startLine: line(st.getStart(sf)), endLine: line(st.getEnd()), kind: 'class' });
    } else if (ts.isFunctionDeclaration(st) && st.name) {
      facts.topLevel.push({ name: st.name.text, startLine: line(st.getStart(sf)), endLine: line(st.getEnd()), kind: 'function' });
    }
  }

  function enclosingFn(n: ts.Node): FnRange | undefined {
    let cur: ts.Node | undefined = n.parent;
    while (cur) {
      const f = byNode.get(cur);
      if (f) return f;
      cur = cur.parent;
    }
    return undefined;
  }
  function addPublic(pub: string, local: string) {
    facts.publicByName.set(pub, local);
    const set = facts.publicByFn.get(local) ?? new Set();
    set.add(pub);
    facts.publicByFn.set(local, set);
  }
  function valueName(e: ts.Expression): string | undefined {
    if (ts.isIdentifier(e)) return e.text;
    if (isFunctionLike(e)) return byNode.get(e)?.name;
    if (ts.isClassExpression(e) && e.name) return e.name.text;
    if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) return e.expression.text; // `exports.x = ns.y` -> ns
    return undefined;
  }
  function enclosingTopVar(n: ts.Node): string | undefined {
    let cur: ts.Node | undefined = n.parent;
    while (cur) {
      if (ts.isVariableDeclaration(cur) && ts.isIdentifier(cur.name) && cur.parent && ts.isVariableDeclarationList(cur.parent) && cur.parent.parent && ts.isVariableStatement(cur.parent.parent) && cur.parent.parent.parent === sf) {
        return cur.name.text;
      }
      cur = cur.parent;
    }
    return undefined;
  }
  function addRef(fn: FnRange | undefined, id: string, node: ts.Node) {
    if (fn) {
      const set = facts.refs.get(fn.name) ?? new Set();
      set.add(id);
      facts.refs.set(fn.name, set);
      return;
    }
    facts.moduleRefs.add(id);
    const v = enclosingTopVar(node);
    if (v && v !== id) {
      const set = facts.varRefs.get(v) ?? new Set();
      set.add(id);
      facts.varRefs.set(v, set);
    }
  }

  // ---- pass 2: calls, references, CJS exports/imports ----
  const walk2 = (n: ts.Node) => {
    if (ts.isIdentifier(n) && !(ts.isPropertyAccessExpression(n.parent) && n.parent.name === n) && !(ts.isPropertyAssignment(n.parent) && n.parent.name === n)) {
      addRef(enclosingFn(n), n.text, n);
    }
    if (ts.isCallExpression(n) || ts.isNewExpression(n)) {
      const f = enclosingFn(n);
      if (f) {
        const set = facts.calls.get(f.name) ?? new Set();
        const callee = n.expression;
        const id = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
        if (id) set.add(id);
        // A function passed as an argument may be called by the callee: count it as reachable.
        for (const a of n.arguments ?? []) if (ts.isIdentifier(a)) set.add(a.text);
        if (set.size) facts.calls.set(f.name, set);
      }
    }
    if (ts.isVariableDeclaration(n) && !enclosingFn(n)) {
      // const x = require('./y') / const { a: b } = require('./y') / const x = require('./y').z
      let init = n.initializer;
      let member: string | undefined;
      if (init && ts.isPropertyAccessExpression(init) && requireSpec(init.expression)) {
        member = init.name.text;
        init = init.expression;
      }
      const spec = requireSpec(init);
      if (spec) {
        if (ts.isIdentifier(n.name)) facts.imports.push({ specifier: spec, bindings: [{ local: n.name.text, imported: member ?? '*' }] });
        else if (ts.isObjectBindingPattern(n.name)) {
          const bindings = n.name.elements.filter((el) => ts.isIdentifier(el.name)).map((el) => ({ local: (el.name as ts.Identifier).text, imported: el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : (el.name as ts.Identifier).text }));
          facts.imports.push({ specifier: spec, bindings });
        }
      }
    }
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const lhs = n.left.getText(sf).replace(/\s+/g, '');
      if (lhs === 'module.exports' || lhs === 'exports') {
        const spec = requireSpec(n.right);
        if (spec) facts.reexports.push({ specifier: spec, names: 'all' });
        else if (isFunctionLike(n.right)) {
          facts.defaultIsFunction = true;
          const v = byNode.get(n.right)?.name;
          if (v) addPublic('default', v);
        } else if (ts.isIdentifier(n.right)) {
          addPublic('default', n.right.text);
          if (facts.functions.some((f) => f.name === n.right.getText(sf))) facts.defaultIsFunction = true;
        } else if (ts.isObjectLiteralExpression(n.right)) {
          for (const p of n.right.properties) {
            if (ts.isShorthandPropertyAssignment(p)) addPublic(p.name.text, p.name.text);
            else if (ts.isPropertyAssignment(p) && propName(p.name)) {
              const v = valueName(p.initializer);
              if (v) addPublic(propName(p.name)!, v);
            } else if (ts.isMethodDeclaration(p) && propName(p.name)) addPublic(propName(p.name)!, propName(p.name)!);
            else if (ts.isSpreadAssignment(p)) {
              const s = requireSpec(p.expression);
              if (s) facts.reexports.push({ specifier: s, names: 'all' });
              else if (ts.isIdentifier(p.expression)) addPublic('*', p.expression.text);
            }
          }
        } else if (ts.isClassExpression(n.right) && n.right.name) addPublic('default', n.right.name.text);
      } else if (ts.isPropertyAccessExpression(n.left) || (ts.isElementAccessExpression(n.left) && ts.isStringLiteral(n.left.argumentExpression))) {
        // `exports.x = f`, `module.exports.x = f`, `lodash.template = template`, `res.redirect = function redirect`
        const pub = ts.isPropertyAccessExpression(n.left) ? n.left.name.text : (n.left.argumentExpression as ts.StringLiteral).text;
        const spec = requireSpec(n.right);
        if (spec) facts.reexports.push({ specifier: spec, names: [{ exported: pub, imported: '*' }] });
        else {
          const v = valueName(n.right);
          if (v && pub !== 'exports') addPublic(pub, v);
        }
      }
    }
    ts.forEachChild(n, walk2);
  };
  walk2(sf);

  // ---- pass 3: ESM imports / exports ----
  for (const st of sf.statements) {
    if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier) && st.importClause) {
      const bindings: ImportRef['bindings'] = [];
      const ic = st.importClause;
      if (ic.name) bindings.push({ local: ic.name.text, imported: 'default' });
      if (ic.namedBindings) {
        if (ts.isNamespaceImport(ic.namedBindings)) bindings.push({ local: ic.namedBindings.name.text, imported: '*' });
        else for (const el of ic.namedBindings.elements) bindings.push({ local: el.name.text, imported: (el.propertyName ?? el.name).text });
      }
      facts.imports.push({ specifier: st.moduleSpecifier.text, bindings });
      continue;
    }
    const mods = ts.canHaveModifiers(st) ? ts.getModifiers(st) : undefined;
    const isExport = mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    const isDefault = mods?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword);
    if (isExport && ts.isFunctionDeclaration(st) && st.name) {
      addPublic(isDefault ? 'default' : st.name.text, st.name.text);
      if (isDefault) facts.defaultIsFunction = true;
    } else if (isExport && ts.isClassDeclaration(st) && st.name) {
      addPublic(isDefault ? 'default' : st.name.text, st.name.text);
    } else if (isExport && ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name)) addPublic(d.name.text, d.name.text);
    } else if (ts.isExportAssignment(st) && !st.isExportEquals) {
      const v = valueName(st.expression);
      if (v) addPublic('default', v);
      if (isFunctionLike(st.expression)) facts.defaultIsFunction = true;
    } else if (ts.isExportDeclaration(st)) {
      const spec = st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier) ? st.moduleSpecifier.text : undefined;
      if (spec) {
        if (!st.exportClause) facts.reexports.push({ specifier: spec, names: 'all' });
        else if (ts.isNamedExports(st.exportClause)) facts.reexports.push({ specifier: spec, names: st.exportClause.elements.map((el) => ({ exported: el.name.text, imported: (el.propertyName ?? el.name).text })) });
        else if (ts.isNamespaceExport(st.exportClause)) facts.reexports.push({ specifier: spec, names: [{ exported: st.exportClause.name.text, imported: '*' }] });
      } else if (st.exportClause && ts.isNamedExports(st.exportClause)) {
        for (const el of st.exportClause.elements) addPublic(el.name.text, (el.propertyName ?? el.name).text);
      }
    }
  }
  return facts;
}

/** Innermost named function containing a line, if any. */
export function enclosing(facts: FileFacts, lineNo: number): FnRange | undefined {
  return enclosingAll(facts, lineNo)[0];
}

/** Every function containing a line, innermost first. */
export function enclosingAll(facts: FileFacts, lineNo: number): FnRange[] {
  return facts.functions.filter((f) => lineNo >= f.startLine && lineNo <= f.endLine).sort((a, b) => a.endLine - a.startLine - (b.endLine - b.startLine));
}

/** Top-level declaration (variable, class, function) containing a line. */
export function enclosingTopLevel(facts: FileFacts, lineNo: number): FileFacts['topLevel'][number] | undefined {
  return facts.topLevel.find((t) => lineNo >= t.startLine && lineNo <= t.endLine);
}

/**
 * Local names in this file that reach any of `seeds` (functions that call or reference them,
 * methods' classes, transitively up to `depth` hops), including the seeds themselves.
 */
export function reachingLocals(facts: FileFacts, seeds: Iterable<string>, depth = 4): Set<string> {
  const out = new Set<string>(seeds);
  const classOf = new Map<string, string>();
  for (const f of facts.functions) if (f.className) classOf.set(f.name, f.className);
  // callers[x] = functions whose calls or refs include x
  const callers = new Map<string, Set<string>>();
  const add = (x: string, by: string) => (callers.get(x) ?? callers.set(x, new Set()).get(x)!).add(by);
  for (const [fn, callees] of facts.calls) for (const c of callees) add(c, fn);
  for (const [fn, ids] of facts.refs) for (const c of ids) add(c, fn);
  for (const [v, ids] of facts.varRefs) for (const c of ids) add(c, v);
  let frontier = [...out];
  for (let d = 0; d < depth && frontier.length; d++) {
    const next: string[] = [];
    for (const name of frontier) {
      for (const by of callers.get(name) ?? []) {
        if (!out.has(by)) {
          out.add(by);
          next.push(by);
        }
        const cls = classOf.get(by);
        if (cls && !out.has(cls)) {
          out.add(cls);
          next.push(cls);
        }
      }
      const cls = classOf.get(name);
      if (cls && !out.has(cls)) {
        out.add(cls);
        next.push(cls);
      }
    }
    frontier = next;
  }
  return out;
}

/** Public names of this file whose local target is in `locals` (plus `obj.x = fn` assignments). */
export function publicNamesFor(facts: FileFacts, locals: Set<string>): Map<string, string> {
  const out = new Map<string, string>();
  for (const [pub, local] of facts.publicByName) if (locals.has(local)) out.set(pub, local);
  for (const local of locals) for (const pub of facts.publicByFn.get(local) ?? []) if (!out.has(pub)) out.set(pub, local);
  for (const f of facts.functions) if (f.assignedTo && locals.has(f.name) && !out.has(f.assignedTo)) out.set(f.assignedTo, f.name);
  return out;
}

/**
 * Public symbols through which a changed function is reachable within its own file: itself
 * when public, plus public callers (one hop when the function is public, `maxDepth` otherwise).
 */
export function resolvePublic(facts: FileFacts, fn: FnRange, maxDepth = 3): Map<string, string> {
  const out = new Map<string, string>();
  const direct = facts.publicByFn.get(fn.name);
  if (direct) for (const p of direct) out.set(p, 'direct');
  if (fn.assignedTo && !facts.publicByName.has(fn.assignedTo)) out.set(fn.assignedTo, 'direct');
  if (fn.className) for (const p of facts.publicByFn.get(fn.className) ?? []) if (!out.has(p)) out.set(p, `class:${fn.className}`);
  const depth = out.size ? 1 : maxDepth;

  const callers = new Map<string, string[]>();
  for (const [caller, callees] of facts.calls) for (const c of callees) (callers.get(c) ?? callers.set(c, []).get(c)!).push(caller);
  const seen = new Set<string>([fn.name]);
  let frontier = [fn.name];
  for (let d = 0; d < depth && frontier.length; d++) {
    const next: string[] = [];
    for (const name of frontier) {
      for (const caller of callers.get(name) ?? []) {
        if (seen.has(caller)) continue;
        seen.add(caller);
        const pubs = facts.publicByFn.get(caller);
        if (pubs) {
          for (const p of pubs) if (!out.has(p)) out.set(p, `caller:${caller}`);
        } else {
          next.push(caller);
        }
      }
    }
    frontier = next;
  }
  return out;
}
