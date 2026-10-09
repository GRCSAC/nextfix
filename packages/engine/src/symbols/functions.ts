import ts from 'typescript';

export interface FnRange {
  /** Name as written in source; synthetic for anonymous functions assigned to a property. */
  name: string;
  startLine: number;
  endLine: number;
  /** Property this function was assigned to (e.g. `res.redirect = function redirect`). */
  assignedTo?: string;
}

export interface FileFacts {
  functions: FnRange[];
  /** public name -> function name (or '*' when unknown) */
  publicByName: Map<string, string>;
  /** function name -> public names it is reachable as */
  publicByFn: Map<string, Set<string>>;
  /** function name -> identifiers it calls */
  calls: Map<string, Set<string>>;
  /** `module.exports = function` or `export default function`: the package is one callable. */
  defaultIsFunction: boolean;
}

function isFunctionLike(n: ts.Node): n is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n);
}

function propName(n: ts.PropertyName | ts.MemberName): string | undefined {
  if (ts.isIdentifier(n) || ts.isStringLiteral(n) || ts.isNumericLiteral(n) || ts.isPrivateIdentifier(n)) return n.text;
  return undefined;
}

/** Parses one source file and records function ranges, public surface, and the intra-file call graph. */
export function analyzeFile(text: string, fileName = 'file.js'): FileFacts {
  const kind = /\.tsx?$/.test(fileName) ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind);
  const line = (pos: number) => sf.getLineAndCharacterOfPosition(pos).line + 1;
  const facts: FileFacts = { functions: [], publicByName: new Map(), publicByFn: new Map(), calls: new Map(), defaultIsFunction: false };
  const byNode = new Map<ts.Node, FnRange>();

  function nameFor(n: ts.FunctionLikeDeclaration): { name: string; assignedTo?: string } {
    if (n.name && (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name))) {
      const assigned = assignedProp(n.parent);
      return { name: n.name.text, assignedTo: assigned };
    }
    const p = n.parent;
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
  function assignedProp(p: ts.Node | undefined): string | undefined {
    if (!p || !ts.isBinaryExpression(p) || p.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return undefined;
    const lhs = p.left.getText(sf).replace(/\s+/g, '');
    if (lhs === 'module.exports' || lhs === 'exports') return undefined;
    if (ts.isPropertyAccessExpression(p.left)) return p.left.name.text;
    if (ts.isElementAccessExpression(p.left) && ts.isStringLiteral(p.left.argumentExpression)) return p.left.argumentExpression.text;
    return undefined;
  }

  const walk = (n: ts.Node) => {
    if (isFunctionLike(n) && n.body) {
      const { name, assignedTo } = nameFor(n);
      const r: FnRange = { name, startLine: line(n.getStart(sf)), endLine: line(n.getEnd()), assignedTo };
      facts.functions.push(r);
      byNode.set(n, r);
    }
    ts.forEachChild(n, walk);
  };
  walk(sf);

  function enclosingFn(n: ts.Node): FnRange | undefined {
    let cur: ts.Node | undefined = n.parent;
    while (cur) {
      const f = byNode.get(cur);
      if (f) return f;
      cur = cur.parent;
    }
    return undefined;
  }
  function addPublic(pub: string, fn: string) {
    facts.publicByName.set(pub, fn);
    const set = facts.publicByFn.get(fn) ?? new Set();
    set.add(pub);
    facts.publicByFn.set(fn, set);
  }
  function valueName(e: ts.Expression): string | undefined {
    if (ts.isIdentifier(e)) return e.text;
    if (isFunctionLike(e)) return byNode.get(e)?.name;
    return undefined;
  }

  const walk2 = (n: ts.Node) => {
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
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const lhs = n.left.getText(sf).replace(/\s+/g, '');
      if (lhs === 'module.exports' || lhs === 'exports') {
        if (isFunctionLike(n.right)) {
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
          }
        }
      } else if (ts.isPropertyAccessExpression(n.left) || (ts.isElementAccessExpression(n.left) && ts.isStringLiteral(n.left.argumentExpression))) {
        // `exports.x = f`, `module.exports.x = f`, `lodash.template = template`, `res.redirect = function redirect`, `Proto.prototype.x = f`
        const pub = ts.isPropertyAccessExpression(n.left) ? n.left.name.text : (n.left.argumentExpression as ts.StringLiteral).text;
        const v = valueName(n.right);
        if (v && pub !== 'exports') addPublic(pub, v);
      }
    }
    ts.forEachChild(n, walk2);
  };
  walk2(sf);

  for (const st of sf.statements) {
    const mods = ts.canHaveModifiers(st) ? ts.getModifiers(st) : undefined;
    const isExport = mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    const isDefault = mods?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword);
    if (isExport && ts.isFunctionDeclaration(st) && st.name) {
      addPublic(isDefault ? 'default' : st.name.text, st.name.text);
      if (isDefault) facts.defaultIsFunction = true;
    } else if (isExport && ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name)) addPublic(d.name.text, d.name.text);
    } else if (ts.isExportAssignment(st) && !st.isExportEquals) {
      const v = valueName(st.expression);
      if (v) addPublic('default', v);
      if (isFunctionLike(st.expression)) facts.defaultIsFunction = true;
    } else if (ts.isExportDeclaration(st) && st.exportClause && ts.isNamedExports(st.exportClause) && !st.moduleSpecifier) {
      for (const el of st.exportClause.elements) addPublic(el.name.text, (el.propertyName ?? el.name).text);
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

/**
 * Public symbols through which a changed function is reachable: itself when public, plus
 * public callers up to `depth` hops away within the same file (a public function that calls
 * a changed public function reaches the vulnerable code too).
 */
export function resolvePublic(facts: FileFacts, fn: FnRange, maxDepth = 3): Map<string, string> {
  const out = new Map<string, string>();
  const direct = facts.publicByFn.get(fn.name);
  if (direct) for (const p of direct) out.set(p, 'direct');
  if (fn.assignedTo && !facts.publicByName.has(fn.assignedTo)) out.set(fn.assignedTo, 'direct');
  // A public function that changed: only its immediate public callers are added. An internal
  // function: search up to maxDepth hops for the public surface that reaches it.
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
