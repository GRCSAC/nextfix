import { parsePython, stringValue, walk, type Node } from '../graph/py/parser.ts';
import type { FileFacts, FnRange } from './functions.ts';

/**
 * Python counterpart of analyzeFile(): function ranges, public surface (top-level defs,
 * classes and assignments, narrowed by __all__), imports / re-exports, and who references what.
 */
export async function analyzePyFile(text: string, fileName = 'module.py'): Promise<FileFacts> {
  const tree = await parsePython(text);
  const root = tree.rootNode;
  const facts: FileFacts = { functions: [], publicByName: new Map(), publicByFn: new Map(), calls: new Map(), refs: new Map(), moduleRefs: new Set(), varRefs: new Map(), topLevel: [], imports: [], reexports: [], defaultIsFunction: false };
  const isInit = /(^|\/)__init__\.py$/.test(fileName);
  const line = (n: Node) => n.startPosition.row + 1;
  const endLine = (n: Node) => n.endPosition.row + 1;
  const fnByNodeId = new Map<number, FnRange>();
  let allNames: Set<string> | undefined;

  const addPublic = (pub: string, local: string) => {
    facts.publicByName.set(pub, local);
    const set = facts.publicByFn.get(local) ?? new Set();
    set.add(pub);
    facts.publicByFn.set(local, set);
  };

  // ---- definitions ----
  const classStack: string[] = [];
  const fnStack: FnRange[] = [];
  const visit = (n: Node) => {
    if (n.type === 'decorated_definition') {
      const def = n.childForFieldName('definition');
      if (def) visit(def);
      return;
    }
    if (n.type === 'function_definition') {
      const name = n.childForFieldName('name')?.text ?? '<anon>';
      const r: FnRange = { name, startLine: line(n), endLine: endLine(n), className: classStack[classStack.length - 1] };
      facts.functions.push(r);
      fnByNodeId.set(n.id, r);
      if (!fnStack.length && !classStack.length) facts.topLevel.push({ name, startLine: r.startLine, endLine: r.endLine, kind: 'function' });
      fnStack.push(r);
      for (const c of n.childForFieldName('body')?.namedChildren ?? []) visit(c);
      fnStack.pop();
      return;
    }
    if (n.type === 'lambda') {
      const r: FnRange = { name: `<lambda@${line(n)}>`, startLine: line(n), endLine: endLine(n), className: classStack[classStack.length - 1] };
      facts.functions.push(r);
      fnByNodeId.set(n.id, r);
      return;
    }
    if (n.type === 'class_definition') {
      const name = n.childForFieldName('name')?.text ?? '<class>';
      if (!fnStack.length && !classStack.length) {
        facts.topLevel.push({ name, startLine: line(n), endLine: endLine(n), kind: 'class' });
        // a class "references" its bases: a changed base class taints the subclass
        const bases = (n.childForFieldName('superclasses')?.namedChildren ?? []).map((b) => b.text.split('.').pop()!).filter(Boolean);
        if (bases.length) facts.varRefs.set(name, new Set([...(facts.varRefs.get(name) ?? []), ...bases]));
      }
      classStack.push(name);
      for (const c of n.childForFieldName('body')?.namedChildren ?? []) visit(c);
      classStack.pop();
      return;
    }
    if (n.type === 'expression_statement' && !fnStack.length && !classStack.length) {
      const a = n.namedChildren[0];
      if (a?.type === 'assignment') {
        const left = a.childForFieldName('left');
        const right = a.childForFieldName('right');
        const targets = left?.type === 'identifier' ? [left.text] : (left?.namedChildren ?? []).filter((c) => c.type === 'identifier').map((c) => c.text);
        for (const t of targets) {
          if (t === '__all__' && right) {
            allNames = new Set((right.namedChildren ?? []).map((c) => stringValue(c)).filter((x): x is string => !!x));
            continue;
          }
          facts.topLevel.push({ name: t, startLine: line(n), endLine: endLine(n), kind: 'var' });
          if (right) {
            const ids = new Set<string>();
            baseIds(right, ids);
            if (ids.size) facts.varRefs.set(t, new Set([...(facts.varRefs.get(t) ?? []), ...ids]));
            // alias: `safe_load = load` style
            if (right.type === 'identifier') facts.publicByName.set(t, right.text);
          }
        }
      }
    }
    for (const c of n.namedChildren) visit(c);
  };
  function baseIds(n: Node, out: Set<string>) {
    if (n.type === 'identifier') {
      out.add(n.text);
      return;
    }
    if (n.type === 'attribute') {
      baseIds(n.childForFieldName('object')!, out);
      out.add(n.childForFieldName('attribute')?.text ?? '');
      return;
    }
    if (n.type === 'function_definition' || n.type === 'lambda' || n.type === 'class_definition') return;
    for (const c of n.namedChildren) baseIds(c, out);
  }
  visit(root);

  // ---- public surface ----
  for (const t of facts.topLevel) {
    if (t.name.startsWith('_') && t.name !== '__all__') continue;
    if (allNames && !allNames.has(t.name)) continue;
    if (!facts.publicByName.has(t.name)) addPublic(t.name, t.name);
    else {
      const set = facts.publicByFn.get(facts.publicByName.get(t.name)!) ?? new Set();
      set.add(t.name);
      facts.publicByFn.set(facts.publicByName.get(t.name)!, set);
    }
  }

  // ---- imports and re-exports ----
  walk(root, (n) => {
    if (n.type === 'import_statement') {
      for (const c of n.namedChildren) {
        if (c.type === 'dotted_name') facts.imports.push({ specifier: c.text, bindings: [{ local: c.text.split('.')[0]!, imported: '*' }] });
        else if (c.type === 'aliased_import') {
          const name = c.childForFieldName('name')?.text ?? '';
          const alias = c.childForFieldName('alias')?.text ?? name;
          facts.imports.push({ specifier: name, bindings: [{ local: alias, imported: '*' }] });
        }
      }
      return false;
    }
    if (n.type === 'import_from_statement') {
      const modName = n.childForFieldName('module_name')?.text ?? '';
      const names = n.namedChildren.filter((c) => c !== n.childForFieldName('module_name'));
      const bindings: { local: string; imported: string }[] = [];
      let star = false;
      if (/import\s+\*/.test(n.text)) star = true;
      for (const c of names) {
        if (c.type === 'dotted_name') bindings.push({ local: c.text, imported: c.text });
        else if (c.type === 'aliased_import') {
          const name = c.childForFieldName('name')?.text ?? '';
          bindings.push({ local: c.childForFieldName('alias')?.text ?? name, imported: name });
        }
      }
      if (star) facts.imports.push({ specifier: modName, bindings: [{ local: '*', imported: '*' }] });
      else facts.imports.push({ specifier: modName, bindings });
      // In a package __init__, `from .x import y` publishes y (and `*` publishes everything).
      if (isInit) {
        if (star) facts.reexports.push({ specifier: modName, names: 'all' });
        else if (bindings.length) {
          facts.reexports.push({ specifier: modName, names: bindings.filter((b) => allNames ? allNames.has(b.local) : !b.local.startsWith('_')).map((b) => ({ exported: b.local, imported: b.imported })) });
        }
      }
      return false;
    }
    return true;
  });

  // ---- calls and references per function ----
  function enclosingFn(n: Node): FnRange | undefined {
    let cur = n.parent;
    while (cur) {
      const f = fnByNodeId.get(cur.id);
      if (f) return f;
      cur = cur.parent;
    }
    return undefined;
  }
  function enclosingTopVar(n: Node): string | undefined {
    let cur = n.parent;
    while (cur) {
      if (cur.type === 'class_definition' && cur.parent?.type === 'module') return cur.childForFieldName('name')?.text;
      if (cur.type === 'assignment' && cur.parent?.type === 'expression_statement' && cur.parent.parent?.type === 'module') {
        const left = cur.childForFieldName('left');
        return left?.type === 'identifier' ? left.text : undefined;
      }
      cur = cur.parent;
    }
    return undefined;
  }
  walk(root, (n) => {
    if (n.type === 'identifier' && !(n.parent?.type === 'attribute' && n.parent.childForFieldName('attribute')?.id === n.id) && !(n.parent?.type === 'keyword_argument' && n.parent.childForFieldName('name')?.id === n.id)) {
      const fn = enclosingFn(n);
      if (fn) (facts.refs.get(fn.name) ?? facts.refs.set(fn.name, new Set()).get(fn.name)!).add(n.text);
      else {
        facts.moduleRefs.add(n.text);
        const v = enclosingTopVar(n);
        if (v && v !== n.text) (facts.varRefs.get(v) ?? facts.varRefs.set(v, new Set()).get(v)!).add(n.text);
      }
    }
    if (n.type === 'call') {
      const fn = enclosingFn(n);
      if (fn) {
        const callee = n.childForFieldName('function');
        const id = callee?.type === 'identifier' ? callee.text : callee?.type === 'attribute' ? callee.childForFieldName('attribute')?.text : undefined;
        const set = facts.calls.get(fn.name) ?? new Set();
        if (id) set.add(id);
        for (const a of n.childForFieldName('arguments')?.namedChildren ?? []) {
          const v = a.type === 'keyword_argument' ? a.childForFieldName('value') : a;
          if (v?.type === 'identifier') set.add(v.text);
        }
        if (set.size) facts.calls.set(fn.name, set);
      }
    }
    return true;
  });
  return facts;
}
