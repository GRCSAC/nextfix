import type { ProjectGraph } from '../graph/js/project.ts';
import type { CallSite } from '../graph/js/analyze.ts';
import type { CallSiteRef, Component, PathHop, ReachPath, ReachResult, SymbolEntry } from '../types.ts';

const REQ = new Set(['req', 'request']);

function matches(c: CallSite, pkg: string, entry: SymbolEntry): string | undefined {
  const t = c.target;
  if (t.kind === 'external' && t.package === pkg && !entry.receiver) {
    if (entry.symbols.includes(t.symbol)) return t.symbol;
    // Calling the package itself (`marked(src)`) reaches an export named after the package
    // (`export function marked`) or its `default`.
    const base = pkg.replace(/^@[^/]+\//, '');
    if (t.symbol === 'default' && entry.symbols.includes(base)) return base;
    if (t.symbol === base && entry.symbols.includes('default')) return 'default';
    return undefined;
  }
  if (t.kind === 'framework' && t.package === pkg && entry.receiver === t.receiver) {
    return entry.symbols.includes(t.symbol) ? t.symbol : undefined;
  }
  return undefined;
}

interface Sink extends CallSiteRef {
  site: CallSite;
}

/** Decides how reachable one advisory on one component is, with the evidence. */
export function assessReach(graph: ProjectGraph, component: Component, symbols: SymbolEntry | undefined): ReachResult {
  const importedIn = [...(graph.packagesImported.get(component.name) ?? [])].sort();
  const base: ReachResult = { tier: 'unused', confidence: 'package-level', importedIn, callSites: [], paths: [] };

  if (component.dev) return { ...base, tier: 'dev-only' };
  if (!importedIn.length) return { ...base, tier: 'unused' };
  if (!symbols) return { ...base, tier: 'imported-unknown-symbol' };

  // All call sites into the vulnerable symbols, by function.
  const sitesByFn = new Map<string, Sink[]>();
  const callSites: CallSiteRef[] = [];
  for (const fn of graph.functions.values()) {
    for (const c of fn.calls) {
      const sym = matches(c, component.name, symbols);
      if (!sym) continue;
      const ref: Sink = { file: fn.file, line: c.line, col: c.col, text: c.text, symbol: sym, userInput: c.userInput, site: c };
      callSites.push({ file: ref.file, line: ref.line, col: ref.col, text: ref.text, symbol: ref.symbol, userInput: ref.userInput });
      (sitesByFn.get(fn.id) ?? sitesByFn.set(fn.id, []).get(fn.id)!).push(ref);
    }
  }
  const result: ReachResult = { ...base, confidence: symbols.confidence, callSites };
  if (!callSites.length) return { ...result, tier: 'imported-not-called' };

  // One path per entry point: a request-data-carrying path if one exists, else any path.
  const paths: ReachPath[] = [];
  for (const entry of graph.entryPoints) {
    let found: Omit<ReachPath, 'entry'> | undefined;
    for (const requireTaint of [true, false]) {
      for (const start of entry.handlerIds) {
        found = findPath(graph, start, sitesByFn, requireTaint);
        if (found) break;
      }
      if (found) break;
    }
    if (found) paths.push({ entry, ...found });
  }
  if (!paths.length) return { ...result, tier: 'called-unreached' };
  return { ...result, tier: 'reachable', paths };
}

interface State {
  id: string;
  trail: string[];
  /** names in the current function that carry request data */
  tainted: Set<string>;
  /** first hop index where request data was passed along, or -1 */
  inputAt: number;
  inputSource?: string;
}

/** Parameters of a function that carry request data by name (`req`, `request`). */
function reqParams(graph: ProjectGraph, id: string): Set<string> {
  const fn = graph.functions.get(id);
  const out = new Set<string>();
  for (const p of fn?.params ?? []) if (REQ.has(p)) out.add(p);
  return out;
}

function argIsTainted(roots: string[], tainted: Set<string>): boolean {
  return roots.some((r) => tainted.has(r) || REQ.has(r));
}

function findPath(graph: ProjectGraph, start: string, sitesByFn: Map<string, Sink[]>, requireTaint: boolean): Omit<ReachPath, 'entry'> | undefined {
  const seen = new Set<string>();
  const startTaint = reqParams(graph, start);
  const stack: State[] = [{ id: start, trail: [start], tainted: startTaint, inputAt: -1 }];
  while (stack.length) {
    const st = stack.pop()!;
    const key = requireTaint ? `${st.id}|${[...st.tainted].sort().join(',')}` : st.id;
    if (seen.has(key)) continue;
    seen.add(key);

    const sinks = sitesByFn.get(st.id);
    if (sinks?.length) {
      for (const sink of sinks) {
        const idx = sink.site.args.findIndex((a) => argIsTainted(a.roots, st.tainted));
        const tainted = idx >= 0;
        if (requireTaint && !tainted) continue;
        const hops = st.trail.map(hop(graph));
        const entered = st.inputAt >= 0 ? hops[st.inputAt] : undefined;
        const direct = tainted && sink.site.args[idx]!.roots.some((r) => REQ.has(r));
        return {
          hops,
          callSite: { file: sink.file, line: sink.line, col: sink.col, text: sink.text, symbol: sink.symbol, userInput: direct },
          userInput: tainted,
          inputEntersAt: tainted && !direct && entered ? { file: entered.file, line: entered.line, name: entered.name } : undefined,
          inputSource: tainted ? (direct ? sink.site.args[idx]!.text : st.inputSource) : undefined,
          taintedArgument: tainted ? { index: idx, text: sink.site.args[idx]!.text } : undefined,
        };
      }
      if (!requireTaint) continue;
    }

    const sites = graph.edgeSites.get(st.id);
    for (const next of graph.edges.get(st.id) ?? []) {
      const callee = graph.functions.get(next);
      const nextTaint = reqParams(graph, next);
      let carried = false;
      let source: string | undefined;
      const realised = sites?.get(next);
      if (realised) {
        // Call edge: callee parameters at tainted argument positions become tainted.
        for (const c of realised) {
          c.args.forEach((a, i) => {
            if (!argIsTainted(a.roots, st.tainted)) return;
            const p = callee?.params[i];
            if (p && p !== '<pattern>') nextTaint.add(p);
            carried = true;
            source ??= a.text;
          });
        }
      } else {
        // Containment edge (callback or returned closure): captured names stay tainted.
        for (const t of st.tainted) if (!callee?.params.includes(t)) nextTaint.add(t);
      }
      stack.push({
        id: next,
        trail: [...st.trail, next],
        tainted: nextTaint,
        inputAt: st.inputAt >= 0 ? st.inputAt : carried ? st.trail.length - 1 : -1,
        inputSource: st.inputSource ?? (carried ? source : undefined),
      });
    }
  }
  return undefined;
}

function hop(graph: ProjectGraph) {
  return (id: string): PathHop => {
    const fn = graph.functions.get(id);
    return fn ? { functionId: id, name: fn.name, file: fn.file, line: fn.line } : { functionId: id, name: id, file: '', line: 0 };
  };
}
