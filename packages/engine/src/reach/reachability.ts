import type { ProjectGraph } from '../graph/js/project.ts';
import type { CallSite } from '../graph/js/analyze.ts';
import type { CallSiteRef, Component, PathHop, ReachPath, ReachResult, SymbolEntry } from '../types.ts';

function matches(c: CallSite, pkg: string, entry: SymbolEntry): string | undefined {
  const t = c.target;
  if (t.kind === 'external' && t.package === pkg && !entry.receiver) {
    return entry.symbols.includes(t.symbol) ? t.symbol : undefined;
  }
  if (t.kind === 'framework' && t.package === pkg && entry.receiver === t.receiver) {
    return entry.symbols.includes(t.symbol) ? t.symbol : undefined;
  }
  return undefined;
}

/** Decides how reachable one advisory on one component is, with the evidence. */
export function assessReach(graph: ProjectGraph, component: Component, symbols: SymbolEntry | undefined): ReachResult {
  const importedIn = [...(graph.packagesImported.get(component.name) ?? [])].sort();
  const base: ReachResult = { tier: 'unused', confidence: 'package-level', importedIn, callSites: [], paths: [] };

  if (component.dev) return { ...base, tier: 'dev-only' };
  if (!importedIn.length) return { ...base, tier: 'unused' };
  if (!symbols) return { ...base, tier: 'imported-unknown-symbol' };

  // All call sites into the vulnerable symbols, by function.
  const sitesByFn = new Map<string, CallSiteRef[]>();
  const callSites: CallSiteRef[] = [];
  for (const fn of graph.functions.values()) {
    for (const c of fn.calls) {
      const sym = matches(c, component.name, symbols);
      if (!sym) continue;
      const ref: CallSiteRef = { file: fn.file, line: c.line, col: c.col, text: c.text, symbol: sym, userInput: c.userInput };
      callSites.push(ref);
      const list = sitesByFn.get(fn.id) ?? [];
      list.push(ref);
      sitesByFn.set(fn.id, list);
    }
  }
  const result: ReachResult = { ...base, confidence: symbols.confidence, callSites };
  if (!callSites.length) return { ...result, tier: 'imported-not-called' };

  // Depth-first from each entry handler, keeping the first path found per entry.
  const paths: ReachPath[] = [];
  for (const entry of graph.entryPoints) {
    for (const start of entry.handlerIds) {
      const found = findPath(graph, start, sitesByFn);
      if (found) {
        paths.push({ entry, ...found });
        break;
      }
    }
  }
  if (!paths.length) return { ...result, tier: 'called-unreached' };
  return { ...result, tier: 'reachable', paths };
}

interface Trail {
  id: string;
  trail: string[];
  /** index into trail of the hop whose call first carried request data, or -1 */
  inputAt: number;
}

function findPath(graph: ProjectGraph, start: string, sitesByFn: Map<string, CallSiteRef[]>): Omit<ReachPath, 'entry'> | undefined {
  const seen = new Set<string>();
  const stack: Trail[] = [{ id: start, trail: [start], inputAt: -1 }];
  while (stack.length) {
    const { id, trail, inputAt } = stack.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const sites = sitesByFn.get(id);
    if (sites?.length) {
      const site = sites.find((s) => s.userInput) ?? sites[0]!;
      const hops = trail.map(hop(graph));
      const entered = inputAt >= 0 ? hops[inputAt] : undefined;
      return {
        hops,
        callSite: site,
        userInput: site.userInput || inputAt >= 0,
        inputEntersAt: !site.userInput && entered ? { file: entered.file, line: entered.line, name: entered.name } : undefined,
      };
    }
    const inputs = graph.edgeInput.get(id);
    for (const next of graph.edges.get(id) ?? []) {
      if (seen.has(next)) continue;
      const carries = inputAt >= 0 ? inputAt : inputs?.has(next) ? trail.length - 1 : -1;
      stack.push({ id: next, trail: [...trail, next], inputAt: carries });
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
