import type { ProjectGraph } from './js/project.ts';

/** Combines per-language graphs of one project into one (ids never collide: they carry file paths). */
export function mergeGraphs(a: ProjectGraph, b: ProjectGraph): ProjectGraph {
  const mergeSetMap = (x: Map<string, Set<string>>, y: Map<string, Set<string>>) => {
    const out = new Map(x);
    for (const [k, v] of y) out.set(k, new Set([...(out.get(k) ?? []), ...v]));
    return out;
  };
  const edgeSites = new Map(a.edgeSites);
  for (const [k, v] of b.edgeSites) edgeSites.set(k, new Map([...(edgeSites.get(k) ?? []), ...v]));
  return {
    rootDir: a.rootDir,
    modules: new Map([...a.modules, ...b.modules]),
    functions: new Map([...a.functions, ...b.functions]),
    edges: mergeSetMap(a.edges, b.edges),
    edgeInput: mergeSetMap(a.edgeInput, b.edgeInput),
    edgeSites,
    entryPoints: [...a.entryPoints, ...b.entryPoints],
    packagesImported: mergeSetMap(a.packagesImported, b.packagesImported),
    rootApps: [...a.rootApps, ...b.rootApps],
    listenLocalOnly: a.listenLocalOnly && b.listenLocalOnly,
  };
}
