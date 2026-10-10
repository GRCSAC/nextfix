import type { FunctionInfo, ProjectGraph } from '../graph/js/project.ts';
import { REQ_NAMES as REQ, type CallSite } from '../graph/js/analyze.ts';
import type { CallSiteRef, Component, PathHop, ReachPath, ReachResult, SymbolEntry } from '../types.ts';

function matches(c: CallSite, pkg: string, entry: SymbolEntry): string | undefined {
  const t = c.target;
  if (t.kind === 'external' && t.package === pkg && !entry.receiver) {
    if (entry.symbols.includes(t.symbol)) return t.symbol;
    // A sub-path import answers to both spellings (`map` and `fp.map` for lodash/fp).
    const alt = t.altSymbols?.find((s) => entry.symbols.includes(s));
    if (alt) return alt;
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

/** Indexes over one graph that every finding of a scan shares; built on first use. */
interface GraphIndex {
  /** package name -> function id -> that function's call sites into the package, in source order */
  byPackage: Map<string, Map<string, CallSite[]>>;
  /** callee id -> caller ids, over call edges and containment edges alike */
  callers: Map<string, string[]>;
}

const INDEXES = new WeakMap<ProjectGraph, GraphIndex>();

function indexOf(graph: ProjectGraph): GraphIndex {
  let idx = INDEXES.get(graph);
  if (idx) return idx;
  const byPackage = new Map<string, Map<string, CallSite[]>>();
  for (const fn of graph.functions.values()) {
    for (const c of fn.calls) {
      const t = c.target;
      if (t.kind !== 'external' && t.kind !== 'framework') continue;
      const perFn = byPackage.get(t.package) ?? byPackage.set(t.package, new Map()).get(t.package)!;
      (perFn.get(fn.id) ?? perFn.set(fn.id, []).get(fn.id)!).push(c);
    }
  }
  const callers = new Map<string, string[]>();
  for (const [from, tos] of graph.edges) {
    for (const to of tos) (callers.get(to) ?? callers.set(to, []).get(to)!).push(from);
  }
  idx = { byPackage, callers };
  INDEXES.set(graph, idx);
  return idx;
}

/** Upper bound on (function, tainted names) states explored per finding; beyond it the search reports what it has. */
const MAX_STATES = 200_000;

/** Decides how reachable one advisory on one component is, with the evidence. */
export function assessReach(graph: ProjectGraph, component: Component, symbols: SymbolEntry | undefined): ReachResult {
  const importedIn = [...(graph.packagesImported.get(component.name) ?? [])].sort();
  const base: ReachResult = { tier: 'unused', confidence: 'package-level', importedIn, callSites: [], paths: [] };

  if (component.dev) return { ...base, tier: 'dev-only' };
  if (!importedIn.length) return { ...base, tier: 'unused' };
  if (!symbols) return { ...base, tier: 'imported-unknown-symbol' };

  // All call sites into the vulnerable symbols, by function.
  const index = indexOf(graph);
  const sitesByFn = new Map<string, Sink[]>();
  const callSites: CallSiteRef[] = [];
  for (const [fnId, calls] of index.byPackage.get(component.name) ?? []) {
    const fn = graph.functions.get(fnId)!;
    for (const c of calls) {
      const sym = matches(c, component.name, symbols);
      if (!sym) continue;
      const ref: Sink = { file: fn.file, line: c.line, col: c.col, text: c.text, symbol: sym, userInput: c.userInput, site: c };
      callSites.push({ file: ref.file, line: ref.line, col: ref.col, text: ref.text, symbol: ref.symbol, userInput: ref.userInput });
      (sitesByFn.get(fn.id) ?? sitesByFn.set(fn.id, []).get(fn.id)!).push(ref);
    }
  }
  const result: ReachResult = { ...base, confidence: symbols.confidence, callSites };
  if (!callSites.length) return { ...result, tier: 'imported-not-called' };

  // Which functions can reach a vulnerable call at all, and the next hop toward the nearest one.
  const toward = towardSinks(index, sitesByFn);
  const starts: string[] = [];
  for (const entry of graph.entryPoints) for (const h of entry.handlerIds) if (toward.has(h) && !starts.includes(h)) starts.push(h);
  const taint = new TaintSearch(graph, sitesByFn, toward, starts);

  // One path per entry point: a request-data-carrying path if one exists, else any path.
  const paths: ReachPath[] = [];
  for (const entry of graph.entryPoints) {
    const handlers = entry.handlerIds.filter((h) => toward.has(h));
    let found: Omit<ReachPath, 'entry'> | undefined;
    for (const start of handlers) {
      found = taint.taintedPath(start);
      if (found) break;
    }
    if (!found) {
      for (const start of handlers) {
        found = taint.anyPath(start);
        if (found) break;
      }
    }
    if (found) paths.push({ entry, ...found });
  }
  if (!paths.length) return { ...result, tier: 'called-unreached' };
  return { ...result, tier: 'reachable', paths };
}

/**
 * Walks backwards from the functions holding a vulnerable call. For every function that can reach
 * one, the next hop on a shortest path there (undefined at the vulnerable call itself).
 */
function towardSinks(index: GraphIndex, sitesByFn: Map<string, Sink[]>): Map<string, string | undefined> {
  const next = new Map<string, string | undefined>();
  const queue: string[] = [];
  for (const id of sitesByFn.keys()) {
    next.set(id, undefined);
    queue.push(id);
  }
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i]!;
    for (const caller of index.callers.get(id) ?? []) {
      if (next.has(caller)) continue;
      next.set(caller, id);
      queue.push(caller);
    }
  }
  return next;
}

/** Parameters of a function that carry request data by name (`req`, `request`). */
function reqParams(graph: ProjectGraph, id: string): Set<string> {
  const fn = graph.functions.get(id);
  const out = new Set<string>();
  for (const p of fn?.params ?? []) if (REQ.has(p)) out.add(p);
  for (const p of fn?.inputParams ?? []) out.add(p);
  return out;
}

function argIsTainted(roots: string[], tainted: Set<string>): boolean {
  return roots.some((r) => tainted.has(r) || REQ.has(r));
}

interface Step {
  /** names in the callee that carry request data */
  tainted: Set<string>;
  /** request data was passed along this edge */
  carried: boolean;
  inputSource?: string;
}

/** Follows one edge of the call graph, carrying request data parameter by parameter. */
function step(graph: ProjectGraph, from: string, tainted: Set<string>, next: string): Step {
  const callee = graph.functions.get(next);
  const nextTaint = reqParams(graph, next);
  let carried = false;
  let source: string | undefined;
  const realised = graph.edgeSites.get(from)?.get(next);
  if (realised) {
    // Call edge: callee parameters at tainted argument positions become tainted.
    for (const c of realised) {
      c.args.forEach((a, i) => {
        if (!argIsTainted(a.roots, tainted)) return;
        const p = callee?.params[i];
        if (p && p !== '<pattern>') nextTaint.add(p);
        carried = true;
        source ??= a.origin ?? a.text;
      });
    }
  }
  if (callee?.parentId === from || !realised) {
    // Containment edge (callback or closure defined inside this function): the names it
    // captures keep their taint, including this function's locals that derive from request
    // data (`const data = req.body.src; setTimeout(() => use(data))`). A closure that is both
    // defined here and called by name gets both models.
    for (const t of tainted) if (!callee?.params.includes(t)) nextTaint.add(t);
    const parent = graph.functions.get(from);
    for (const l of parent?.locals ?? []) {
      if (callee?.params.includes(l.name) || !argIsTainted(l.roots, tainted)) continue;
      nextTaint.add(l.name);
      carried = true;
      source ??= l.origin ?? l.name;
    }
  }
  return { tainted: nextTaint, carried, inputSource: source };
}

interface State {
  id: string;
  tainted: Set<string>;
  /** index into the function's sinks of the first one with a tainted argument, or -1 */
  sink: number;
  /** states one edge upstream, with what that edge carried */
  preds: { from: number; carried: boolean; inputSource?: string }[];
}

interface Succ {
  to: number;
  carried: boolean;
  inputSource?: string;
}

/**
 * Request-data search over (function, tainted names) states, shared by every entry point of a
 * finding: the states reachable from a handler do not depend on which handler reached them, so
 * they are expanded once, then a backwards pass from the states where a vulnerable call takes
 * tainted data gives each handler its shortest such path.
 */
class TaintSearch {
  private states: State[] = [];
  private keys = new Map<string, number>();
  /** hops from each state to the nearest tainted vulnerable call, -1 when there is none */
  private dist: Int32Array;
  private succ: (Succ | undefined)[];
  /** every state reachable from the handlers was expanded (the cap was not hit) */
  private complete: boolean;
  private hops = new Map<string, PathHop>();
  private graph: ProjectGraph;
  private sitesByFn: Map<string, Sink[]>;
  private toward: Map<string, string | undefined>;

  constructor(graph: ProjectGraph, sitesByFn: Map<string, Sink[]>, toward: Map<string, string | undefined>, starts: string[]) {
    this.graph = graph;
    this.sitesByFn = sitesByFn;
    this.toward = toward;
    for (const s of starts) this.intern(s, reqParams(graph, s));
    this.expand();
    this.complete = this.states.length < MAX_STATES;
    this.dist = new Int32Array(this.states.length).fill(-1);
    this.succ = new Array<Succ | undefined>(this.states.length);
    this.resolve();
  }

  private key(id: string, tainted: Set<string>): string {
    return tainted.size ? `${id}|${[...tainted].sort().join(',')}` : id;
  }

  private intern(id: string, tainted: Set<string>): number {
    const key = this.key(id, tainted);
    const have = this.keys.get(key);
    if (have !== undefined) return have;
    const sinks = this.sitesByFn.get(id);
    const sink = sinks ? sinks.findIndex((s) => s.site.args.some((a) => argIsTainted(a.roots, tainted))) : -1;
    const n = this.states.length;
    this.states.push({ id, tainted, sink, preds: [] });
    this.keys.set(key, n);
    return n;
  }

  /** Breadth-first over states; a state where the vulnerable call is tainted is not expanded further. */
  private expand(): void {
    for (let i = 0; i < this.states.length && this.states.length < MAX_STATES; i++) {
      const st = this.states[i]!;
      if (st.sink >= 0) continue;
      for (const next of this.graph.edges.get(st.id) ?? []) {
        if (!this.toward.has(next)) continue;
        const s = step(this.graph, st.id, st.tainted, next);
        const n = this.intern(next, s.tainted);
        this.states[n]!.preds.push({ from: i, carried: s.carried, inputSource: s.inputSource });
      }
    }
  }

  /** Backwards from every tainted vulnerable call: distance and next hop for every state that reaches one. */
  private resolve(): void {
    const queue: number[] = [];
    for (let i = 0; i < this.states.length; i++) {
      if (this.states[i]!.sink < 0) continue;
      this.dist[i] = 0;
      queue.push(i);
    }
    for (let q = 0; q < queue.length; q++) {
      const x = queue[q]!;
      for (const p of this.states[x]!.preds) {
        if (this.dist[p.from]! >= 0) continue;
        this.dist[p.from] = this.dist[x]! + 1;
        this.succ[p.from] = { to: x, carried: p.carried, inputSource: p.inputSource };
        queue.push(p.from);
      }
    }
  }

  /** Shortest path from a handler along which request data reaches a vulnerable call. */
  taintedPath(start: string): Omit<ReachPath, 'entry'> | undefined {
    let cur = this.keys.get(this.key(start, reqParams(this.graph, start)));
    if (cur === undefined || this.dist[cur]! < 0) return undefined;
    const ids = [start];
    let inputAt = -1;
    let inputSource: string | undefined;
    for (let s = this.succ[cur]; s; s = this.succ[cur]) {
      if (inputAt < 0 && s.carried) {
        inputAt = ids.length - 1;
        inputSource = s.inputSource;
      }
      cur = s.to;
      ids.push(this.states[cur]!.id);
    }
    const st = this.states[cur]!;
    const sink = this.sitesByFn.get(st.id)![st.sink]!;
    const idx = sink.site.args.findIndex((a) => argIsTainted(a.roots, st.tainted));
    return this.describe(ids, sink, idx, inputAt, inputSource);
  }

  /** Shortest path from a handler to any vulnerable call, with whatever request data it happens to carry. */
  anyPath(start: string): Omit<ReachPath, 'entry'> | undefined {
    if (!this.toward.has(start)) return undefined;
    const ids = [start];
    for (let next = this.toward.get(start); next !== undefined; next = this.toward.get(next)) ids.push(next);
    const sink = this.sitesByFn.get(ids[ids.length - 1]!)![0]!;
    // This path is only asked for once no tainted path exists from the handler. When every state
    // was explored that settles it: no argument of the call is tainted along any path, this one
    // included. Only a capped search has to carry the request data along the path to find out.
    let idx = -1;
    let inputAt = -1;
    let inputSource: string | undefined;
    if (!this.complete) {
      let tainted = reqParams(this.graph, start);
      for (let i = 1; i < ids.length; i++) {
        const s = step(this.graph, ids[i - 1]!, tainted, ids[i]!);
        if (inputAt < 0 && s.carried) {
          inputAt = i - 1;
          inputSource = s.inputSource;
        }
        tainted = s.tainted;
      }
      idx = sink.site.args.findIndex((a) => argIsTainted(a.roots, tainted));
    }
    return this.describe(ids, sink, idx, inputAt, inputSource);
  }

  private hop(id: string): PathHop {
    let h = this.hops.get(id);
    if (!h) {
      const fn: FunctionInfo | undefined = this.graph.functions.get(id);
      h = fn ? { functionId: id, name: fn.name, file: fn.file, line: fn.line } : { functionId: id, name: id, file: '', line: 0 };
      this.hops.set(id, h);
    }
    return h;
  }

  /** The reported path; `idx` is the argument of the vulnerable call that carries request data, -1 for none. */
  private describe(ids: string[], sink: Sink, idx: number, inputAt: number, inputSource: string | undefined): Omit<ReachPath, 'entry'> {
    const isTainted = idx >= 0;
    const hops = ids.map((id) => this.hop(id));
    const entered = inputAt >= 0 ? hops[inputAt] : undefined;
    const arg = sink.site.args[idx];
    // Direct: the request data is read in the same function as the vulnerable call (or is one
    // of that handler's own request-carrying parameters), not handed down from a caller.
    const direct = isTainted && (inputAt < 0 || arg!.roots.some((r) => REQ.has(r)));
    return {
      hops,
      callSite: { file: sink.file, line: sink.line, col: sink.col, text: sink.text, symbol: sink.symbol, userInput: direct },
      userInput: isTainted,
      inputEntersAt: isTainted && !direct && entered ? { file: entered.file, line: entered.line, name: entered.name } : undefined,
      inputSource: isTainted ? (direct ? arg!.origin ?? arg!.text : inputSource ?? arg!.origin ?? arg!.text) : undefined,
      taintedArgument: isTainted ? { index: idx, text: arg!.text } : undefined,
    };
  }
}
