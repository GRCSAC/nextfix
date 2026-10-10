import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CallArg, CallSite, FunctionInfo } from '../graph/js/analyze.ts';
import type { ProjectGraph } from '../graph/js/project.ts';
import { assessReach } from './reachability.ts';
import { scan } from '../scan.ts';
import type { Component, EntryPoint, SymbolEntry } from '../types.ts';

const SAMPLE = fileURLToPath(new URL('../../../../samples/express-shop/', import.meta.url));

const lodash: Component = { ecosystem: 'npm', name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', dev: false, optional: false, direct: true, path: 'node_modules/lodash' };
const entryFor = (symbol: string): SymbolEntry => ({ ids: [`X-${symbol}`], ecosystem: 'npm', package: 'lodash', symbols: [symbol], source: 'curated', confidence: 'confirmed' });

/** Builds a ProjectGraph by hand, the way the analyzer would, from functions and their call sites. */
class GraphBuilder {
  functions = new Map<string, FunctionInfo>();
  edges = new Map<string, Set<string>>();
  edgeSites = new Map<string, Map<string, CallSite[]>>();
  entryPoints: EntryPoint[] = [];
  packagesImported = new Map<string, Set<string>>();

  fn(id: string, name: string, file: string, params: string[], parentId?: string): FunctionInfo {
    const f: FunctionInfo = { id, name, file, line: this.functions.size + 1, col: 1, params, calls: [], parentId };
    this.functions.set(id, f);
    if (parentId) (this.edges.get(parentId) ?? this.edges.set(parentId, new Set()).get(parentId)!).add(id);
    return f;
  }

  /** A call from `from` to the local function `to`, with the given arguments. */
  call(from: string, to: string, args: CallArg[]): void {
    const f = this.functions.get(from)!;
    const site: CallSite = { line: f.line, col: f.calls.length + 1, text: `${this.functions.get(to)!.name}(${args.map((a) => a.text).join(', ')})`, target: { kind: 'local', name: to }, userInput: args.some((a) => a.roots.includes('req')), args };
    f.calls.push(site);
    (this.edges.get(from) ?? this.edges.set(from, new Set()).get(from)!).add(to);
    const sites = this.edgeSites.get(from) ?? this.edgeSites.set(from, new Map()).get(from)!;
    (sites.get(to) ?? sites.set(to, []).get(to)!).push(site);
  }

  /** A call from `from` into a package symbol. */
  external(from: string, pkg: string, symbol: string, args: CallArg[]): void {
    const f = this.functions.get(from)!;
    f.calls.push({ line: f.line, col: f.calls.length + 1, text: `${symbol}(${args.map((a) => a.text).join(', ')})`, target: { kind: 'external', package: pkg, symbol }, userInput: args.some((a) => a.roots.includes('req')), args });
    (this.packagesImported.get(pkg) ?? this.packagesImported.set(pkg, new Set()).get(pkg)!).add(f.file);
  }

  route(method: string, path: string, handlerIds: string[]): void {
    this.entryPoints.push({ method, path, file: 'src/app.js', line: this.entryPoints.length + 1, authenticated: false, guards: [], mounted: true, handlerIds });
  }

  build(): ProjectGraph {
    return { rootDir: '/synthetic', modules: new Map(), functions: this.functions, edges: this.edges, edgeInput: new Map(), edgeSites: this.edgeSites, entryPoints: this.entryPoints, packagesImported: this.packagesImported, rootApps: ['src/app.js'], listenLocalOnly: false };
  }
}

const arg = (text: string, ...roots: string[]): CallArg => ({ text, roots });

/**
 * `entries` handlers all call the head of a chain of `chain` service functions, each with a
 * callback defined inside it; the tail calls every one of `symbols` from lodash. Odd handlers pass
 * request data as the first argument, which the chain carries straight through.
 */
function chainGraph(chain: number, entries: number, symbols: string[]): ProjectGraph {
  const b = new GraphBuilder();
  for (let k = 0; k < chain; k++) {
    const file = `src/services/s${k}.js`;
    b.fn(`${file}#f${k}`, `f${k}`, file, ['a', 'b']);
    b.fn(`${file}#f${k}/cb`, '<callback>', file, ['x'], `${file}#f${k}`);
    if (k > 0) b.call(`src/services/s${k - 1}.js#f${k - 1}`, `${file}#f${k}`, [arg('a', 'a'), arg('b', 'b')]);
  }
  const tail = `src/services/s${chain - 1}.js#f${chain - 1}`;
  for (const s of symbols) b.external(tail, 'lodash', s, [arg('a', 'a')]);
  for (let j = 0; j < entries; j++) {
    const id = `src/app.js#<handler>@${j}`;
    b.fn(id, '<handler>', 'src/app.js', ['req', 'res']);
    b.call(id, 'src/services/s0.js#f0', [j % 2 ? arg('req.body.x', 'req') : arg("'lit'"), arg("'x'")]);
    b.route('POST', `/r${j}`, [id]);
  }
  return b.build();
}

test('a generated graph with 1,000+ functions and 200+ entry points is assessed in bounded time', () => {
  const symbols = Array.from({ length: 20 }, (_, i) => `sym${i}`);
  const g = chainGraph(600, 250, symbols);
  assert.ok(g.functions.size >= 1000 && g.entryPoints.length >= 200);
  const started = performance.now();
  const results = symbols.map((s) => assessReach(g, lodash, entryFor(s)));
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 2000, `20 findings took ${elapsed.toFixed(0)} ms`);
  for (const r of results) {
    assert.equal(r.tier, 'reachable');
    assert.equal(r.callSites.length, 1);
    assert.equal(r.paths.length, 250, 'one path per entry point');
    r.paths.forEach((p, j) => {
      assert.equal(p.hops.length, 601, 'handler plus the whole chain');
      assert.equal(p.userInput, j % 2 === 1, p.entry.path);
      if (j % 2) {
        assert.equal(p.inputSource, 'req.body.x');
        assert.equal(p.inputEntersAt?.name, '<handler>');
        assert.deepEqual(p.taintedArgument, { index: 0, text: 'a' });
      } else {
        assert.equal(p.inputEntersAt, undefined);
      }
    });
  }
});

test('the shortest path is reported, unless a longer one carries request data', () => {
  const b = new GraphBuilder();
  b.fn('h', '<handler>', 'src/app.js', ['req', 'res']);
  b.fn('a', 'a', 'src/a.js', ['v']);
  b.fn('b', 'b', 'src/b.js', ['v']);
  b.fn('sink', 'render', 'src/render.js', ['src']);
  b.external('sink', 'lodash', 'template', [arg('src', 'src')]);
  // The long way carries req.body.t through a and b; the direct call passes a constant.
  b.call('h', 'a', [arg('req.body.t', 'req')]);
  b.call('a', 'b', [arg('v', 'v')]);
  b.call('b', 'sink', [arg('v', 'v')]);
  b.call('h', 'sink', [arg("'static'")]);
  b.route('POST', '/t', ['h']);
  const g = b.build();

  const tainted = assessReach(g, lodash, entryFor('template'));
  assert.equal(tainted.tier, 'reachable');
  assert.deepEqual(tainted.paths[0]!.hops.map((h) => h.name), ['<handler>', 'a', 'b', 'render']);
  assert.equal(tainted.paths[0]!.userInput, true);
  assert.equal(tainted.paths[0]!.inputSource, 'req.body.t');
  assert.deepEqual(tainted.paths[0]!.inputEntersAt?.name, '<handler>');

  // Without request data on the long way, the two-hop path wins.
  b.edgeSites.get('h')!.get('a')![0]!.args = [arg("'fixed'")];
  const direct = assessReach(b.build(), lodash, entryFor('template'));
  assert.deepEqual(direct.paths[0]!.hops.map((h) => h.name), ['<handler>', 'render']);
  assert.equal(direct.paths[0]!.userInput, false);
});

test('a path through a callback inherits the captured request data', () => {
  const b = new GraphBuilder();
  b.fn('h', '<handler>', 'src/app.js', ['req', 'res']);
  b.functions.get('h')!.locals = [{ name: 'data', roots: ['req'], origin: 'req.body.src' }];
  b.fn('h/cb', '<callback>', 'src/app.js', [], 'h');
  b.fn('sink', 'render', 'src/render.js', ['src']);
  b.external('sink', 'lodash', 'template', [arg('src', 'src')]);
  b.call('h/cb', 'sink', [arg('data', 'data')]);
  b.route('POST', '/t', ['h']);
  const r = assessReach(b.build(), lodash, entryFor('template'));
  assert.equal(r.tier, 'reachable');
  assert.deepEqual(r.paths[0]!.hops.map((h) => h.name), ['<handler>', '<callback>', 'render']);
  assert.equal(r.paths[0]!.userInput, true);
  assert.equal(r.paths[0]!.inputSource, 'req.body.src');
  assert.equal(r.paths[0]!.inputEntersAt?.name, '<handler>');
});

const cancelled = (err: unknown) => err instanceof Error && err.message.startsWith('Scan cancelled');
const cacheDir = mkdtempSync(join(tmpdir(), 'nextfix-test-'));
let caches = 0;
const cachePath = () => join(cacheDir, `cache-${++caches}.sqlite`);
after(() => rmSync(cacheDir, { recursive: true, force: true }));

test('an already aborted signal stops the scan before it starts', async () => {
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(scan(SAMPLE, { offline: true, derive: false, cachePath: cachePath(), signal: ac.signal }), cancelled);
});

test('aborting during a scan stops it at the next stage', async () => {
  const ac = new AbortController();
  const stages: string[] = [];
  const log = (msg: string) => {
    stages.push(msg);
    if (msg.startsWith('Code:')) ac.abort();
  };
  await assert.rejects(scan(SAMPLE, { offline: true, derive: false, cachePath: cachePath(), signal: ac.signal, log }), cancelled);
  assert.ok(stages.some((s) => s.startsWith('Inventory:')), 'the scan ran up to the abort');
  assert.ok(!stages.some((s) => s.startsWith('Advisories:')), 'and no further');
});
