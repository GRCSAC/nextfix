import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { analyzeProject } from './project.ts';
import { compileGuardPatterns } from './analyze.ts';
import { assessReach } from '../../reach/reachability.ts';
import type { Component, SymbolEntry } from '../../types.ts';

const fixture = (name: string) => fileURLToPath(new URL(`../../../test-fixtures/${name}/`, import.meta.url));
const lodash: Component = { ecosystem: 'npm', name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', dev: false, optional: false, direct: true, path: 'node_modules/lodash' };
const template: SymbolEntry = { ids: ['X'], ecosystem: 'npm', package: 'lodash', symbols: ['template'], source: 'curated', confidence: 'confirmed' };
const byRoute = (g: ReturnType<typeof analyzeProject>) => new Map(g.entryPoints.map((e) => [`${e.method} ${e.path}`, e]));
const pathsOf = (r: ReturnType<typeof assessReach>) => r.paths.map((p) => `${p.entry.method} ${p.entry.path}${p.userInput ? ' <' + p.inputSource + '>' : ''}`).sort();

test('the final argument of a route registration is the handler, never only a guard', () => {
  const g = analyzeProject(fixture('guard-handlers'));
  const eps = byRoute(g);
  assert.deepEqual([...eps.keys()].sort(), ['GET /roles', 'GET /x', 'POST /login', 'POST /register', 'PUT /users/:id']);
  // authController.login / auth.register: the receiver says "auth", the handler does not.
  for (const key of ['POST /login', 'POST /register']) {
    const e = eps.get(key)!;
    assert.equal(e.authenticated, false, key);
    assert.equal(e.unresolvedHandlers, undefined, key);
    assert.ok(e.handlerIds[0]?.startsWith('src/controllers/auth.js#'), `${key} handler lives in the controller`);
  }
  // A named inline handler containing a guard word is still the handler.
  assert.equal(eps.get('GET /roles')!.authenticated, false);
  assert.equal(eps.get('GET /roles')!.handlerIds.length, 1);
  // A final argument that names a guard is the handler and keeps the route guarded.
  const deny = eps.get('PUT /users/:id')!;
  assert.equal(deny.authenticated, true);
  assert.deepEqual(deny.guards, ['security.denyAll()']);
  assert.ok(deny.handlerIds[0]?.startsWith('src/lib/security.js#denyAll'));

  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  assert.deepEqual(pathsOf(r), ['GET /roles <req.query.t>', 'POST /login <req.body.t>', 'POST /register <req.body.t>']);
});

test('a default import of a package sub-path is the sub-path symbol', () => {
  const g = analyzeProject(fixture('subpath-import'));
  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  assert.deepEqual(pathsOf(r), ['POST /t <req.body.src>']);
  assert.equal(r.callSites[0]!.symbol, 'template');
});

test('a parameter reassigned from itself still carries request data', () => {
  const g = analyzeProject(fixture('taint-reassign'));
  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  assert.deepEqual(pathsOf(r), ['POST /p <req.body.src>']);
  const p = r.paths[0]!;
  assert.deepEqual(p.taintedArgument, { index: 0, text: 'src' });
  assert.equal(p.inputEntersAt?.name, '<handler>');
});

test('require() and import() inside a function import the package and resolve calls', () => {
  const g = analyzeProject(fixture('scoped-require'));
  assert.deepEqual([...g.packagesImported.get('lodash') ?? []], ['app.js']);
  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  assert.deepEqual(pathsOf(r), ['POST /p <req.body.src>', 'POST /q <req.body.src>']);
});

test('./x.js resolves to x.ts (NodeNext) so the cross-file call is followed', () => {
  const g = analyzeProject(fixture('nodenext-resolve'));
  const app = g.modules.get('src/app.ts')!;
  const render = app.imports.find((b) => b.local === 'render')!;
  assert.ok(render.file?.replace(/\\/g, '/').endsWith('src/render.ts'), render.file);
  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  assert.deepEqual(pathsOf(r), ['POST /p <req.body.src>']);
});

test('closures inherit the taint of request-derived locals they capture', () => {
  const g = analyzeProject(fixture('closure-taint'));
  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  // /p: the closure is both defined in the handler and called by name; /q: a callback.
  assert.deepEqual(pathsOf(r), ['POST /p <req.body.src>', 'POST /q <req.body.src>']);
  for (const p of r.paths) {
    assert.deepEqual(p.taintedArgument, { index: 0, text: 'data' }, p.entry.path);
    assert.equal(p.inputEntersAt?.name, '<handler>', p.entry.path);
  }
});

test('inline middleware that answers 401/403 is a guard; a bare throw and a final handler are not', () => {
  const g = analyzeProject(fixture('inline-guard'));
  const eps = byRoute(g);
  assert.deepEqual([...eps.keys()].sort(), ['POST /p', 'USE /files']);
  const p = eps.get('POST /p')!;
  assert.equal(p.authenticated, true);
  assert.deepEqual(p.guards, ['inline check (app.js:8)'], 'only the 401 middleware, not the throwing one');
  // The final argument of a scoped use() is the handler even though its body can reject.
  const files = eps.get('USE /files')!;
  assert.equal(files.authenticated, true, 'guarded by the global 401 middleware');
  assert.equal(files.handlerIds.length, 1);
  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  assert.equal(r.paths[0]!.entry.authenticated, true);
});

test('constructors are call sites, this.method() resolves, and sub-path members answer to both names', () => {
  const g = analyzeProject(fixture('ctor-subpath'));
  // `fp.template()` for `require('lodash/fp')` matches the symbol `template` as well as `fp.template`.
  const r = assessReach(g, lodash, template);
  assert.equal(r.tier, 'reachable');
  // The handler hands the whole request to handle(); run() then gets req.body.src through this.run().
  assert.deepEqual(pathsOf(r), ['POST /fp <req>']);
  assert.deepEqual(r.paths[0]!.hops.map((h) => h.name), ['<handler>', 'handle', 'run']);
  assert.deepEqual(r.paths[0]!.taintedArgument, { index: 0, text: 'src' });
  const fpNamed = assessReach(g, lodash, { ...template, symbols: ['fp.template'] });
  assert.equal(fpNamed.tier, 'reachable');

  const xml2js: Component = { ...lodash, name: 'xml2js', version: '0.4.23', purl: 'pkg:npm/xml2js@0.4.23', path: 'node_modules/xml2js' };
  const parser = assessReach(g, xml2js, { ...template, package: 'xml2js', symbols: ['Parser'] });
  assert.equal(parser.tier, 'reachable');
  assert.equal(parser.callSites[0]!.text, 'new Parser');
  assert.equal(parser.paths[0]!.entry.path, '/xml');
  assert.equal(parser.paths[0]!.userInput, false, 'the constructor only receives options');
});

test('authGuards patterns from the scanned repository are validated', () => {
  assert.equal(compileGuardPatterns(['requireRole', '(a|b)+', '[a-z]+\\d*', '']), 'requireRole|(a|b)+|[a-z]+\\d*');
  assert.equal(compileGuardPatterns([]), undefined);
  assert.throws(() => compileGuardPatterns(['(a+)+']), /nested|quantifier/);
  assert.throws(() => compileGuardPatterns(['(\\w*)*$']), (e: Error) => e.message.includes(`authGuards pattern ${JSON.stringify('(\\w*)*$')}`));
  assert.throws(() => compileGuardPatterns(['(\\d{2})+']), /quantifier/);
  assert.throws(() => compileGuardPatterns(['(']), /not a valid regular expression/);
  assert.throws(() => compileGuardPatterns(['a'.repeat(201)]), /longer than 200/);
  assert.throws(() => analyzeProject(fixture('inline-guard'), { authGuards: ['(x+)+'] }), /authGuards pattern "\(x\+\)\+"/);
  // A benign pattern still extends the guard list.
  const g = analyzeProject(fixture('guard-handlers'), { authGuards: ['getRolePermissions'] });
  assert.equal(byRoute(g).get('GET /roles')!.authenticated, false, 'a final inline handler is never a guard, whatever its name');
});
