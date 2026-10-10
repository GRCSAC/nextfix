import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { analyzePythonProject } from './project.ts';
import { assessReach } from '../../reach/reachability.ts';
import { readPythonDeps } from '../../inventory/python.ts';
import { comparePep440 } from '../../vulns/pep440.ts';
import type { Component } from '../../types.ts';

const FX = (name: string) => fileURLToPath(new URL(`../../../test-fixtures/${name}/`, import.meta.url));
const comp = (name: string, version: string): Component => ({ ecosystem: 'PyPI', name, version, purl: `pkg:pypi/${name}@${version}`, dev: false, optional: false, direct: true, path: 'requirements.txt' });
const sym = (pkg: string, symbols: string[]) => ({ ids: ['X'], ecosystem: 'PyPI' as const, package: pkg, symbols, source: 'curated' as const, confidence: 'confirmed' as const });
const installed = new Set(['flask', 'pyyaml', 'flask-login', 'fastapi', 'jinja2', 'django', 'markdown']);
const label = (p: { entry: { method: string; path: string; authenticated: boolean }; userInput: boolean; inputSource?: string }) => `${p.entry.method} ${p.entry.path}${p.entry.authenticated ? ' [auth]' : ''}${p.userInput ? ' <' + p.inputSource + '>' : ''}`;

test('pep 440 ordering', () => {
  assert.ok(comparePep440('5.3', '5.4') < 0);
  assert.ok(comparePep440('2.29.2', '2.29.10') < 0);
  assert.ok(comparePep440('4.2', '4.2rc1') > 0);
  assert.ok(comparePep440('1.0.post1', '1.0') > 0);
  assert.ok(comparePep440('1.0.dev1', '1.0a1') < 0);
  assert.equal(comparePep440('3.2', '3.2.0'), 0);
});

test('python inventory reads pinned requirements with normalised names', () => {
  const inv = readPythonDeps(FX('flask-app'));
  assert.deepEqual(inv.components.map((c) => `${c.name}@${c.version}`), ['flask@2.0.0', 'flask-login@0.6.0', 'pyyaml@5.3']);
  assert.equal(inv.components[2]!.purl, 'pkg:pypi/pyyaml@5.3');
});

test('flask: blueprints registered from a factory, url_prefix, login_required, request data', async () => {
  const g = await analyzePythonProject(FX('flask-app'), { installed });
  const eps = g.entryPoints.map((e) => `${e.method} ${e.path}${e.authenticated ? ' [auth]' : ''}`).sort();
  assert.deepEqual(eps, ['GET /', 'GET /auth/login', 'POST /auth/login', 'POST /config [auth]', 'POST /preview']);
  assert.ok(g.entryPoints.every((e) => e.mounted), 'blueprints are mounted through create_app()');

  const load = assessReach(g, comp('pyyaml', '5.3'), sym('pyyaml', ['load']));
  assert.equal(load.tier, 'reachable');
  assert.deepEqual(load.paths.map(label), ['POST /config [auth] <request.data>']);
  assert.equal(load.callSites.length, 2, 'helper() also calls yaml.load but nothing reaches it');

  const rts = assessReach(g, comp('flask', '2.0.0'), sym('flask', ['render_template_string']));
  assert.deepEqual(rts.paths.map(label), ['POST /preview <request.form[\'t\']>']);
});

test('fastapi: nested include_router prefixes, router dependencies as guards, handler params as input', async () => {
  const g = await analyzePythonProject(FX('fastapi-app'), { installed });
  const eps = g.entryPoints.map((e) => `${e.method} ${e.path}${e.authenticated ? ' [auth]' : ''}`).sort();
  // the users router carries dependencies=[Depends(get_current_user)], so both of its routes are guarded;
  // '/' on a prefixed router collapses to the prefix
  assert.deepEqual(eps, ['GET /api/v1/items/{item_id}', 'GET /api/v1/users [auth]', 'POST /api/v1/users/import [auth]']);

  const load = assessReach(g, comp('pyyaml', '5.3'), sym('pyyaml', ['load']));
  assert.deepEqual(load.paths.map(label), ['POST /api/v1/users/import [auth] <body>']);
  const tpl = assessReach(g, comp('jinja2', '2.10'), sym('jinja2', ['Template']));
  assert.deepEqual(tpl.paths.map(label), ['GET /api/v1/items/{item_id} <q>']);
});

test('django: urlpatterns with include(), class-based views with mixins, login_required', async () => {
  const g = await analyzePythonProject(FX('django-app'), { installed });
  const eps = g.entryPoints.map((e) => `${e.method} ${e.path}${e.authenticated ? ' [auth]' : ''}${e.unresolvedHandlers ? ' ?' : ''}`).sort();
  assert.deepEqual(eps, ['ANY /admin ?', 'ANY /blog', 'ANY /blog/render [auth]', 'GET /blog/post/:pk [auth]', 'POST /blog/post/:pk [auth]']);

  const load = assessReach(g, comp('pyyaml', '5.3'), sym('pyyaml', ['load']));
  assert.deepEqual(load.paths.map(label), ['POST /blog/post/:pk [auth] <request.body>']);
  const md = assessReach(g, comp('markdown', '3.1'), sym('markdown', ['markdown']));
  assert.deepEqual(md.paths.map(label), ["ANY /blog/render [auth] <request.POST['body']>"]);
});
