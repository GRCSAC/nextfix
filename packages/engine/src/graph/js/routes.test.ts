import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { analyzeProject } from './project.ts';
import { assessReach } from '../../reach/reachability.ts';
import type { Component } from '../../types.ts';

const FIXTURE = fileURLToPath(new URL('../../../test-fixtures/controllers-app/', import.meta.url));

test('controller, instance, factory and mounted handlers all become entry points', () => {
  const g = analyzeProject(FIXTURE);
  const eps = new Map(g.entryPoints.map((e) => [`${e.method} ${e.path}`, e]));
  assert.deepEqual([...eps.keys()].sort(), ['GET /', 'GET /account', 'GET /dashboard', 'GET /factory', 'GET /nested', 'GET /reports', 'POST /login', 'POST /reports/preview', 'USE /legacy']);

  // session(), passport.initialize/session and flash are setup middleware, not guards.
  assert.equal(eps.get('GET /')!.authenticated, false);
  assert.equal(eps.get('POST /login')!.authenticated, false);
  // passport.authenticate(...) and isLoggedIn are guards.
  assert.equal(eps.get('GET /account')!.authenticated, true);
  assert.equal(eps.get('GET /dashboard')!.authenticated, true);
  assert.equal(eps.get('GET /reports')!.authenticated, true);

  // controller.method resolves into the controller module; factories resolve to the factory function.
  assert.ok(eps.get('GET /')!.handlerIds[0]?.startsWith('controllers/user.js#'));
  assert.ok(eps.get('POST /login')!.handlerIds[0]?.startsWith('lib/factories.js#login'));
  assert.equal(eps.get('POST /login')!.unresolvedHandlers, undefined);
  assert.ok(eps.get('GET /factory')!.handlerIds[0]?.startsWith('lib/factories.js#makeHandler'), 'wrapper unwrapped to the factory');
  assert.ok(eps.get('POST /reports/preview')!.handlerIds[0]?.startsWith('lib/reports.js#preview'));
});

test('reachability follows controller and class-method handlers', () => {
  const g = analyzeProject(FIXTURE);
  const lodash: Component = { ecosystem: 'npm', name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', dev: false, optional: false, direct: true, path: 'node_modules/lodash' };
  const template = assessReach(g, lodash, { ids: ['X'], ecosystem: 'npm', package: 'lodash', symbols: ['template'], source: 'curated', confidence: 'confirmed' });
  assert.equal(template.tier, 'reachable');
  const entries = template.paths.map((p) => `${p.entry.method} ${p.entry.path}`).sort();
  // USE /legacy (controller), the two report routes (class methods via this.render), the wrapped
  // factory (returned closure), and the nested-callback handler.
  assert.deepEqual(entries, ['GET /factory', 'GET /nested', 'GET /reports', 'POST /reports/preview', 'USE /legacy']);
  const factory = template.paths.find((p) => p.entry.path === '/factory')!;
  assert.equal(factory.callSite.userInput, true);
  const preview = template.paths.find((p) => p.entry.path === '/reports/preview')!;
  assert.equal(preview.entry.authenticated, false);
  assert.equal(preview.userInput, true);

  const pick = assessReach(g, lodash, { ids: ['Y'], ecosystem: 'npm', package: 'lodash', symbols: ['pick'], source: 'curated', confidence: 'confirmed' });
  assert.equal(pick.tier, 'reachable');
  assert.equal(pick.paths[0]!.entry.path, '/account');
  assert.equal(pick.paths[0]!.entry.authenticated, true);
});
