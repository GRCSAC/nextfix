import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { analyzeProject } from './project.ts';
import { assessReach } from '../../reach/reachability.ts';
import type { Component } from '../../types.ts';

const FASTIFY = fileURLToPath(new URL('../../../test-fixtures/fastify-app/', import.meta.url));
const KOA = fileURLToPath(new URL('../../../test-fixtures/koa-app/', import.meta.url));
const lodash: Component = { ecosystem: 'npm', name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', dev: false, optional: false, direct: true, path: 'node_modules/lodash' };
const templateSym = { ids: ['X'], ecosystem: 'npm' as const, package: 'lodash', symbols: ['template'], source: 'curated' as const, confidence: 'confirmed' as const };
const trimSym = { ...templateSym, ids: ['Y'], symbols: ['trim'] };

test('fastify: options hooks, route(), register with prefix, in-file plugins', () => {
  const g = analyzeProject(FASTIFY);
  const eps = new Map(g.entryPoints.map((e) => [`${e.method} ${e.path}`, e]));
  assert.deepEqual([...eps.keys()].sort(), ['GET /admin/report', 'GET /health', 'GET /users', 'POST /billing/invoice', 'POST /preview', 'POST /users/:id/rename']);
  assert.equal(eps.get('GET /admin/report')!.authenticated, true, 'preHandler guard');
  assert.equal(eps.get('POST /billing/invoice')!.authenticated, true, 'scoped onRequest hook');
  assert.equal(eps.get('POST /preview')!.authenticated, false);
  assert.equal(eps.get('POST /users/:id/rename')!.authenticated, false);

  const template = assessReach(g, lodash, templateSym);
  const found = template.paths.map((p) => `${p.entry.method} ${p.entry.path}${p.userInput ? ' <' + p.inputSource + '>' : ''}`).sort();
  assert.deepEqual(found, ['GET /admin/report <request.query.layout>', 'POST /billing/invoice <request.body.layout>', 'POST /preview <request.body.template>']);

  const trim = assessReach(g, lodash, trimSym);
  assert.equal(trim.paths[0]!.entry.path, '/users/:id/rename');
  assert.equal(trim.paths[0]!.inputSource, 'request.body.name');
});

test('koa: router prefixes, named routes, router.use guards, mounted router modules', () => {
  const g = analyzeProject(KOA);
  const eps = new Map(g.entryPoints.map((e) => [`${e.method} ${e.path}`, e]));
  assert.deepEqual([...eps.keys()].sort(), ['GET /api/health', 'GET /api/search', 'GET /public/ping', 'POST /admin/layout', 'POST /api/preview']);
  assert.equal(eps.get('GET /public/ping')!.authenticated, false, '"unprotected" is not a guard; named router export mounts');
  assert.equal(eps.get('GET /api/search')!.authenticated, true, 'route-level guard');
  assert.equal(eps.get('POST /admin/layout')!.authenticated, true, 'router.use(requireAuth) in the mounted module');
  assert.equal(eps.get('POST /api/preview')!.authenticated, false);

  const template = assessReach(g, lodash, templateSym);
  const found = template.paths.map((p) => `${p.entry.method} ${p.entry.path}${p.userInput ? ' <' + p.inputSource + '>' : ''}`).sort();
  assert.deepEqual(found, ['POST /admin/layout <ctx.request.body.layout>', 'POST /api/preview <ctx.request.body.template>']);
});
