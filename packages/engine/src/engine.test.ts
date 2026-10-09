import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { cvss3BaseScore } from './vulns/cvss.ts';
import { readNpmLock } from './inventory/npm-lock.ts';
import { analyzeProject } from './graph/js/project.ts';
import { assessReach } from './reach/reachability.ts';
import { analyzeExposure } from './exposure/docker.ts';
import { SymbolDb } from './vulns/symbols.ts';
import type { Component } from './types.ts';

const SAMPLE = fileURLToPath(new URL('../../../samples/express-shop/', import.meta.url));

test('cvss 3.1 base score matches published examples', () => {
  // CVE-2021-23337 (lodash template): 7.2
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'), 7.2);
  // Scope-changed example from the spec: 10.0
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), undefined);
});

test('npm lockfile inventory flags dev, direct and nested packages', () => {
  const inv = readNpmLock(SAMPLE);
  const byName = new Map(inv.components.map((c) => [c.name, c]));
  assert.equal(byName.get('lodash')?.version, '4.17.15');
  assert.equal(byName.get('lodash')?.direct, true);
  assert.equal(byName.get('lodash')?.dev, false);
  assert.equal(byName.get('minimist')?.dev, true);
  assert.equal(byName.get('qs')?.direct, false);
  assert.equal(byName.get('lodash')?.purl, 'pkg:npm/lodash@4.17.15');
});

test('express entry points carry mount prefixes and auth guards', () => {
  const g = analyzeProject(SAMPLE);
  const eps = g.entryPoints.map((e) => `${e.method} ${e.path}${e.authenticated ? ' [auth]' : ''}`).sort();
  assert.deepEqual(eps, ['GET /go', 'GET /healthz', 'POST /admin/users/normalize [auth]', 'POST /preview']);
  assert.equal(g.listenLocalOnly, false);
});

test('reachability tiers on the demo app', () => {
  const g = analyzeProject(SAMPLE);
  const db = SymbolDb.load();
  const comp = (name: string, version: string, dev = false): Component => ({ ecosystem: 'npm', name, version, purl: `pkg:npm/${name}@${version}`, dev, optional: false, direct: true, path: `node_modules/${name}` });
  const lodash = comp('lodash', '4.17.15');

  const template = assessReach(g, lodash, db.lookup(['CVE-2021-23337'], 'lodash'));
  assert.equal(template.tier, 'reachable');
  assert.equal(template.paths[0]?.entry.path, '/preview');
  assert.equal(template.paths[0]?.entry.authenticated, false);
  assert.equal(template.paths[0]?.userInput, true, 'req.body.template is passed down to _.template');
  assert.equal(template.paths[0]?.inputEntersAt?.file, 'src/app.js');
  assert.equal(template.paths[0]?.inputSource, 'req.body.template');
  assert.deepEqual(template.paths[0]?.taintedArgument, { index: 0, text: 'source' });

  const trim = assessReach(g, lodash, db.lookup(['CVE-2020-28500'], 'lodash'));
  assert.equal(trim.tier, 'reachable');
  assert.equal(trim.paths[0]?.entry.path, '/admin/users/normalize');
  assert.equal(trim.paths[0]?.entry.authenticated, true);

  const set = assessReach(g, lodash, db.lookup(['CVE-2020-8203'], 'lodash'));
  assert.equal(set.tier, 'called-unreached');

  const defaultsDeep = assessReach(g, lodash, db.lookup(['CVE-2019-10744'], 'lodash'));
  assert.equal(defaultsDeep.tier, 'imported-not-called');

  assert.equal(assessReach(g, lodash, undefined).tier, 'imported-unknown-symbol');
  assert.equal(assessReach(g, comp('moment', '2.29.1'), undefined).tier, 'unused');
  assert.equal(assessReach(g, comp('minimist', '1.2.5', true), db.lookup(['CVE-2021-44906'], 'minimist')).tier, 'dev-only');

  const redirect = assessReach(g, comp('express', '4.17.1'), db.lookup(['CVE-2024-29041'], 'express'));
  assert.equal(redirect.tier, 'reachable');
  assert.equal(redirect.paths[0]?.callSite.userInput, true);
});

test('docker exposure reads EXPOSE and compose ports', () => {
  const x = analyzeExposure(SAMPLE, false);
  assert.equal(x.network, 'published');
  assert.deepEqual(x.ports, [3000]);
});
