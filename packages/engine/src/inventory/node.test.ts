import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findNodeLockfile, hasNodeProject, listWorkspaceDirs, readNodeInventory } from './node.ts';

const FIXTURES = fileURLToPath(new URL('../../test-fixtures/', import.meta.url));

test('the root lockfile is picked in order: package-lock.json, yarn.lock, pnpm-lock.yaml', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-node-'));
  assert.equal(findNodeLockfile(dir), undefined);
  assert.equal(hasNodeProject(dir), false);
  writeFileSync(join(dir, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n");
  assert.equal(findNodeLockfile(dir), 'pnpm-lock.yaml');
  writeFileSync(join(dir, 'yarn.lock'), '# yarn lockfile v1\n');
  assert.equal(findNodeLockfile(dir), 'yarn.lock');
  writeFileSync(join(dir, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}');
  assert.equal(findNodeLockfile(dir), 'package-lock.json');
  assert.equal(hasNodeProject(dir), true);
});

test('workspace directories come from package.json workspaces or pnpm-workspace.yaml', () => {
  assert.deepEqual(listWorkspaceDirs(join(FIXTURES, 'workspaces-app')), ['packages/api']);
  assert.deepEqual(listWorkspaceDirs(join(FIXTURES, 'pnpm-app')), ['packages/shared', 'packages/web']);
  assert.deepEqual(listWorkspaceDirs(join(FIXTURES, 'yarn-app')), []);
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-ws-'));
  mkdirSync(join(dir, 'apps', 'web', 'admin'), { recursive: true });
  mkdirSync(join(dir, 'tools', 'cli'), { recursive: true });
  writeFileSync(join(dir, 'apps', 'web', 'package.json'), '{}');
  writeFileSync(join(dir, 'apps', 'web', 'admin', 'package.json'), '{}');
  writeFileSync(join(dir, 'tools', 'cli', 'package.json'), '{}');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ workspaces: { packages: ['apps/**', 'tools/cli', '!apps/web/admin'] } }));
  assert.deepEqual(listWorkspaceDirs(dir), ['apps/web', 'apps/web/admin', 'tools/cli']);
});

test('workspaces merge: the same purl in two lockfiles is one component with two paths', () => {
  const inv = readNodeInventory(join(FIXTURES, 'workspaces-app'));
  assert.deepEqual(inv.sources, ['package-lock.json', 'packages/api/yarn.lock']);
  assert.equal(inv.projectName, 'workspaces-app');
  assert.equal(inv.projectVersion, '1.0.0');
  const by = new Map(inv.components.map((c) => [c.name, c]));
  assert.deepEqual([...by.keys()].sort(), ['lodash', 'ms']);
  const lodash = by.get('lodash')!;
  assert.equal(lodash.purl, 'pkg:npm/lodash@4.17.21');
  assert.equal(lodash.path, 'node_modules/lodash');
  assert.deepEqual(lodash.paths, ['node_modules/lodash', 'packages/api/yarn.lock:lodash@4.17.21']);
  assert.equal(lodash.direct, true);
  const ms = by.get('ms')!;
  assert.deepEqual(ms.paths, ['node_modules/ms', 'packages/api/yarn.lock:ms@2.1.3']);
  assert.equal(ms.direct, true, "declared by the workspace's package.json, not the root's");
  assert.equal(ms.dev, false);
});

test('a pnpm workspace is inventoried from the single root lockfile', () => {
  const inv = readNodeInventory(join(FIXTURES, 'pnpm-app'));
  assert.deepEqual(inv.sources, ['pnpm-lock.yaml']);
  assert.equal(inv.projectName, 'pnpm-app');
  assert.equal(inv.components.length, 10);
  assert.equal(inv.components.find((c) => c.name === 'express')?.direct, true);
});

test('a yarn classic project is inventoried from yarn.lock', () => {
  const inv = readNodeInventory(join(FIXTURES, 'yarn-app'));
  assert.deepEqual(inv.sources, ['yarn.lock']);
  assert.equal(inv.projectName, 'yarn-app');
  assert.equal(inv.components.find((c) => c.name === 'string-width')?.purl, 'pkg:npm/string-width@4.2.3');
});

test('a directory without any lockfile is an error', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-empty-'));
  assert.throws(() => readNodeInventory(dir), /No package-lock.json, yarn.lock or pnpm-lock.yaml/);
});
