import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePackageKey, parseYaml, readPnpmLock } from './pnpm-lock.ts';

const PNPM_APP = fileURLToPath(new URL('../../test-fixtures/pnpm-app/', import.meta.url));

test('the YAML subset parser handles nested maps, quoted keys, flow maps and sequences', () => {
  const doc = parseYaml(`lockfileVersion: '9.0'
# a comment
settings:
  autoInstallPeers: true
packages:
  '@scope/name@1.0.0':
    resolution: {integrity: sha512-abc, tarball: 'https://x/y.tgz'}
    engines: {node: '>= 0.6'}
    os: [darwin, linux]
  plain@2.0.0: {}
list:
- one
- 'two'
nested:
  items:
    - a
after: value
`);
  assert.equal(doc.lockfileVersion, '9.0');
  assert.deepEqual(doc.settings, { autoInstallPeers: 'true' });
  const pkgs = doc.packages as Record<string, unknown>;
  assert.deepEqual(pkgs['@scope/name@1.0.0'], { resolution: { integrity: 'sha512-abc', tarball: 'https://x/y.tgz' }, engines: { node: '>= 0.6' }, os: ['darwin', 'linux'] });
  assert.deepEqual(pkgs['plain@2.0.0'], {});
  assert.deepEqual(doc.list, ['one', 'two']);
  assert.deepEqual(doc.nested, { items: ['a'] });
  assert.equal(doc.after, 'value');
});

test('package keys of every lockfile version parse to name and version', () => {
  assert.deepEqual(parsePackageKey('lodash@4.17.15'), { name: 'lodash', version: '4.17.15' });
  assert.deepEqual(parsePackageKey('@babel/core@7.24.0(supports-color@9.4.0)'), { name: '@babel/core', version: '7.24.0' });
  assert.deepEqual(parsePackageKey('/lodash@4.17.15'), { name: 'lodash', version: '4.17.15' });
  assert.deepEqual(parsePackageKey('/@babel/core@7.24.0(supports-color@9.4.0)'), { name: '@babel/core', version: '7.24.0' });
  assert.deepEqual(parsePackageKey('/lodash/4.17.15'), { name: 'lodash', version: '4.17.15' });
  assert.deepEqual(parsePackageKey('/@babel/core/7.24.0_supports-color@9.4.0'), { name: '@babel/core', version: '7.24.0' });
  assert.equal(parsePackageKey('github.com/user/repo/0123abc'), undefined);
  assert.equal(parsePackageKey('https://example.com/pkg.tgz'), undefined);
});

test('pnpm v9: importers, packages and snapshots, an alias, a link: workspace dependency', () => {
  const inv = readPnpmLock(PNPM_APP);
  assert.equal(inv.lockfileVersion, '9.0');
  assert.equal(inv.projectName, 'pnpm-app');
  assert.equal(inv.projectVersion, '3.1.0');
  const by = new Map(inv.components.map((c) => [c.name, c]));
  assert.ok(!by.has('@pnpm-app/shared'), 'a link: dependency is a workspace package, not a component');
  assert.deepEqual([...by.keys()].sort(), ['@types/node', 'accepts', 'ansi-styles', 'chalk', 'emoji-regex', 'express', 'fsevents', 'lodash', 'minimist', 'string-width']);

  const aliased = by.get('string-width')!;
  assert.equal(aliased.purl, 'pkg:npm/string-width@4.2.3');
  assert.equal(aliased.direct, true, 'the root importer names it as string-width-cjs');
  assert.equal(aliased.dev, false);
  assert.equal(aliased.path, 'pnpm-lock.yaml:string-width@4.2.3');
  assert.equal(by.get('emoji-regex')!.dev, false);

  assert.equal(by.get('express')!.direct, true, 'declared by the packages/web importer');
  assert.equal(by.get('accepts')!.direct, false);
  assert.equal(by.get('accepts')!.dev, false);
  assert.equal(by.get('chalk')!.dev, true, 'only a devDependency of a workspace');
  assert.equal(by.get('ansi-styles')!.dev, true);
  assert.equal(by.get('minimist')!.dev, true);
  assert.equal(by.get('fsevents')!.optional, true, 'only reachable through optionalDependencies');
  assert.equal(by.get('fsevents')!.dev, false);
  assert.equal(by.get('@types/node')!.dev, false, 'an orphan entry is kept and not called dev');
  assert.equal(by.get('@types/node')!.purl, 'pkg:npm/%40types/node@20.11.0');
});

test('pnpm v6: root dependencies without importers, /-prefixed keys, peer suffixes fold to one component', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-pnpm6-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'six', version: '1.0.0' }));
  writeFileSync(join(dir, 'pnpm-lock.yaml'), `lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  react-dom:
    specifier: ^18.2.0
    version: 18.2.0(react@18.2.0)
  string-width-cjs:
    specifier: npm:string-width@^4.2.0
    version: /string-width@4.2.3

devDependencies:
  '@types/react':
    specifier: ^18.0.0
    version: 18.2.0

packages:

  /@types/react@18.2.0:
    resolution: {integrity: sha512-types}
    dev: true

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-dom}
    peerDependencies:
      react: ^18.2.0
    dependencies:
      react: 18.2.0
      scheduler: 0.23.0
    dev: false

  /react@18.2.0:
    resolution: {integrity: sha512-react}
    dev: false

  /scheduler@0.23.0:
    resolution: {integrity: sha512-sched}
    dev: false

  /scheduler@0.23.0(react@18.2.0):
    resolution: {integrity: sha512-sched}
    dev: false

  /string-width@4.2.3:
    resolution: {integrity: sha512-sw}
    dev: false
`);
  const inv = readPnpmLock(dir);
  assert.equal(inv.lockfileVersion, '6.0');
  const by = new Map(inv.components.map((c) => [c.name, c]));
  assert.deepEqual([...by.keys()].sort(), ['@types/react', 'react', 'react-dom', 'scheduler', 'string-width']);
  assert.equal(by.get('react-dom')!.version, '18.2.0');
  assert.equal(by.get('react-dom')!.direct, true);
  assert.equal(by.get('react-dom')!.path, 'pnpm-lock.yaml:/react-dom@18.2.0(react@18.2.0)');
  assert.equal(by.get('react')!.dev, false);
  assert.equal(by.get('@types/react')!.dev, true);
  assert.equal(by.get('string-width')!.direct, true);
  assert.deepEqual(by.get('scheduler')!.paths, ['pnpm-lock.yaml:/scheduler@0.23.0', 'pnpm-lock.yaml:/scheduler@0.23.0(react@18.2.0)']);
});
