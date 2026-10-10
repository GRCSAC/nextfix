import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readNpmLock } from './npm-lock.ts';

test('npm aliases are inventoried under the real package name', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-lock-'));
  const lock = {
    name: 'app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0', dependencies: { cliui: '8.0.1', 'string-width-cjs': 'npm:string-width@4.2.3' } },
      'node_modules/cliui': { version: '8.0.1' },
      'node_modules/string-width-cjs': { name: 'string-width', version: '4.2.3' },
      'node_modules/string-width': { version: '5.1.2' },
    },
  };
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(lock));
  const inv = readNpmLock(dir);
  const names = inv.components.map((c) => `${c.name}@${c.version}`).sort();
  assert.deepEqual(names, ['cliui@8.0.1', 'string-width@4.2.3', 'string-width@5.1.2']);
  const aliased = inv.components.find((c) => c.version === '4.2.3')!;
  assert.equal(aliased.purl, 'pkg:npm/string-width@4.2.3', 'queried as the real package');
  assert.equal(aliased.path, 'node_modules/string-width-cjs', 'the alias stays as the location');
  assert.equal(aliased.direct, true, 'direct-ness follows the alias the manifest names');
});
