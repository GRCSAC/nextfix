import { test } from 'node:test';
import assert from 'node:assert/strict';
import { asList, validateConfig } from './config.ts';

test('config: well-formed settings pass through', () => {
  const cfg = validateConfig({ authGuards: ['checkSession'], ignore: ['scripts'], internalRoutes: ['GET /healthz'], image: 'ghcr.io/x/y:1', sbom: ['a.cdx.json'], syft: 'docker', authGuardsReplace: false });
  assert.deepEqual(asList(cfg.image), ['ghcr.io/x/y:1']);
  assert.deepEqual(asList(cfg.sbom), ['a.cdx.json']);
  assert.deepEqual(validateConfig({}), {});
});

test('config: the first wrong shape is named in plain words', () => {
  assert.throws(() => validateConfig({ authGuards: 'x' }), /"authGuards" must be a list of strings/);
  assert.throws(() => validateConfig({ image: 3 }), /"image" must be a string or a list of strings/);
  assert.throws(() => validateConfig({ authGuardsReplace: 'yes' }), /true or false/);
  assert.throws(() => validateConfig({ syft: ['a'] }), /"syft" must be a string/);
  assert.throws(() => validateConfig({ ignored: ['x'] }), /unknown setting "ignored"/);
  assert.throws(() => validateConfig([]), /JSON object/);
  assert.throws(() => validateConfig(null), /JSON object/);
});
