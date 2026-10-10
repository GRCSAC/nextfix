import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { findGovulncheck, frameSymbol, goIdFor, parseGovulncheckJson, projectCallSite, runGovulncheck, splitJsonObjects } from './govulncheck.ts';

const FIXTURE = join(import.meta.dirname, '..', '..', 'test-fixtures', 'go-govulncheck', 'govulncheck.json');

test('splitJsonObjects reads concatenated pretty-printed objects and skips malformed or truncated ones', () => {
  const objs = splitJsonObjects('{\n "a": "x}y{"\n}\n{"b": {"c": "\\"}"}}\n{"broken": }\n{"d": 1}\n{"truncated": {"e": 2}');
  assert.deepEqual(objs, [{ a: 'x}y{' }, { b: { c: '"}' } }, { d: 1 }]);
});

test('parseGovulncheckJson builds symbols, verdicts and aliases from a real run', () => {
  const r = parseGovulncheckJson(readFileSync(FIXTURE, 'utf8'));
  assert.equal(r.goVersion, '1.26.4');
  assert.equal(r.error, undefined);

  // OSV entries: symbols per package, under the module they belong to, deduplicated across repeats.
  const http2 = r.symbols.get('GO-2026-6617')!;
  assert.deepEqual(http2.modules, ['stdlib', 'golang.org/x/net']);
  assert.deepEqual(
    http2.packages.map((p) => `${p.module}:${p.path}`),
    ['stdlib:net/http', 'stdlib:net/http/internal/http2', 'golang.org/x/net:golang.org/x/net/http2'],
  );
  assert.ok(http2.packages[0]!.symbols.includes('Client.Do'));
  const jwt = r.symbols.get('GO-2025-3553')!;
  assert.deepEqual(jwt.packages.find((p) => p.module === 'github.com/golang-jwt/jwt/v5')?.symbols, ['Parser.ParseUnverified']);

  // Aliases map every id the advisory goes by to the GO- id.
  assert.equal(goIdFor(r, ['GHSA-mh63-6h87-95cp']), 'GO-2025-3553');
  assert.equal(goIdFor(r, ['CVE-2025-30204', 'GO-2025-3553']), 'GO-2025-3553');
  assert.equal(goIdFor(r, ['GHSA-nope']), undefined);

  // Verdicts: the deepest level any finding reached, per module.
  const called = r.verdicts.get('GO-2025-3553')!;
  assert.equal(called.level, 'called');
  assert.equal(called.byModule['github.com/golang-jwt/jwt/v5'], 'called');
  assert.deepEqual(called.packages['github.com/golang-jwt/jwt/v5'], ['github.com/golang-jwt/jwt/v5']);
  assert.equal(called.fixedVersion, 'v5.2.2');
  assert.equal(called.trace.length, 1);
  assert.equal(frameSymbol(called.trace[0]![0]!), 'Parser.ParseUnverified');
  assert.deepEqual(projectCallSite(called.trace[0]!), { file: 'common/test_helpers.go', line: 26, col: 35, caller: 'VerifyTokenClaims' });

  const imported = r.verdicts.get('GO-2026-4970')!;
  assert.equal(imported.level, 'imported');
  assert.deepEqual(imported.byModule, { stdlib: 'imported' });
  assert.deepEqual(imported.packages, { stdlib: ['os'] });
  assert.equal(imported.trace.length, 0);

  const stdlibCalled = r.verdicts.get('GO-2026-6617')!;
  assert.equal(stdlibCalled.level, 'called');
  assert.equal(stdlibCalled.byModule['stdlib'], 'called');
  assert.equal(stdlibCalled.byModule['golang.org/x/net'], 'required', 'x/net is in the module graph but none of its vulnerable packages is imported');
  assert.equal(stdlibCalled.packages['golang.org/x/net'], undefined);
  assert.equal(stdlibCalled.trace.length, 2);

  // An OSV entry without any finding has symbols but no verdict.
  assert.ok(r.symbols.has('GO-2024-2611'));
  assert.equal(r.verdicts.has('GO-2024-2611'), false);
});

test('a finding whose first frame is only a module is a required-level verdict', () => {
  const r = parseGovulncheckJson('{"finding": {"osv": "GO-2020-0001", "fixed_version": "v1.2.3", "trace": [{"module": "github.com/a/b", "version": "v1.0.0"}]}}');
  assert.deepEqual(r.verdicts.get('GO-2020-0001'), { level: 'required', trace: [], module: 'github.com/a/b', byModule: { 'github.com/a/b': 'required' }, packages: {}, fixedVersion: 'v1.2.3' });
});

test('runGovulncheck reports a missing binary as an error and keeps the maps empty', async () => {
  const r = await runGovulncheck(process.cwd(), { binary: 'definitely-not-govulncheck', pathEnv: '' });
  assert.match(r.error ?? '', /not installed/);
  assert.equal(r.verdicts.size, 0);
  assert.equal(r.symbols.size, 0);
  assert.equal(findGovulncheck({ binary: 'definitely-not-govulncheck', pathEnv: '' }), undefined);
});
