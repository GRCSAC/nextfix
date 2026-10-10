import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fullGoVersion, hasGoProject, parseGoMod, parseGoSum, readGoDeps } from './go.ts';

const FIXTURE = join(import.meta.dirname, '..', '..', 'test-fixtures', 'go-app');

test('hasGoProject looks for go.mod at the root', () => {
  assert.equal(hasGoProject(FIXTURE), true);
  assert.equal(hasGoProject(join(FIXTURE, '..')), false);
});

test('parseGoMod reads module, go, require blocks, replace and exclude', () => {
  const mod = parseGoMod(`module "github.com/example/quoted"

go 1.22.3
toolchain go1.23.1

require github.com/a/b v1.0.0 // indirect
require (
	github.com/c/d v2.0.0+incompatible
	github.com/e/f v0.0.0-20200128174031-69ecbb4d6d5d // indirect; kept for go 1.16
)
replace github.com/c/d v2.0.0+incompatible => github.com/c/d-fork v2.1.0
replace github.com/local/x => ./x
exclude github.com/a/b v0.9.0
retract v1.0.1
`);
  assert.equal(mod.module, 'github.com/example/quoted');
  assert.equal(mod.go, '1.22.3');
  assert.equal(mod.toolchain, '1.23.1');
  assert.deepEqual(mod.requires, [
    { path: 'github.com/a/b', version: 'v1.0.0', indirect: true },
    { path: 'github.com/c/d', version: 'v2.0.0+incompatible', indirect: false },
    { path: 'github.com/e/f', version: 'v0.0.0-20200128174031-69ecbb4d6d5d', indirect: true },
  ]);
  assert.deepEqual(mod.replaces, [
    { oldPath: 'github.com/c/d', oldVersion: 'v2.0.0+incompatible', newPath: 'github.com/c/d-fork', newVersion: 'v2.1.0' },
    { oldPath: 'github.com/local/x', oldVersion: undefined, newPath: './x', newVersion: undefined },
  ]);
  assert.deepEqual(mod.excludes, [{ path: 'github.com/a/b', version: 'v0.9.0' }]);
});

test('parseGoSum lists each module@version once and skips /go.mod lines', () => {
  const sum = parseGoSum(`github.com/a/b v1.0.0 h1:abc=
github.com/a/b v1.0.0/go.mod h1:def=
github.com/a/b v1.0.0 h1:abc=
github.com/c/d v2.0.0 h1:ghi=
`);
  assert.deepEqual(sum, [
    { path: 'github.com/a/b', version: 'v1.0.0' },
    { path: 'github.com/c/d', version: 'v2.0.0' },
  ]);
});

test('fullGoVersion pads the go directive to three parts', () => {
  assert.equal(fullGoVersion('1.21'), '1.21.0');
  assert.equal(fullGoVersion('1.22.3'), '1.22.3');
  assert.equal(fullGoVersion('go1.23rc1'), '1.23.0rc1');
});

test('readGoDeps inventories go.mod and go.sum with replace, exclude and indirect applied', () => {
  const inv = readGoDeps(FIXTURE);
  assert.equal(inv.module, 'github.com/example/go-app');
  assert.equal(inv.goVersion, '1.21.0');
  assert.deepEqual(inv.sources, ['go.mod', 'go.sum']);
  assert.deepEqual(inv.localReplacements, ['github.com/example/local']);

  const byName = new Map(inv.components.map((c) => [c.name, c]));
  assert.deepEqual(
    [...byName.keys()].sort(),
    ['github.com/gin-contrib/sse', 'github.com/gin-gonic/gin', 'github.com/golang-jwt/jwt/v5', 'github.com/stretchr/testify', 'golang.org/x/crypto', 'golang.org/x/net', 'google.golang.org/protobuf', 'stdlib'],
  );
  for (const c of inv.components) {
    assert.equal(c.ecosystem, 'Go');
    assert.equal(c.dev, false);
    assert.equal(c.purl, `pkg:golang/${c.name}@${c.version}`);
  }

  const gin = byName.get('github.com/gin-gonic/gin')!;
  assert.equal(gin.version, 'v1.10.0', 'the go.mod version, not the superseded go.sum line');
  assert.equal(gin.direct, true);
  assert.equal(gin.path, 'go.mod');
  assert.equal(inv.components.filter((c) => c.name === 'github.com/gin-gonic/gin').length, 1);

  const jwt = byName.get('github.com/golang-jwt/jwt/v5')!;
  assert.equal(jwt.direct, true, 'a comment that is not "indirect" leaves the require direct');
  assert.equal(jwt.version, 'v5.2.1');

  assert.equal(byName.get('github.com/gin-contrib/sse')!.direct, false);
  assert.equal(byName.get('golang.org/x/net')!.version, 'v0.35.0', 'replace applied');

  const testify = byName.get('github.com/stretchr/testify')!;
  assert.equal(testify.direct, false);
  assert.equal(testify.path, 'go.sum');

  const std = byName.get('stdlib')!;
  assert.equal(std.version, '1.21.0');
  assert.equal(std.purl, 'pkg:golang/stdlib@1.21.0');
  assert.equal(byName.has('github.com/example/local'), false, 'a directory replacement is not a registry module');
});
