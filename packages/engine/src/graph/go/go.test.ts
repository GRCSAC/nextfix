import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeGoProject } from './project.ts';
import { parseGoMod, readGoModules } from './gomod.ts';
import { assessReach } from '../../reach/reachability.ts';
import type { Component } from '../../types.ts';

const FX = (name: string) => fileURLToPath(new URL(`../../../test-fixtures/${name}/`, import.meta.url));
const comp = (name: string): Component => ({ ecosystem: 'Go', name, version: '1.0.0', purl: `pkg:golang/${name}@1.0.0`, dev: false, optional: false, direct: true, path: 'go.mod' });
const sym = (pkg: string, symbols: string[]) => ({ ids: ['X'], ecosystem: 'Go' as const, package: pkg, symbols, source: 'curated' as const, confidence: 'confirmed' as const });
const installedOf = (dir: string) => new Set(readGoModules(dir).flatMap((m) => m.requires.map((r) => r.path)));
const label = (p: { entry: { method: string; path: string; authenticated: boolean }; userInput: boolean; inputSource?: string }) => `${p.entry.method} ${p.entry.path}${p.entry.authenticated ? ' [auth]' : ''}${p.userInput ? ' <' + p.inputSource + '>' : ''}`;
const eps = (g: { entryPoints: { method: string; path: string; authenticated: boolean; unresolvedHandlers?: string[] }[] }) => g.entryPoints.map((e) => `${e.method} ${e.path}${e.authenticated ? ' [auth]' : ''}${e.unresolvedHandlers ? ' ?' : ''}`).sort();

test('go.mod: module path and require block', () => {
  const m = parseGoMod(readFileSync(join(FX('go-chi'), 'go.mod'), 'utf8'))!;
  assert.equal(m.path, 'example.com/chiapp');
  assert.deepEqual(m.requires.map((r) => `${r.path}@${r.version}`), ['github.com/go-chi/chi/v5@v5.0.12', 'github.com/go-chi/jwtauth/v5@v5.3.0', 'gopkg.in/yaml.v2@v2.2.8']);
  const single = parseGoMod('module x\n\nrequire github.com/a/b v1.2.3 // indirect\n')!;
  assert.deepEqual(single.requires, [{ path: 'github.com/a/b', version: 'v1.2.3', indirect: true }]);
});

test('net/http: ServeMux patterns, wrapper middleware by name and by body, loopback listen', async () => {
  const g = await analyzeGoProject(FX('go-nethttp'), { installed: installedOf(FX('go-nethttp')) });
  assert.deepEqual(eps(g), ['ANY /admin/export [auth]', 'ANY /admin/import [auth]', 'ANY /health', 'ANY /metrics ?', 'POST /config']);
  const imp = g.entryPoints.find((e) => e.path === '/admin/import')!;
  assert.deepEqual(imp.guards, ['auth.Required']);
  const exp = g.entryPoints.find((e) => e.path === '/admin/export')!;
  assert.deepEqual(exp.guards, ['auth.Gate'], 'Gate is a guard because its body writes 403');
  assert.equal(g.entryPoints.find((e) => e.path === '/metrics')!.unresolvedHandlers![0], 'http.NotFoundHandler()');
  assert.ok(g.entryPoints.every((e) => e.mounted));
  assert.equal(g.listenLocalOnly, true);
  assert.deepEqual([...g.packagesImported.keys()].sort(), ['github.com/BurntSushi/toml', 'gopkg.in/yaml.v2', 'stdlib']);

  // yaml.Unmarshal: called from Config (via parse) and from the dead function; only one path
  const yaml = assessReach(g, comp('gopkg.in/yaml.v2'), sym('gopkg.in/yaml.v2', ['Unmarshal']));
  assert.equal(yaml.tier, 'reachable');
  assert.equal(yaml.callSites.length, 2);
  assert.deepEqual(yaml.paths.map(label), ['POST /config <io.ReadAll(r.Body)>']);
  assert.deepEqual(yaml.paths[0]!.hops.map((h) => h.name), ['Config', 'parse']);
  const toml = assessReach(g, comp('github.com/BurntSushi/toml'), sym('github.com/BurntSushi/toml', ['Decode']));
  assert.deepEqual(toml.paths.map(label), ['ANY /admin/import [auth] <r.FormValue("doc")>']);
  // Marshal is called (Export) but not with request data
  const marshal = assessReach(g, comp('gopkg.in/yaml.v2'), sym('gopkg.in/yaml.v2', ['Marshal']));
  assert.deepEqual(marshal.paths.map(label), ['ANY /admin/export [auth]']);
});

test('gin: groups with prefixes, Use applies to later registrations, router passed to another package, interface call', async () => {
  const g = await analyzeGoProject(FX('go-gin'), { installed: installedOf(FX('go-gin')) });
  assert.deepEqual(eps(g), ['DELETE /api/admin/users/:id [auth]', 'GET /api/me [auth]', 'GET /api/ping', 'GET /api/users/:id', 'POST /api/render']);
  assert.deepEqual(g.entryPoints.find((e) => e.path === '/api/admin/users/:id')!.guards, ['middleware.JWTAuth()']);
  assert.deepEqual(g.entryPoints.find((e) => e.path === '/api/me')!.guards, ['middleware.RequireLogin()']);
  assert.equal(g.entryPoints.find((e) => e.path === '/api/ping')!.guards.length, 0, 'gin.Logger() is not a guard');
  assert.equal(g.listenLocalOnly, false);

  const yaml = assessReach(g, comp('gopkg.in/yaml.v3'), sym('gopkg.in/yaml.v3', ['Unmarshal']));
  assert.equal(yaml.tier, 'reachable');
  assert.deepEqual(yaml.paths.map(label).sort(), ['DELETE /api/admin/users/:id [auth] <c.Param("id")>', 'GET /api/users/:id <c.Query("doc")>', 'POST /api/render <c.ShouldBindJSON(&req)>']);
  const viaStore = yaml.paths.find((p) => p.entry.path === '/api/users/:id')!;
  assert.deepEqual(viaStore.hops.map((h) => h.name), ['Show', 'Load'], 'store.Load resolves through the Store interface to yamlStore.Load');
  // the gin component itself: every handler calls into it
  const gin = assessReach(g, comp('github.com/gin-gonic/gin'), sym('github.com/gin-gonic/gin', ['Context.ShouldBindJSON']));
  assert.deepEqual(gin.paths.map(label), ['POST /api/render <c.ShouldBindJSON(&req)>']);
});

test('chi: Route/Group literals, With, Mount of a returned router, jwtauth guards', async () => {
  const g = await analyzeGoProject(FX('go-chi'), { installed: installedOf(FX('go-chi')) });
  assert.deepEqual(eps(g), ['DELETE /users/{id} [auth]', 'GET /', 'GET /admin/export [auth]', 'GET /api/items [auth]', 'GET /api/public', 'POST /parse']);
  assert.deepEqual(g.entryPoints.find((e) => e.path === '/admin/export')!.guards, ['jwtauth.Verifier(tokenAuth)', 'jwtauth.Authenticator(tokenAuth)']);
  assert.deepEqual(g.entryPoints.find((e) => e.path === '/api/items')!.guards, ['requireKey']);
  assert.deepEqual(g.entryPoints.find((e) => e.path === '/users/{id}')!.guards, ['adminOnly']);
  assert.ok(g.entryPoints.every((e) => e.mounted));

  const yaml = assessReach(g, comp('gopkg.in/yaml.v2'), sym('gopkg.in/yaml.v2', ['Unmarshal']));
  assert.equal(yaml.tier, 'reachable');
  assert.deepEqual(yaml.paths.map(label).sort(), ['GET /admin/export [auth]', 'GET /api/items [auth] <r.URL.Query().Get("filter")>', 'POST /parse <json.NewDecoder(r.Body)>']);
  const unused = assessReach(g, comp('github.com/go-chi/jwtauth/v5'), sym('github.com/go-chi/jwtauth/v5', ['FromContext']));
  assert.equal(unused.tier, 'imported-not-called');
});

test('go: ignore list and internalRoutes', async () => {
  const g = await analyzeGoProject(FX('go-chi'), { installed: installedOf(FX('go-chi')), ignore: ['api'], internalRoutes: ['GET /'] });
  assert.deepEqual(eps(g), ['DELETE /users/{id} [auth]', 'GET / [auth]', 'GET /admin/export [auth]', 'POST /parse']);
  assert.deepEqual(g.entryPoints.find((e) => e.path === '/')!.guards, ['internal (nextfix.config.json)']);
});
