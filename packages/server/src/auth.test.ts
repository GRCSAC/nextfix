import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { Store } from './store.ts';
import { createNextFixServer, type Route } from './server.ts';
import { hashPassword, verifyPassword, lockedUntil, LOCKOUT_ATTEMPTS } from './auth/local.ts';
import { isLoopbackAddress, parseCookies, SESSION_IDLE_MS, SESSION_ABSOLUTE_MS } from './auth/sessions.ts';
import { scrubDetail } from './auth/audit.ts';
import { matchPattern, roleForScopes } from './auth/roles.ts';
import { checkClaims, mapRole, normalizeOidcSettings, resetOidcCache, type OidcProvider } from './auth/oidc.ts';

type Json = Record<string, unknown>;

/** Fail with the response body only when the status is wrong, so the body stays readable afterwards. */
async function expectStatus(res: Response, status: number): Promise<void> {
  if (res.status !== status) assert.fail(`expected ${status}, got ${res.status}: ${(await res.text()).slice(0, 300)}`);
}

/** fetch drops a custom Host header, so requests that need one go through node:http. */
function rawGet(host: string, port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host, port, path, method: 'GET', headers: { host: 'localhost' }, setHost: false, timeout: 2000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString() }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

function listen(server: Server, host = '127.0.0.1'): Promise<number> {
  return new Promise((resolve) => server.listen(0, host, () => resolve((server.address() as { port: number }).port)));
}

/** A server on a fresh temp database plus a cookie-aware request helper. */
async function fixture(opts: { allowOpen?: boolean; secureCookies?: boolean; routes?: Route[]; host?: string } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-auth-'));
  const dbPath = join(dir, 'test.sqlite');
  const store = new Store(dbPath);
  const app = createNextFixServer({ store, staticDir: dir, allowOpen: opts.allowOpen, secureCookies: opts.secureCookies, routes: opts.routes, host: opts.host });
  const port = await listen(app, opts.host);
  const base = `http://127.0.0.1:${port}`;
  const api = (path: string, init: RequestInit = {}, headers: Record<string, string> = {}) => fetch(`${base}${path}`, { redirect: 'manual', ...init, headers: { 'content-type': 'application/json', ...headers } });
  /** The session cookie a response set, as a Cookie header value. */
  const cookieOf = (res: Response) => {
    const set = res.headers.getSetCookie().map((c) => c.split(';')[0]!).find((c) => c.startsWith('nextfix_session='));
    assert.ok(set, 'a session cookie was set');
    return set;
  };
  const withCookie = (cookie: string) => ({ cookie });
  const setup = async (username = 'root', password = 'correct horse battery') => {
    const res = await api('/api/setup', { method: 'POST', body: JSON.stringify({ username, password, displayName: 'Root' }) });
    await expectStatus(res, 201);
    return cookieOf(res);
  };
  const login = async (username: string, password: string) => {
    const res = await api('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    await expectStatus(res, 200);
    return cookieOf(res);
  };
  const addUser = async (admin: string, username: string, role: string, password = 'another good password') => {
    const res = await api('/api/users', { method: 'POST', body: JSON.stringify({ username, password, role }) }, withCookie(admin));
    await expectStatus(res, 201);
    return (await res.json()) as { id: number; username: string; role: string };
  };
  const close = () => {
    app.close();
    store.close();
  };
  return { dir, dbPath, store, app, port, base, api, cookieOf, withCookie, setup, login, addUser, close };
}

test('unit: passwords, cookies, loopback, patterns, scrubbing', async () => {
  const h = await hashPassword('hunter22hunter22');
  assert.match(h, /^scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.equal(await verifyPassword('hunter22hunter22', h), true);
  assert.equal(await verifyPassword('hunter22hunter23', h), false);
  assert.equal(await verifyPassword('anything', null), false, 'a user without a password never verifies');
  assert.equal(await verifyPassword('anything', 'bcrypt$nope'), false);
  assert.notEqual(await hashPassword('same'), await hashPassword('same'), 'salts differ');

  assert.deepEqual(parseCookies('a=1; nextfix_session=abc.def ; b'), { a: '1', nextfix_session: 'abc.def' });
  for (const ip of ['127.0.0.1', '::1', '::ffff:127.0.0.1', '127.9.9.9']) assert.equal(isLoopbackAddress(ip), true, ip);
  for (const ip of ['10.0.0.1', '192.168.1.5', '::ffff:10.0.0.1', '', '127.0.0.1.evil']) assert.equal(isLoopbackAddress(ip), false, ip);

  assert.deepEqual(matchPattern('/targets/:id/scan', ['targets', '4', 'scan']), { id: '4' });
  assert.equal(matchPattern('/targets/:id/scan', ['targets', '4']), undefined);
  assert.equal(matchPattern('/targets', ['targets', '4']), undefined);
  assert.deepEqual(matchPattern('/scans/:id/findings/*', ['scans', '1', 'findings', 'pkg:npm', 'x']), { id: '1', '*': 'pkg:npm/x' });
  assert.equal(roleForScopes(['read']), 'viewer');
  assert.equal(roleForScopes(['read', 'tickets']), 'analyst');

  assert.deepEqual(scrubDetail({ username: 'a', password: 'p', nested: { apiToken: 't', ok: 1 }, list: ['x'.repeat(600)] }), { username: 'a', nested: { ok: 1 }, list: [`${'x'.repeat(500)}…`] });
});

test('setup: open on loopback until the first admin exists, then every route needs a session', async () => {
  const f = await fixture();
  try {
    assert.deepEqual(await (await f.api('/api/session')).json(), { setupRequired: true, authMode: 'none' });
    assert.equal((await f.api('/api/targets')).status, 200, 'open before setup');
    assert.equal(((await (await f.api('/api/health')).json()) as Json).authMode, 'none');
    assert.equal((await f.api('/api/setup', { method: 'POST', body: JSON.stringify({ username: 'root', password: 'short' }) })).status, 400, 'password rules apply');
    assert.equal((await f.api('/api/setup', { method: 'POST', body: JSON.stringify({ username: 'bad name!', password: 'long enough password' }) })).status, 400);

    const res = await f.api('/api/setup', { method: 'POST', body: JSON.stringify({ username: 'Root', password: 'correct horse battery', displayName: 'Root' }) });
    assert.equal(res.status, 201);
    const body = (await res.json()) as { user: Json };
    assert.deepEqual(body.user, { id: 1, username: 'root', displayName: 'Root', role: 'admin' }, 'usernames are lowercased');
    const setCookie = res.headers.getSetCookie()[0]!;
    assert.match(setCookie, /^nextfix_session=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=604800$/, setCookie);
    const cookie = f.cookieOf(res);
    const raw = cookie.split('=')[1]!;
    const stored = f.store.getSession(createHash('sha256').update(raw).digest('hex'));
    assert.ok(stored, 'the session is stored under its sha256');
    assert.equal(stored.userId, 1);
    assert.equal(stored.ip, '127.0.0.1');

    assert.equal((await f.api('/api/setup', { method: 'POST', body: JSON.stringify({ username: 'again', password: 'correct horse battery' }) })).status, 409, 'setup runs once');
    const session = (await (await f.api('/api/session', {}, f.withCookie(cookie))).json()) as Json;
    assert.deepEqual(session, { setupRequired: false, authMode: 'local', user: { id: 1, username: 'root', displayName: 'Root', role: 'admin' } });
    assert.deepEqual(await (await f.api('/api/session')).json(), { setupRequired: false, authMode: 'local' }, 'no cookie, no user');

    // everything else now needs a session; public routes and static files do not
    const r401 = await f.api('/api/targets');
    assert.equal(r401.status, 401);
    assert.equal(((await r401.json()) as Json).error, 'Sign in to use this');
    assert.equal((await f.api('/api/targets', {}, f.withCookie('nextfix_session=forged'))).status, 401);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(cookie))).status, 200);
    assert.equal((await fetch(`${f.base}/`)).status, 200, 'the SPA is public');
    assert.equal((await f.api('/api/health')).status, 200);
    assert.equal(((await (await f.api('/api/health')).json()) as Json).authMode, 'local');
    assert.equal((await f.api('/api/nope')).status, 404, 'unknown paths are 404 even without a session');

    // sign in and out
    const wrong = await f.api('/api/login', { method: 'POST', body: JSON.stringify({ username: 'root', password: 'correct horse batter' }) });
    assert.equal(wrong.status, 401);
    assert.equal(((await wrong.json()) as Json).error, 'Wrong username or password');
    assert.equal((await f.api('/api/login', { method: 'POST', body: JSON.stringify({ username: 'nobody', password: 'correct horse battery' }) })).status, 401);
    const cookie2 = await f.login('ROOT', 'correct horse battery');
    assert.notEqual(cookie2, cookie);
    const out = await f.api('/api/logout', { method: 'POST' }, f.withCookie(cookie2));
    assert.equal(out.status, 204);
    assert.match(out.headers.getSetCookie()[0]!, /^nextfix_session=; Path=\/; HttpOnly; SameSite=Lax; Max-Age=0$/);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(cookie2))).status, 401, 'the session is gone');
    assert.equal((await f.api('/api/targets', {}, f.withCookie(cookie))).status, 200, 'other sessions live on');
    assert.equal((await f.api('/api/logout', { method: 'POST' })).status, 204, 'logout without a session is fine');
  } finally {
    f.close();
  }
});

test('loopback rule: before setup, other machines are refused', async () => {
  const lan = Object.values(networkInterfaces()).flat().find((i) => i && i.family === 'IPv4' && !i.internal)?.address;
  const f = await fixture({ host: '0.0.0.0' });
  try {
    assert.equal((await f.api('/api/session')).status, 200, 'loopback is fine');
    if (!lan) {
      test.skip?.('no LAN address on this machine');
      return;
    }
    let remote: { status: number; body: string };
    try {
      remote = await rawGet(lan, f.port, '/api/session');
    } catch {
      return; // the address is not reachable from itself here; nothing to assert
    }
    assert.equal(remote.status, 403, remote.body);
    assert.match((JSON.parse(remote.body) as Json).error as string, /no accounts yet/);
    assert.equal((await rawGet(lan, f.port, '/')).status, 403, 'static files too');
    await f.setup();
    const after = await rawGet(lan, f.port, '/api/session');
    assert.equal(after.status, 200, 'with accounts, other machines may sign in');
    assert.equal((JSON.parse(after.body) as Json).setupRequired, false);
  } finally {
    f.close();
  }
});

test('sessions: idle and absolute expiry, disabled users lose theirs, last_seen is touched sparingly', async () => {
  const f = await fixture();
  try {
    const cookie = await f.setup();
    const hash = createHash('sha256').update(cookie.split('=')[1]!).digest('hex');
    const db = new DatabaseSync(f.dbPath);
    const setSeen = (ms: number) => db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(new Date(Date.now() - ms).toISOString(), hash);
    setSeen(2 * 60_000);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(cookie))).status, 200);
    const seen = f.store.getSession(hash)!.lastSeenAt;
    assert.ok(Date.now() - Date.parse(seen) < 5000, 'a request after a minute refreshes last_seen_at');
    setSeen(SESSION_IDLE_MS + 1000);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(cookie))).status, 401, 'idle for 12 h: gone');
    assert.equal(f.store.getSession(hash), undefined, 'and deleted');

    const cookie2 = await f.login('root', 'correct horse battery');
    const hash2 = createHash('sha256').update(cookie2.split('=')[1]!).digest('hex');
    assert.ok(Date.parse(f.store.getSession(hash2)!.expiresAt) - Date.now() > SESSION_ABSOLUTE_MS - 5000, '7-day absolute expiry');
    db.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), hash2);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(cookie2))).status, 401, 'past the absolute limit: gone');

    const admin = await f.login('root', 'correct horse battery');
    const bob = await f.addUser(admin, 'bob', 'viewer');
    const bobCookie = await f.login('bob', 'another good password');
    assert.equal((await f.api('/api/targets', {}, f.withCookie(bobCookie))).status, 200);
    assert.equal((await f.api(`/api/users/${bob.id}`, { method: 'PATCH', body: JSON.stringify({ disabled: true }) }, f.withCookie(admin))).status, 200);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(bobCookie))).status, 401, 'disabling ends the session');
    const disabledLogin = await f.api('/api/login', { method: 'POST', body: JSON.stringify({ username: 'bob', password: 'another good password' }) });
    assert.equal(disabledLogin.status, 403);
    assert.equal(((await disabledLogin.json()) as Json).error, 'This account is disabled');
    db.close();
  } finally {
    f.close();
  }
});

test('lockout: five wrong passwords lock the name for fifteen minutes, with Retry-After', async () => {
  const f = await fixture();
  try {
    await f.setup();
    const attempt = (password: string) => f.api('/api/login', { method: 'POST', body: JSON.stringify({ username: 'Root', password }) });
    for (let i = 0; i < LOCKOUT_ATTEMPTS; i++) assert.equal((await attempt('wrong password here')).status, 401);
    const locked = await attempt('wrong password here');
    assert.equal(locked.status, 429);
    const retry = Number(locked.headers.get('retry-after'));
    assert.ok(retry > 14 * 60 && retry <= 15 * 60, `retry-after ${retry}`);
    assert.match(((await locked.json()) as Json).error as string, /Too many failed sign-ins/);
    assert.equal((await attempt('correct horse battery')).status, 429, 'the right password does not unlock it');
    assert.equal((await f.api('/api/login', { method: 'POST', body: JSON.stringify({ username: 'other', password: 'x'.repeat(10) }) })).status, 401, 'other names are not locked');
    assert.ok(lockedUntil(f.store, 'root'));
    assert.equal(lockedUntil(f.store, 'root', Date.now() + 16 * 60_000), undefined, 'lifts after fifteen minutes');
    // age the failures and sign in; success clears the counter
    const db = new DatabaseSync(f.dbPath);
    db.prepare('UPDATE login_failures SET at = ?').run(new Date(Date.now() - 16 * 60_000).toISOString());
    db.close();
    assert.equal((await attempt('correct horse battery')).status, 200);
    assert.deepEqual(f.store.loginFailures('root', new Date(0).toISOString()), []);
  } finally {
    f.close();
  }
});

test('role matrix: viewer reads, analyst scans and files tickets, admin manages; tokens by scope', async () => {
  const f = await fixture();
  try {
    const admin = await f.setup();
    await f.addUser(admin, 'ana', 'analyst');
    await f.addUser(admin, 'vic', 'viewer');
    const analyst = await f.login('ana', 'another good password');
    const viewer = await f.login('vic', 'another good password');
    const mk = async (scopes: string[]) => {
      const r = await f.api('/api/tokens', { method: 'POST', body: JSON.stringify({ name: scopes.join('+'), scopes }) }, f.withCookie(admin));
      assert.equal(r.status, 201);
      return ((await r.json()) as { token: string }).token;
    };
    const readToken = await mk(['read']);
    const scanToken = await mk(['scan']);
    const ticketToken = await mk(['tickets']);
    const target = f.store.upsertTarget('C:/x/matrix', 'matrix');

    type Row = { method: string; path: string; body?: unknown; role: 'viewer' | 'analyst' | 'admin'; scope?: 'read' | 'scan' | 'tickets' };
    const rows: Row[] = [
      { method: 'GET', path: '/api/scan/progress', role: 'viewer', scope: 'read' },
      { method: 'DELETE', path: '/api/scan', role: 'analyst', scope: 'scan' },
      { method: 'GET', path: '/api/settings', role: 'viewer', scope: 'read' },
      { method: 'PUT', path: '/api/settings', body: {}, role: 'admin' },
      { method: 'GET', path: '/api/settings/oidc', role: 'admin' },
      { method: 'PUT', path: '/api/settings/oidc', body: { providers: [] }, role: 'admin' },
      { method: 'GET', path: '/api/targets', role: 'viewer', scope: 'read' },
      { method: 'POST', path: '/api/targets', body: { dir: 'C:/definitely/missing' }, role: 'analyst', scope: 'scan' },
      { method: 'DELETE', path: '/api/targets/999', role: 'admin' },
      { method: 'POST', path: '/api/targets/999/scan', role: 'analyst', scope: 'scan' },
      { method: 'GET', path: `/api/targets/${target.id}/scans`, role: 'viewer', scope: 'read' },
      { method: 'GET', path: `/api/targets/${target.id}/history`, role: 'viewer', scope: 'read' },
      { method: 'POST', path: '/api/targets/999/redecide', role: 'analyst', scope: 'scan' },
      { method: 'GET', path: `/api/targets/${target.id}/tickets`, role: 'viewer', scope: 'read' },
      { method: 'POST', path: `/api/targets/${target.id}/tickets`, body: { kind: 'nope' }, role: 'analyst', scope: 'tickets' },
      { method: 'GET', path: '/api/integrations', role: 'viewer', scope: 'read' },
      { method: 'PUT', path: '/api/integrations/github', body: {}, role: 'admin' },
      { method: 'DELETE', path: '/api/integrations/github', role: 'admin' },
      { method: 'POST', path: '/api/integrations/github/test', role: 'admin' },
      { method: 'GET', path: '/api/scans/999', role: 'viewer', scope: 'read' },
      { method: 'GET', path: '/api/scans/999/json', role: 'viewer', scope: 'read' },
      { method: 'GET', path: '/api/scans/999/findings/x', role: 'viewer', scope: 'read' },
      { method: 'GET', path: '/api/scans/999/diff', role: 'viewer', scope: 'read' },
      { method: 'GET', path: '/api/scans/999/vex', role: 'viewer', scope: 'read' },
      { method: 'GET', path: '/api/users', role: 'admin' },
      { method: 'POST', path: '/api/users', body: {}, role: 'admin' },
      { method: 'PATCH', path: '/api/users/999', body: {}, role: 'admin' },
      { method: 'DELETE', path: '/api/users/999', role: 'admin' },
      { method: 'GET', path: '/api/tokens', role: 'admin' },
      { method: 'POST', path: '/api/tokens', body: {}, role: 'admin' },
      { method: 'DELETE', path: '/api/tokens/999', role: 'admin' },
      { method: 'GET', path: '/api/audit', role: 'admin' },
    ];
    const rank = { viewer: 0, analyst: 1, admin: 2 };
    const call = (row: Row, headers: Record<string, string>) => f.api(row.path, { method: row.method, body: row.body === undefined ? undefined : JSON.stringify(row.body) }, headers);
    for (const row of rows) {
      const label = `${row.method} ${row.path}`;
      assert.equal((await call(row, {})).status, 401, `${label}: anonymous`);
      for (const [name, cookie, role] of [['viewer', viewer, 'viewer'], ['analyst', analyst, 'analyst'], ['admin', admin, 'admin']] as const) {
        const res = await call(row, f.withCookie(cookie));
        if (rank[role] >= rank[row.role]) assert.ok(res.status !== 401 && res.status !== 403, `${label}: ${name} should be allowed, got ${res.status}`);
        else {
          assert.equal(res.status, 403, `${label}: ${name} should be refused`);
          assert.match(((await res.json()) as Json).error as string, new RegExp(`needs the ${row.role} role`));
        }
      }
      for (const [scope, token] of [['read', readToken], ['scan', scanToken], ['tickets', ticketToken]] as const) {
        const res = await call(row, { authorization: `Bearer ${token}` });
        if (row.scope === scope) assert.ok(res.status !== 401 && res.status !== 403, `${label}: ${scope} token should be allowed, got ${res.status}`);
        else assert.equal(res.status, 403, `${label}: ${scope} token should be refused`);
      }
    }
    // tokens are never admins, and a bad token is refused outright
    assert.equal((await f.api('/api/users', {}, { authorization: `Bearer ${readToken}` })).status, 403);
    assert.equal((await f.api('/api/targets', {}, { authorization: 'Bearer nfx_' + 'a'.repeat(40) })).status, 401);
    assert.equal((await f.api('/api/targets', {}, { authorization: 'Bearer not-a-token' })).status, 401);
    assert.equal((await f.api('/api/targets', {}, { authorization: `Bearer ${readToken}`, cookie: admin })).status, 200);
    assert.equal((await f.api('/api/users', {}, { authorization: `Bearer ${readToken}`, cookie: admin })).status, 403, 'a bearer token wins over a cookie');
    // the password route: self with the current password, admin for others, nobody else
    const vic = f.store.getUserByUsername('vic')!;
    const ana = f.store.getUserByUsername('ana')!;
    assert.equal((await f.api(`/api/users/${vic.id}/password`, { method: 'POST', body: JSON.stringify({ password: 'a brand new password' }) }, f.withCookie(analyst))).status, 403, 'an analyst cannot reset others');
    assert.equal((await f.api(`/api/users/${vic.id}/password`, { method: 'POST', body: JSON.stringify({ password: 'a brand new password' }) }, f.withCookie(viewer))).status, 403, 'self needs the current password');
    assert.equal((await f.api(`/api/users/${vic.id}/password`, { method: 'POST', body: JSON.stringify({ currentPassword: 'another good password', password: 'a brand new password' }) }, f.withCookie(viewer))).status, 204);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(viewer))).status, 200, 'own session survives a self change');
    await f.login('vic', 'a brand new password');
    assert.equal((await f.api(`/api/users/${ana.id}/password`, { method: 'POST', body: JSON.stringify({ password: 'reset by the admin' }) }, f.withCookie(admin))).status, 204);
    assert.equal((await f.api('/api/targets', {}, f.withCookie(analyst))).status, 401, 'an admin reset ends the sessions');
    await f.login('ana', 'reset by the admin');
    assert.equal((await f.api(`/api/users/${ana.id}/password`, { method: 'POST', body: JSON.stringify({ password: 'x' }) }, { authorization: `Bearer ${readToken}` })).status, 403, 'tokens never change passwords');
  } finally {
    f.close();
  }
});

test('users: last enabled admin cannot be demoted, disabled or deleted; no self-delete', async () => {
  const f = await fixture();
  try {
    const admin = await f.setup();
    const list = (await (await f.api('/api/users', {}, f.withCookie(admin))).json()) as Json[];
    assert.equal(list.length, 1);
    assert.deepEqual(Object.keys(list[0]!).sort(), ['createdAt', 'disabled', 'displayName', 'id', 'lastLoginAt', 'role', 'source', 'username']);
    assert.equal(list[0]!.source, 'local');
    assert.ok(list[0]!.lastLoginAt);
    const patch = (id: number, body: unknown, cookie = admin) => f.api(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }, f.withCookie(cookie));

    const demote = await patch(1, { role: 'viewer' });
    assert.equal(demote.status, 409);
    assert.match(((await demote.json()) as Json).error as string, /last enabled admin/);
    assert.equal((await patch(1, { disabled: true })).status, 409);
    assert.equal((await patch(1, { displayName: 'The Root' })).status, 200, 'other fields are fine');
    const self = await f.api('/api/users/1', { method: 'DELETE' }, f.withCookie(admin));
    assert.equal(self.status, 400);
    assert.equal(((await self.json()) as Json).error, 'You cannot delete your own account');

    const dup = await f.api('/api/users', { method: 'POST', body: JSON.stringify({ username: 'ROOT', password: 'another good password', role: 'viewer' }) }, f.withCookie(admin));
    assert.equal(dup.status, 409, 'usernames are unique case-insensitively');
    assert.equal((await f.api('/api/users', { method: 'POST', body: JSON.stringify({ username: 'x', password: 'another good password', role: 'owner' }) }, f.withCookie(admin))).status, 400);
    const second = await f.addUser(admin, 'second', 'admin');
    assert.equal((await patch(1, { role: 'analyst' })).status, 200, 'with two admins, one can step down');
    const secondCookie = await f.login('second', 'another good password');
    assert.equal((await patch(second.id, { role: 'viewer' }, secondCookie)).status, 409, 'and the other is now the last');
    const stepped = (await (await f.api('/api/session', {}, f.withCookie(admin))).json()) as { user: Json };
    assert.equal(stepped.user.role, 'analyst', 'the role change is live on the next request');
    assert.equal((await f.api('/api/users', {}, f.withCookie(admin))).status, 403);
    assert.equal((await patch(1, { role: 'admin' }, secondCookie)).status, 200);
    assert.equal((await f.api(`/api/users/${second.id}`, { method: 'DELETE' }, f.withCookie(admin))).status, 204, 'deleting another admin while two exist');
    assert.equal((await f.api('/api/targets', {}, f.withCookie(secondCookie))).status, 401, 'their sessions are gone');
    assert.equal((await f.api(`/api/users/${second.id}`, { method: 'DELETE' }, f.withCookie(admin))).status, 404);
  } finally {
    f.close();
  }
});

test('tokens: shown once, stored hashed, scoped, last used, deletable', async () => {
  const f = await fixture();
  try {
    const admin = await f.setup();
    assert.equal((await f.api('/api/tokens', { method: 'POST', body: JSON.stringify({ name: 'ci', scopes: ['read', 'nope'] }) }, f.withCookie(admin))).status, 400);
    assert.equal((await f.api('/api/tokens', { method: 'POST', body: JSON.stringify({ name: '', scopes: ['read'] }) }, f.withCookie(admin))).status, 400);
    const created = await f.api('/api/tokens', { method: 'POST', body: JSON.stringify({ name: 'ci', scopes: ['read', 'scan', 'read'] }) }, f.withCookie(admin));
    assert.equal(created.status, 201);
    const { id, token } = (await created.json()) as { id: number; token: string };
    assert.match(token, /^nfx_[A-Za-z0-9]{40}$/);
    const db = new DatabaseSync(f.dbPath);
    const row = db.prepare('SELECT token_hash, scopes FROM api_tokens WHERE id = ?').get(id) as { token_hash: string; scopes: string };
    db.close();
    assert.equal(row.token_hash, createHash('sha256').update(token).digest('hex'));
    assert.deepEqual(JSON.parse(row.scopes), ['read', 'scan']);
    const listed = (await (await f.api('/api/tokens', {}, f.withCookie(admin))).json()) as Json[];
    assert.deepEqual(listed.map((t) => ({ id: t.id, name: t.name, scopes: t.scopes, createdBy: t.createdBy, lastUsedAt: t.lastUsedAt })), [{ id, name: 'ci', scopes: ['read', 'scan'], createdBy: 'root', lastUsedAt: null }]);
    assert.equal(JSON.stringify(listed).includes(token), false, 'the token is never listed');

    const use = await f.api('/api/targets', {}, { authorization: `Bearer ${token}` });
    assert.equal(use.status, 200);
    const after = (await (await f.api('/api/tokens', {}, f.withCookie(admin))).json()) as Json[];
    assert.ok(after[0]!.lastUsedAt, 'use is recorded');
    assert.equal((await f.api('/api/targets/999/scan', { method: 'POST' }, { authorization: `Bearer ${token}` })).status, 404, 'scan scope reaches the scan route');
    assert.equal((await f.api('/api/targets/1/tickets', { method: 'POST', body: '{}' }, { authorization: `Bearer ${token}` })).status, 403, 'no tickets scope');
    assert.equal((await f.api(`/api/tokens/${id}`, { method: 'DELETE' }, f.withCookie(admin))).status, 204);
    assert.equal((await f.api('/api/targets', {}, { authorization: `Bearer ${token}` })).status, 401, 'revoked');
    assert.equal((await f.api(`/api/tokens/${id}`, { method: 'DELETE' }, f.withCookie(admin))).status, 404);
  } finally {
    f.close();
  }
});

// ---- OIDC against an in-process provider ----

interface MockProvider {
  server: Server;
  issuer: string;
  /** The nonce the next id_token carries; the test copies it from the authorization URL. */
  nonce: string;
  /** The PKCE challenge the token endpoint expects, from the authorization URL. */
  challenge: string;
  /** Extra claims for the next id_token. */
  claims: Record<string, unknown>;
  /** Seconds the next id_token lives (negative for an expired one). */
  ttl: number;
  tokenRequests: { auth?: string; body: URLSearchParams }[];
  close(): void;
}

function base64url(s: string | Buffer): string {
  return Buffer.from(s).toString('base64url');
}

async function mockProvider(alg: 'RS256' | 'ES256'): Promise<MockProvider> {
  const pair = alg === 'RS256' ? generateKeyPairSync('rsa', { modulusLength: 2048 }) : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateKey: KeyObject = pair.privateKey;
  const jwk = pair.publicKey.export({ format: 'jwk' }) as Record<string, string>;
  const mock: MockProvider = { server: undefined as unknown as Server, issuer: '', nonce: '', challenge: '', claims: {}, ttl: 300, tokenRequests: [], close: () => mock.server.close() };
  const signToken = (claims: Record<string, unknown>) => {
    const header = base64url(JSON.stringify({ alg, kid: 'key-1', typ: 'JWT' }));
    const payload = base64url(JSON.stringify(claims));
    const data = `${header}.${payload}`;
    const sig = alg === 'RS256' ? cryptoSign('sha256', Buffer.from(data), privateKey) : cryptoSign('sha256', Buffer.from(data), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    return `${data}.${base64url(sig)}`;
  };
  mock.server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', mock.issuer);
    res.setHeader('content-type', 'application/json');
    if (url.pathname === '/.well-known/openid-configuration') {
      return res.end(JSON.stringify({ issuer: mock.issuer, authorization_endpoint: `${mock.issuer}/authorize`, token_endpoint: `${mock.issuer}/token`, jwks_uri: `${mock.issuer}/jwks`, userinfo_endpoint: `${mock.issuer}/userinfo` }));
    }
    if (url.pathname === '/jwks') return res.end(JSON.stringify({ keys: [{ ...jwk, kid: 'key-1', use: 'sig', alg }] }));
    if (url.pathname === '/token' && req.method === 'POST') {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = new URLSearchParams(Buffer.concat(chunks).toString());
      mock.tokenRequests.push({ auth: req.headers.authorization, body });
      const verifier = body.get('code_verifier') ?? '';
      if (body.get('grant_type') !== 'authorization_code' || body.get('code') !== 'good-code' || base64url(createHash('sha256').update(verifier).digest()) !== mock.challenge) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'bad code or verifier' }));
      }
      const now = Math.floor(Date.now() / 1000);
      const idToken = signToken({ iss: mock.issuer, aud: 'nextfix-client', sub: 'sub-123', iat: now, exp: now + mock.ttl, nonce: mock.nonce, email: 'pat@acme.test', name: 'Pat Example', ...mock.claims });
      return res.end(JSON.stringify({ id_token: idToken, access_token: 'access-1', token_type: 'Bearer' }));
    }
    if (url.pathname === '/userinfo') return res.end(JSON.stringify({ sub: 'sub-123', email: 'pat@acme.test', name: 'Pat Example' }));
    res.statusCode = 404;
    res.end('{}');
  });
  const port = await listen(mock.server);
  mock.issuer = `http://127.0.0.1:${port}`;
  return mock;
}

/** Start the flow at NextFix, read the provider redirect, and feed the mock what it needs. */
async function beginFlow(f: Awaited<ReturnType<typeof fixture>>, mock: MockProvider, providerId = 'mock') {
  const start = await f.api(`/api/auth/oidc/${providerId}/start`);
  await expectStatus(start, 302);
  const location = new URL(start.headers.get('location')!);
  assert.equal(location.origin + location.pathname, `${mock.issuer}/authorize`);
  assert.equal(location.searchParams.get('client_id'), 'nextfix-client');
  assert.equal(location.searchParams.get('redirect_uri'), `${f.base}/api/auth/oidc/${providerId}/callback`);
  assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(location.searchParams.get('scope'), 'openid profile email');
  const flowCookie = start.headers.getSetCookie().map((c) => c.split(';')[0]!).find((c) => c.startsWith('nextfix_oidc='))!;
  assert.ok(flowCookie);
  assert.match(start.headers.getSetCookie()[0]!, /HttpOnly; SameSite=Lax; Max-Age=600/);
  mock.nonce = location.searchParams.get('nonce')!;
  mock.challenge = location.searchParams.get('code_challenge')!;
  const state = location.searchParams.get('state')!;
  const callback = (query: string, cookie = flowCookie) => f.api(`/api/auth/oidc/${providerId}/callback?${query}`, {}, { cookie });
  return { state, flowCookie, callback };
}

test('oidc: settings, discovery, PKCE, RS256 verification, user creation, role mapping, repeat sign-in', async () => {
  resetOidcCache();
  const mock = await mockProvider('RS256');
  const f = await fixture();
  try {
    const admin = await f.setup();
    const put = (body: unknown) => f.api('/api/settings/oidc', { method: 'PUT', body: JSON.stringify(body) }, f.withCookie(admin));
    assert.equal((await put({ providers: [{ id: 'bad id', issuer: mock.issuer, clientId: 'c' }] })).status, 400);
    assert.equal((await put({ providers: [{ id: 'e', preset: 'entra', clientId: 'c' }] })).status, 400, 'entra needs a tenant');
    assert.equal((await put({ providers: [{ id: 'g', issuer: 'http://accounts.google.com', clientId: 'c' }] })).status, 400, 'http issuers only on loopback');
    const saved = await put({ providers: [{ id: 'mock', name: 'Mock IdP', preset: 'generic', issuer: `${mock.issuer}/`, clientId: 'nextfix-client', clientSecret: 's3cret-value', roleMap: { admin: ['nextfix-admins'], analyst: ['nextfix-analysts'] }, allowedDomains: ['acme.test', '@Example.org'] }, { id: 'entra', preset: 'entra', tenant: 'contoso.onmicrosoft.com', clientId: 'app-id' }, { id: 'okta', preset: 'okta', domain: 'acme.okta.com', clientId: 'okta-id', clientSecret: 'okta-secret' }, { id: 'google', preset: 'google', clientId: 'g-id' }] });
    await expectStatus(saved, 200);
    const settings = (await saved.json()) as { providers: Json[] };
    assert.equal(JSON.stringify(settings).includes('s3cret'), false, 'secrets are never returned');
    assert.equal(settings.providers[0]!.hasSecret, true);
    assert.equal(settings.providers[0]!.issuer, mock.issuer, 'trailing slash removed');
    assert.equal(settings.providers[0]!.redirectUri, `${f.base}/api/auth/oidc/mock/callback`);
    assert.deepEqual(settings.providers[0]!.allowedDomains, ['acme.test', 'example.org']);
    assert.equal(settings.providers[1]!.issuer, 'https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0');
    assert.equal(settings.providers[2]!.issuer, 'https://acme.okta.com/oauth2/default');
    assert.equal(settings.providers[3]!.issuer, 'https://accounts.google.com');
    assert.equal(settings.providers[3]!.hasSecret, false);
    // a second PUT without the secret keeps it
    const again = await put({ providers: [{ id: 'mock', name: 'Mock IdP', issuer: mock.issuer, clientId: 'nextfix-client', roleMap: { admin: ['nextfix-admins'], analyst: ['nextfix-analysts'] }, allowedDomains: ['acme.test'] }] });
    assert.equal(again.status, 200);
    assert.equal(((await again.json()) as { providers: Json[] }).providers[0]!.hasSecret, true);
    assert.equal(f.store.getJsonSetting<{ providers: OidcProvider[] }>('oidc')!.providers[0]!.clientSecret, 's3cret-value');
    const session = (await (await f.api('/api/session')).json()) as Json;
    assert.deepEqual(session, { setupRequired: false, authMode: 'oidc', oidc: { providers: [{ id: 'mock', name: 'Mock IdP' }] } });
    assert.equal(((await (await f.api('/api/health')).json()) as Json).authMode, 'oidc');
    assert.equal((await f.api('/api/auth/oidc/other/start')).status, 404);

    // the full round trip
    const flow = await beginFlow(f, mock);
    mock.claims = { groups: ['everyone', 'nextfix-analysts'] };
    const cb = await flow.callback(`code=good-code&state=${flow.state}`);
    await expectStatus(cb, 302);
    assert.equal(cb.headers.get('location'), '/');
    const cookies = cb.headers.getSetCookie();
    assert.ok(cookies.some((c) => c.startsWith('nextfix_session=') && c.includes('HttpOnly')), 'a session cookie');
    assert.ok(cookies.some((c) => c.startsWith('nextfix_oidc=;') && c.includes('Max-Age=0')), 'the flow cookie is cleared');
    const sessionCookie = f.cookieOf(cb);
    const me = (await (await f.api('/api/session', {}, f.withCookie(sessionCookie))).json()) as { user: Json };
    assert.deepEqual(me.user, { id: 2, username: 'pat@acme.test', displayName: 'Pat Example', role: 'analyst' });
    const users = (await (await f.api('/api/users', {}, f.withCookie(admin))).json()) as Json[];
    assert.equal(users.find((u) => u.username === 'pat@acme.test')!.source, 'oidc');
    const tokenReq = mock.tokenRequests[0]!;
    assert.equal(tokenReq.auth, `Basic ${Buffer.from('nextfix-client:s3cret-value').toString('base64')}`, 'client_secret_basic');
    assert.equal(tokenReq.body.get('redirect_uri'), `${f.base}/api/auth/oidc/mock/callback`);
    assert.equal(tokenReq.body.get('client_id'), null, 'client_id travels in the Basic header only');

    // signing in again maps the role from the provider's groups and reuses the account
    const flow2 = await beginFlow(f, mock);
    mock.claims = { groups: ['nextfix-admins'], name: 'Pat E.' };
    const cb2 = await flow2.callback(`code=good-code&state=${flow2.state}`);
    assert.equal(cb2.status, 302);
    const me2 = (await (await f.api('/api/session', {}, f.withCookie(f.cookieOf(cb2)))).json()) as { user: Json };
    assert.deepEqual(me2.user, { id: 2, username: 'pat@acme.test', displayName: 'Pat E.', role: 'admin' });
    assert.equal(f.store.countUsers(), 2);

    // the flow cookie is single use and must match the state
    assert.equal((await flow2.callback(`code=good-code&state=${flow2.state}`, flow2.flowCookie)).status, 302, 'a replay inside the ttl with the same cookie still verifies at the provider; the provider refuses reused codes');
    const flow3 = await beginFlow(f, mock);
    assert.equal((await flow3.callback(`code=good-code&state=not-the-state`)).status, 400);
    assert.equal((await flow3.callback(`code=good-code&state=${flow3.state}`, 'nextfix_oidc=tampered.cookie')).status, 400);
    assert.equal((await flow3.callback(`code=good-code&state=${flow3.state}`, '')).status, 400);
    const refused = await flow3.callback(`error=access_denied&error_description=User+said+no&state=${flow3.state}`);
    assert.equal(refused.status, 400);
    assert.match(await refused.text(), /User said no/);
    assert.equal(refused.headers.get('content-type'), 'text/html; charset=utf-8');
    const wrongCode = await flow3.callback(`code=stale&state=${flow3.state}`);
    assert.equal(wrongCode.status, 502, 'the provider refused the code');
  } finally {
    f.close();
    mock.close();
  }
});

test('oidc: bad nonce, expired token, wrong audience, domain not allowed, ES256, linking a local account', async () => {
  resetOidcCache();
  const mock = await mockProvider('ES256');
  const f = await fixture();
  try {
    const admin = await f.setup();
    const saved = await f.api('/api/settings/oidc', { method: 'PUT', body: JSON.stringify({ providers: [{ id: 'mock', name: 'Mock', issuer: mock.issuer, clientId: 'nextfix-client', clientSecret: 'sec', defaultRole: 'analyst', allowedDomains: ['acme.test'] }] }) }, f.withCookie(admin));
    await expectStatus(saved, 200);

    let flow = await beginFlow(f, mock);
    mock.claims = { nonce: 'someone-elses-nonce' };
    let res = await flow.callback(`code=good-code&state=${flow.state}`);
    assert.equal(res.status, 400);
    assert.match(await res.text(), /nonce/);

    flow = await beginFlow(f, mock);
    mock.claims = {};
    mock.ttl = -120;
    res = await flow.callback(`code=good-code&state=${flow.state}`);
    assert.equal(res.status, 400);
    assert.match(await res.text(), /expired/);
    mock.ttl = 300;

    flow = await beginFlow(f, mock);
    mock.claims = { aud: ['someone-else'] };
    res = await flow.callback(`code=good-code&state=${flow.state}`);
    assert.equal(res.status, 400);
    assert.match(await res.text(), /not for this application/);

    flow = await beginFlow(f, mock);
    mock.claims = { email: 'mallory@other.test' };
    res = await flow.callback(`code=good-code&state=${flow.state}`);
    assert.equal(res.status, 403);
    assert.match(await res.text(), /other\.test are not allowed/);
    assert.equal(f.store.countUsers(), 1, 'nothing was created');

    // a local account with the same e-mail is linked, keeps its role, and the audit says so
    await f.addUser(admin, 'pat@acme.test', 'viewer');
    flow = await beginFlow(f, mock);
    mock.claims = {};
    res = await flow.callback(`code=good-code&state=${flow.state}`);
    await expectStatus(res, 302);
    const me = (await (await f.api('/api/session', {}, f.withCookie(f.cookieOf(res)))).json()) as { user: Json };
    assert.equal(me.user.username, 'pat@acme.test');
    assert.equal(me.user.role, 'viewer', 'no roleMap: the stored role stands');
    assert.equal(f.store.countUsers(), 2);
    assert.equal(f.store.getUserByOidc('mock', 'sub-123')!.username, 'pat@acme.test');
    const audit = (await (await f.api('/api/audit', {}, f.withCookie(admin))).json()) as { rows: Json[] };
    assert.ok(audit.rows.some((r) => r.action === 'oidc.link'));
    assert.ok(audit.rows.some((r) => r.action === 'login' && (r.detail as Json).provider === 'mock'));

    // claims helpers
    assert.equal(mapRole({ roles: ['x'] }, { roleMap: { admin: ['x'] }, defaultRole: 'viewer' } as OidcProvider), 'admin', 'roles is read when no claim is named');
    assert.equal(mapRole({ groups: 'solo' }, { roleClaim: 'groups', roleMap: { analyst: ['solo'] }, defaultRole: 'viewer' } as OidcProvider), 'analyst');
    assert.throws(() => checkClaims({ iss: 'a', sub: 's', aud: 'c', exp: 1e12, nonce: 'n' }, { issuer: 'b', clientId: 'c', nonce: 'n' }), /issued by someone else/);
    assert.throws(() => normalizeOidcSettings({ providers: [{ id: 'x', issuer: 'https://idp.test/?x=1', clientId: 'c' }] }, undefined), /query/);
  } finally {
    f.close();
    mock.close();
  }
});

test('audit: rows for setup, logins, users, tokens, settings and targets; paging; no secrets', async () => {
  const f = await fixture();
  try {
    const admin = await f.setup();
    await f.api('/api/login', { method: 'POST', body: JSON.stringify({ username: 'root', password: 'nope nope nope' }) });
    const vic = await f.addUser(admin, 'vic', 'viewer', 'vic-secret-password');
    await f.api(`/api/users/${vic.id}`, { method: 'PATCH', body: JSON.stringify({ role: 'analyst' }) }, f.withCookie(admin));
    const tok = await f.api('/api/tokens', { method: 'POST', body: JSON.stringify({ name: 'ci', scopes: ['read'] }) }, f.withCookie(admin));
    const { id: tokenId, token } = (await tok.json()) as { id: number; token: string };
    await f.api(`/api/tokens/${tokenId}`, { method: 'DELETE' }, f.withCookie(admin));
    await f.api('/api/settings', { method: 'PUT', body: JSON.stringify({ slaActDays: 3 }) }, f.withCookie(admin));
    await f.api('/api/integrations/github', { method: 'PUT', body: JSON.stringify({ repo: 'acme/shop', token: 'gh-secret-token' }) }, f.withCookie(admin));
    await f.api('/api/integrations/github', { method: 'DELETE' }, f.withCookie(admin));
    const target = f.store.upsertTarget('C:/x/audited', 'audited');
    await f.api(`/api/targets/${target.id}`, { method: 'DELETE' }, f.withCookie(admin));
    await f.api(`/api/users/${vic.id}`, { method: 'DELETE' }, f.withCookie(admin));
    await f.api('/api/logout', { method: 'POST' }, f.withCookie(admin));
    const admin2 = await f.login('root', 'correct horse battery');

    const all = (await (await f.api('/api/audit', {}, f.withCookie(admin2))).json()) as { rows: Json[]; next: number | null };
    assert.equal(all.next, null);
    assert.deepEqual(all.rows.map((r) => r.action), ['login', 'logout', 'user.delete', 'target.delete', 'integration.delete', 'integration.update', 'settings.update', 'token.delete', 'token.create', 'user.update', 'user.create', 'login.failed', 'setup']);
    const text = JSON.stringify(all);
    for (const s of ['correct horse', 'nope nope', 'vic-secret', 'gh-secret', token]) assert.equal(text.includes(s), false, `${s} leaked`);
    const setupRow = all.rows.at(-1)!;
    assert.equal(setupRow.username, 'root');
    assert.equal(setupRow.userId, 1);
    assert.equal(setupRow.ip, '127.0.0.1');
    assert.deepEqual(setupRow.detail, { username: 'root' });
    assert.deepEqual(all.rows.find((r) => r.action === 'login.failed')!.detail, { reason: 'wrong password' });
    assert.deepEqual(all.rows.find((r) => r.action === 'user.update')!.detail, { role: 'analyst' });
    assert.deepEqual(all.rows.find((r) => r.action === 'token.create')!.detail, { name: 'ci', scopes: ['read'] });
    assert.deepEqual(all.rows.find((r) => r.action === 'settings.update')!.detail, { slaActDays: 3 });
    assert.deepEqual(all.rows.find((r) => r.action === 'integration.update')!.detail, { fields: ['repo'] });
    assert.equal(all.rows.find((r) => r.action === 'target.delete')!.target, `target:${target.id}`);

    const page1 = (await (await f.api('/api/audit?limit=5', {}, f.withCookie(admin2))).json()) as { rows: Json[]; next: number | null };
    assert.equal(page1.rows.length, 5);
    assert.equal(page1.next, page1.rows[4]!.id);
    const page2 = (await (await f.api(`/api/audit?limit=5&before=${page1.next}`, {}, f.withCookie(admin2))).json()) as { rows: Json[]; next: number | null };
    assert.ok((page2.rows[0]!.id as number) < (page1.next as number));
    assert.equal((await f.api('/api/audit?limit=0', {}, f.withCookie(admin2))).status, 400);
    assert.equal((await f.api('/api/audit?before=x', {}, f.withCookie(admin2))).status, 400);
  } finally {
    f.close();
  }
});

test('feature routes: registered handlers get the context, role gate, scope gate and audit', async () => {
  const routes: Route[] = [
    { method: 'GET', path: '/exceptions', role: 'viewer', scope: 'read', handler: (ctx) => ({ who: ctx.user?.username, path: ctx.path }) },
    { method: 'POST', path: '/exceptions/:id/approve', role: 'analyst', handler: (ctx) => { ctx.requireRole('admin'); ctx.audit('exception.approve', `exception:${ctx.params.id}`, { note: 'ok', password: 'never' }); return { approved: ctx.params.id }; } },
    { method: 'DELETE', path: '/exceptions/:id', role: 'analyst', handler: () => undefined },
    { method: 'GET', path: '/public-thing', public: true, handler: (ctx) => { ctx.send(418, 'teapot'); } },
    { method: 'GET', path: '/health', public: true, handler: () => ({ shadowed: true }) },
  ];
  const f = await fixture({ routes });
  try {
    const admin = await f.setup();
    await f.addUser(admin, 'ana', 'analyst');
    const analyst = await f.login('ana', 'another good password');
    assert.equal((await f.api('/api/exceptions')).status, 401);
    assert.deepEqual(await (await f.api('/api/exceptions', {}, f.withCookie(analyst))).json(), { who: 'ana', path: '/exceptions' });
    const approve = await f.api('/api/exceptions/7/approve', { method: 'POST' }, f.withCookie(analyst));
    assert.equal(approve.status, 403, 'requireRole inside the handler');
    assert.equal(((await approve.json()) as Json).error, 'This needs the admin role; you are signed in as a analyst');
    assert.deepEqual(await (await f.api('/api/exceptions/7/approve', { method: 'POST' }, f.withCookie(admin))).json(), { approved: '7' });
    assert.equal((await f.api('/api/exceptions/7', { method: 'DELETE' }, f.withCookie(analyst))).status, 204);
    const tea = await f.api('/api/public-thing');
    assert.equal(tea.status, 418);
    assert.equal(await tea.text(), 'teapot');
    assert.equal('shadowed' in ((await (await f.api('/api/health')).json()) as Json), false, 'built-in routes win');
    const rows = (await (await f.api('/api/audit?limit=1', {}, f.withCookie(admin))).json()) as { rows: Json[] };
    assert.equal(rows.rows[0]!.action, 'exception.approve');
    assert.deepEqual(rows.rows[0]!.detail, { note: 'ok' });
    assert.equal(rows.rows[0]!.username, 'root');
    const tok = (await (await f.api('/api/tokens', { method: 'POST', body: JSON.stringify({ name: 't', scopes: ['read'] }) }, f.withCookie(admin))).json()) as { token: string };
    assert.equal((await f.api('/api/exceptions', {}, { authorization: `Bearer ${tok.token}` })).status, 200);
    assert.equal((await f.api('/api/exceptions/7', { method: 'DELETE' }, { authorization: `Bearer ${tok.token}` })).status, 403, 'no scope on the route: tokens refused');
  } finally {
    f.close();
  }
});

test('--allow-open: no sign-in, local admin, loopback only; --secure-cookies marks cookies and accepts https origins', async () => {
  const open = await fixture({ allowOpen: true });
  try {
    assert.deepEqual(await (await open.api('/api/session')).json(), { setupRequired: false, authMode: 'none', user: { id: 0, username: 'local', displayName: 'Local user', role: 'admin' } });
    assert.equal((await open.api('/api/users')).status, 200);
    assert.equal((await open.api('/api/login', { method: 'POST', body: '{}' })).status, 409);
    await open.api('/api/settings', { method: 'PUT', body: JSON.stringify({ slaActDays: 2 }) });
    const rows = (await (await open.api('/api/audit')).json()) as { rows: Json[] };
    assert.equal(rows.rows[0]!.username, 'local');
    assert.equal(rows.rows[0]!.userId, null);
  } finally {
    open.close();
  }
  const secure = await fixture({ secureCookies: true });
  try {
    const res = await secure.api('/api/setup', { method: 'POST', body: JSON.stringify({ username: 'root', password: 'correct horse battery' }) });
    assert.match(res.headers.getSetCookie()[0]!, /; Secure$/);
    const cookie = secure.cookieOf(res);
    assert.equal((await secure.api('/api/settings', { method: 'PUT', body: '{}' }, { cookie, origin: `https://localhost` })).status, 200, 'an https origin on an allowed name');
    assert.equal((await secure.api('/api/settings', { method: 'PUT', body: '{}' }, { cookie, origin: `https://evil.example` })).status, 403);
    const oidc = (await (await secure.api('/api/settings/oidc', {}, { cookie, 'x-forwarded-proto': 'https', host: 'localhost' })).json()) as Json;
    assert.deepEqual(oidc, { providers: [] });
  } finally {
    secure.close();
  }
  const plain = await fixture();
  try {
    await plain.setup();
    assert.equal((await plain.api('/api/health', {}, { origin: 'https://localhost' })).status, 403, 'without TLS an https origin is still foreign');
  } finally {
    plain.close();
  }
});

test('cli: user add reads the password from stdin and user password resets it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-cli-'));
  const dbPath = join(dir, 'cli.sqlite');
  const cli = fileURLToPath(new URL('./cli.ts', import.meta.url));
  const run = (args: string[], stdin: string) =>
    new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const child = spawn(process.execPath, [cli, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
      let out = '';
      let err = '';
      child.stdout.on('data', (d: Buffer) => (out += d.toString()));
      child.stderr.on('data', (d: Buffer) => (err += d.toString()));
      child.on('close', (code) => resolve({ code, out, err }));
      child.stdin.end(stdin);
    });
  const added = await run(['user', 'add', 'Recovery', '--role', 'admin', '--db', dbPath], 'recovery password 1\n');
  assert.equal(added.code, 0, added.err);
  assert.match(added.out, /Created admin recovery/);
  assert.equal((await run(['user', 'add', 'recovery', '--role', 'admin', '--db', dbPath], 'x'.repeat(12))).code, 1, 'already exists');
  assert.equal((await run(['user', 'add', 'two', '--role', 'owner', '--db', dbPath], 'x'.repeat(12))).code, 1, 'bad role');
  assert.equal((await run(['user', 'add', 'two', '--db', dbPath], 'short')).code, 1, 'short password');
  const reset = await run(['user', 'password', 'recovery', '--db', dbPath], 'recovery password 2\n');
  assert.equal(reset.code, 0, reset.err);
  const store = new Store(dbPath);
  try {
    const user = store.getUserByUsername('recovery')!;
    assert.equal(user.role, 'admin');
    assert.equal(await verifyPassword('recovery password 2', user.passwordHash), true);
    assert.equal(await verifyPassword('recovery password 1', user.passwordHash), false);
    assert.deepEqual(store.listAudit(10).map((r) => `${r.username}:${r.action}`), ['cli:user.password', 'cli:user.create']);
    assert.equal(store.schemaVersion, 7);
  } finally {
    store.close();
  }
});

test('POST /api/shutdown: an admin on loopback stops the server; the CLI hears the event', async () => {
  const open = await fixture({ allowOpen: true });
  try {
    const heard = new Promise<void>((resolve) => open.app.once('nextfix:shutdown', () => resolve()));
    const res = await open.api('/api/shutdown', { method: 'POST', body: '{}' });
    assert.equal(res.status, 202);
    assert.match(((await res.json()) as { message: string }).message, /stopping/);
    await Promise.race([heard, new Promise((_, reject) => setTimeout(() => reject(new Error('no shutdown event')), 2000))]);
    const rows = (await (await open.api('/api/audit')).json()) as { rows: { action: string }[] };
    assert.ok(rows.rows.some((r) => r.action === 'server.shutdown'));
  } finally {
    open.close();
  }
});
