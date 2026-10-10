import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request, type Server, type IncomingHttpHeaders } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { Store, type HistorySummary } from './store.ts';
import { createNextFixServer, localStamp } from './server.ts';
import { diffReports } from './diff.ts';
import type { Finding, ScanReport } from '../../engine/src/types.ts';

/** A tiny tracker double that records what it is sent. */
function mockTracker(opts: { rateLimitOnce?: boolean } = {}) {
  const received: { method: string; url: string; auth?: string; body?: unknown; at: number }[] = [];
  let limited = false;
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const text = Buffer.concat(chunks).toString();
    received.push({ method: req.method ?? '', url: req.url ?? '', auth: req.headers.authorization, body: text ? JSON.parse(text) : undefined, at: Date.now() });
    res.setHeader('content-type', 'application/json');
    if (opts.rateLimitOnce && !limited && req.method === 'POST') {
      limited = true;
      res.statusCode = 429;
      res.setHeader('retry-after', '1');
      return res.end(JSON.stringify({ message: 'slow down' }));
    }
    if (req.url === '/repos/acme/shop' && req.method === 'GET') return res.end(JSON.stringify({ full_name: 'acme/shop', permissions: { push: true } }));
    if (req.url === '/repos/acme/shop/issues' && req.method === 'POST') return res.end(JSON.stringify({ number: 42, html_url: 'https://github.com/acme/shop/issues/42' }));
    if (req.url === '/rest/api/3/project/SEC' && req.method === 'GET') return res.end(JSON.stringify({ key: 'SEC', name: 'Security' }));
    if (req.url === '/rest/api/3/issue' && req.method === 'POST') return res.end(JSON.stringify({ id: '1', key: 'SEC-7' }));
    res.statusCode = 404;
    res.end(JSON.stringify({ message: 'not found' }));
  });
  return { server, received };
}

/** fetch refuses to set a Host header, so the Host checks use a raw request. */
function raw(port: number, path: string, headers: Record<string, string>, method = 'GET'): Promise<{ status: number; body: string; bytes: Buffer; headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers, setHost: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString(), bytes: Buffer.concat(chunks), headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

function fakeReport(): ScanReport {
  const component = { ecosystem: 'npm' as const, name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', dev: false, optional: false, direct: true, path: 'node_modules/lodash' };
  const advisory = { id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], cve: 'CVE-2021-23337', summary: 'Command Injection in lodash', details: '', cvssScore: 7.2, severityLabel: 'HIGH', fixedVersion: '4.17.21', references: ['https://github.com/advisories/GHSA-35jh-r3h4-6jhm'] };
  const entry = { method: 'POST', path: '/preview', file: 'src/app.js', line: 12, authenticated: false, guards: [], mounted: true, handlerIds: ['h'] };
  const finding = {
    id: `${component.purl}|${advisory.id}`,
    component,
    advisory,
    reach: { tier: 'reachable' as const, confidence: 'confirmed' as const, importedIn: ['src/services/render.js'], callSites: [], paths: [{ entry, hops: [], callSite: { file: 'src/services/render.js', line: 6, col: 20, text: '_.template', symbol: 'template', userInput: true }, userInput: true, inputSource: 'req.body.template', taintedArgument: { index: 0, text: 'source' } }] },
    exposure: { network: 'published' as const, ports: [3000], evidence: ['Dockerfile: EXPOSE 3000'] },
    exploitation: 'likely' as const,
    decision: 'Act' as const,
    score: 81,
    why: ['lodash 4.17.15 is affected by CVE-2021-23337.', 'Reachable: POST /preview → _.template().'],
    fix: 'Upgrade lodash 4.17.15 → 4.17.21',
  };
  return {
    tool: { name: 'NextFix', version: '0.0.0-test' },
    target: { dir: 'C:/x/express-shop', name: 'express-shop' },
    generatedAt: new Date().toISOString(),
    summary: { components: 1, advisories: 1, findings: 1, byDecision: { Act: 1, Attend: 0, 'Track*': 0, Track: 0 }, byTier: { reachable: 1, 'called-unreached': 0, 'imported-unknown-symbol': 0, 'image-only': 0, 'imported-not-called': 0, unused: 0, 'dev-only': 0 }, noiseRemoved: 0 },
    exposure: finding.exposure,
    entryPoints: [entry],
    components: [component],
    findings: [finding],
  };
}

test('tickets: configure trackers, create issues for a finding, remember the links', async () => {
  const tracker = mockTracker();
  const trackerPort = await listen(tracker.server);
  const base = `http://127.0.0.1:${trackerPort}`;

  const dir = mkdtempSync(join(tmpdir(), 'nextfix-test-'));
  const store = new Store(join(dir, 'test.sqlite'));
  const target = store.upsertTarget('C:/x/express-shop', 'express-shop');
  const scan = store.addScan(target.id, fakeReport());
  const app = createNextFixServer({ store, staticDir: dir });
  const port = await listen(app);
  const api = (path: string, init?: RequestInit) => fetch(`http://127.0.0.1:${port}${path}`, { ...init, headers: { 'content-type': 'application/json' } });

  try {
    // configure both trackers against the double
    assert.equal((await api('/api/integrations/github', { method: 'PUT', body: JSON.stringify({ repo: 'acme/shop', token: 'test-token', labels: 'security, nextfix', apiBase: base }) })).status, 200);
    assert.equal((await api('/api/integrations/jira', { method: 'PUT', body: JSON.stringify({ baseUrl: base, email: 'qa@acme.test', apiToken: 'test-api-token', projectKey: 'SEC' }) })).status, 200);
    const listed = (await (await api('/api/integrations')).json()) as { github: { repo: string; hasToken: boolean; labels: string[] }; jira: { projectKey: string; hasToken: boolean } };
    assert.equal(listed.github.repo, 'acme/shop');
    assert.deepEqual(listed.github.labels, ['security', 'nextfix']);
    assert.equal(listed.github.hasToken, true, 'token is stored');
    assert.equal(JSON.stringify(listed).includes('test-token'), false, 'token is never returned');

    // connection tests
    const t1 = (await (await api('/api/integrations/github/test', { method: 'POST' })).json()) as { message: string };
    assert.equal(t1.message, 'Connected to acme/shop');
    const t2 = (await (await api('/api/integrations/jira/test', { method: 'POST' })).json()) as { message: string };
    assert.equal(t2.message, 'Connected to project SEC (Security)');

    // create tickets
    const fid = 'pkg:npm/lodash@4.17.15|GHSA-35jh-r3h4-6jhm';
    const gh = (await (await api(`/api/targets/${target.id}/tickets`, { method: 'POST', body: JSON.stringify({ scanId: scan.id, kind: 'github', findingIds: [fid] }) })).json()) as { results: { key: string; url: string }[] };
    assert.deepEqual(gh.results[0], { findingId: fid, key: '#42', url: 'https://github.com/acme/shop/issues/42' });
    const jira = (await (await api(`/api/targets/${target.id}/tickets`, { method: 'POST', body: JSON.stringify({ scanId: scan.id, kind: 'jira', findingIds: [fid] }) })).json()) as { results: { key: string; url: string }[] };
    assert.equal(jira.results[0]!.key, 'SEC-7');
    assert.equal(jira.results[0]!.url, `${base}/browse/SEC-7`);

    // what the trackers were sent
    const ghIssue = tracker.received.find((r) => r.url === '/repos/acme/shop/issues')!;
    assert.equal(ghIssue.auth, 'Bearer test-token');
    const ghBody = ghIssue.body as { title: string; body: string; labels: string[] };
    assert.ok(ghBody.title.startsWith('[Act] lodash@4.17.15: CVE-2021-23337'));
    assert.ok(ghBody.body.includes('npm install lodash@4.17.21'));
    assert.deepEqual(ghBody.labels, ['security', 'nextfix']);
    const jiraIssue = tracker.received.find((r) => r.url === '/rest/api/3/issue')!;
    assert.equal(jiraIssue.auth, `Basic ${Buffer.from('qa@acme.test:test-api-token').toString('base64')}`);
    const jiraBody = jiraIssue.body as { fields: { project: { key: string }; issuetype: { name: string }; description: { type: string } } };
    assert.equal(jiraBody.fields.project.key, 'SEC');
    assert.equal(jiraBody.fields.issuetype.name, 'Task');
    assert.equal(jiraBody.fields.description.type, 'doc');

    // remembered, and not created twice
    const again = (await (await api(`/api/targets/${target.id}/tickets`, { method: 'POST', body: JSON.stringify({ scanId: scan.id, kind: 'github', findingIds: [fid] }) })).json()) as { results: { skipped?: boolean }[] };
    assert.equal(again.results[0]!.skipped, true);
    const map = (await (await api(`/api/targets/${target.id}/tickets`)).json()) as Record<string, { kind: string; key: string }[]>;
    assert.deepEqual(map[fid]!.map((t) => `${t.kind}:${t.key}`).sort(), ['github:#42', 'jira:SEC-7']);
    assert.equal(tracker.received.filter((r) => r.url === '/repos/acme/shop/issues').length, 1);
  } finally {
    app.close();
    tracker.server.close();
    store.close();
  }
});

/** A server on a fresh temp database, plus a request helper that sends JSON by default. */
async function fixture(opts: { allowHosts?: string[]; host?: string } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-test-'));
  const dbPath = join(dir, 'test.sqlite');
  const store = new Store(dbPath);
  const app = createNextFixServer({ store, staticDir: dir, ...opts });
  const port = await listen(app);
  const api = (path: string, init: RequestInit = {}, headers: Record<string, string> = {}) =>
    fetch(`http://127.0.0.1:${port}${path}`, { ...init, headers: { 'content-type': 'application/json', ...headers } });
  const close = () => {
    app.close();
    store.close();
  };
  return { dir, dbPath, store, app, port, api, close };
}

test('request guards: content-type, Origin, Host and body size', async () => {
  const f = await fixture({ allowHosts: ['build-box.lan'] });
  try {
    // mutating requests must declare JSON
    const r415 = await f.api('/api/targets', { method: 'POST', body: 'dir=C:/x' }, { 'content-type': 'text/plain' });
    assert.equal(r415.status, 415);
    assert.match(((await r415.json()) as { error: string }).error, /application\/json/);
    assert.equal((await f.api('/api/integrations/github', { method: 'PUT', body: '{}' }, { 'content-type': 'application/x-www-form-urlencoded' })).status, 415);
    assert.equal((await f.api('/api/integrations/github', { method: 'PUT', body: '{"repo":"a/b"}' }, { 'content-type': 'Application/JSON; charset=utf-8' })).status, 200, 'parameters and case are fine');
    // GET never needs one
    assert.equal((await fetch(`http://127.0.0.1:${f.port}/api/health`)).status, 200);
    assert.equal((await fetch(`http://127.0.0.1:${f.port}/`)).status, 200, 'static serving still works');

    // a foreign Origin is refused, our own is accepted, a preflight gets no CORS grant
    assert.equal((await f.api('/api/health', {}, { origin: 'https://evil.example' })).status, 403);
    assert.equal((await f.api('/api/health', {}, { origin: 'http://127.0.0.1:1' })).status, 403, 'same host on another port is another origin');
    assert.equal((await f.api('/api/health', {}, { origin: 'null' })).status, 403);
    assert.equal((await f.api('/api/health', {}, { origin: `http://localhost:${f.port}` })).status, 200);
    assert.equal((await f.api('/api/health', {}, { origin: `http://[::1]:${f.port}` })).status, 200);
    const preflight = await f.api('/api/targets', { method: 'OPTIONS' }, { origin: 'https://evil.example', 'access-control-request-method': 'POST' });
    assert.equal(preflight.status, 403);
    assert.equal(preflight.headers.get('access-control-allow-origin'), null);
    const options = await f.api('/api/targets', { method: 'OPTIONS' });
    assert.equal(options.status, 204);
    assert.equal(options.headers.get('access-control-allow-origin'), null);

    // DNS rebinding: an unknown Host name is refused with a hint, known ones (with or without port) pass
    const r421 = await raw(f.port, '/api/health', { host: 'attacker.example' });
    assert.equal(r421.status, 421);
    assert.match((JSON.parse(r421.body) as { error: string }).error, /--allow-host attacker\.example/);
    assert.equal((await raw(f.port, '/', { host: 'attacker.example:8790' })).status, 421, 'applies to the dashboard too');
    for (const h of ['localhost', `localhost:${f.port}`, '127.0.0.1', `[::1]:${f.port}`, 'build-box.lan', 'Build-Box.LAN:8790']) {
      assert.equal((await raw(f.port, '/api/health', { host: h })).status, 200, h);
    }

    // bodies above 1 MB are refused
    const big = Buffer.alloc(1024 * 1024 + 1, 0x20);
    const r413 = await f.api('/api/targets', { method: 'POST', body: big });
    assert.equal(r413.status, 413);
    const chunked = await fetch(`http://127.0.0.1:${f.port}/api/targets`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: new ReadableStream({ start(c) { c.enqueue(big); c.close(); } }), duplex: 'half' } as RequestInit);
    assert.equal(chunked.status, 413, 'streamed bodies without content-length are capped as they arrive');
    assert.equal((await f.api('/api/targets', { method: 'POST', body: '[1,2]' })).status, 400, 'a JSON array is not a request object');
    assert.equal((await fetch(`http://127.0.0.1:${f.port}/api/health`)).status, 200, 'server still healthy afterwards');

    // echoed input is trimmed
    const long = 'x'.repeat(5000);
    const r400 = await f.api('/api/targets', { method: 'POST', body: JSON.stringify({ dir: long }) });
    assert.equal(r400.status, 400);
    assert.ok(((await r400.json()) as { error: string }).error.length < 260);
    const r404 = await fetch(`http://127.0.0.1:${f.port}/api/${long}`);
    assert.ok(((await r404.json()) as { error: string }).error.length < 260);
  } finally {
    f.close();
  }
});

test('integration settings: unknown keys dropped, host change needs the token, secrets never returned', async () => {
  const f = await fixture();
  try {
    const put = (kind: string, body: unknown) => f.api(`/api/integrations/${kind}`, { method: 'PUT', body: JSON.stringify(body) });
    assert.equal((await put('github', { repo: 'acme/shop', token: 'secret-1', apiBase: 'http://127.0.0.1:9', webhook: 'https://evil.example', labels: ['x'] })).status, 200);
    assert.deepEqual(f.store.getIntegration('github'), { repo: 'acme/shop', token: 'secret-1', labels: ['x'], apiBase: 'http://127.0.0.1:9' }, 'only known keys are stored');

    const moved = await put('github', { repo: 'acme/shop', apiBase: 'https://evil.example', token: '' });
    assert.equal(moved.status, 400);
    assert.equal(((await moved.json()) as { error: string }).error, 'Enter the token again when changing the server address');
    assert.equal((f.store.getIntegration('github') as { apiBase: string }).apiBase, 'http://127.0.0.1:9', 'nothing was saved');
    assert.equal((await put('github', { repo: 'acme/shop', apiBase: 'http://localhost:9' })).status, 400, 'loopback is a different host too');
    assert.equal((await put('github', { repo: 'acme/shop', apiBase: 'http://127.0.0.1:9/v3', token: '' })).status, 200, 'same host, other path: fine without the token');
    assert.equal((await put('github', { repo: 'acme/shop', apiBase: 'ftp://x.test', token: 'secret-2' })).status, 400, 'scheme is checked');
    assert.equal((await put('github', { repo: 'acme/shop', apiBase: 'https://ghe.example/api/v3?x=1', token: 'secret-2' })).status, 400, 'query is refused');
    assert.equal((await put('github', { repo: 'acme/shop', apiBase: 'https://ghe.example/api/v3', token: 'secret-2' })).status, 200);
    assert.equal((await put('jira', { baseUrl: 'https://acme.atlassian.net', email: 'e@x.test', apiToken: 'secret-j', projectKey: 'SEC' })).status, 200);
    assert.equal((await put('jira', { baseUrl: 'https://other.atlassian.net', email: 'e@x.test', apiToken: '', projectKey: 'SEC' })).status, 400);
    assert.equal((await put('jira', { baseUrl: 'https://user:pw@acme.atlassian.net', email: 'e@x.test', apiToken: 'secret-j', projectKey: 'SEC' })).status, 400, 'credentials in the URL are refused');

    // no response ever carries a secret
    const bodies = [await (await f.api('/api/integrations')).text(), await (await f.api('/api/health')).text(), await (await put('github', { repo: 'acme/shop', token: 'secret-3' })).text(), await (await f.api('/api/integrations/github/test', { method: 'POST' })).text()];
    for (const b of bodies) for (const s of ['secret-1', 'secret-2', 'secret-3', 'secret-j']) assert.equal(b.includes(s), false, `${s} leaked in ${b}`);
    assert.equal((JSON.parse(bodies[0]!) as { github: { hasToken: boolean } }).github.hasToken, true);
  } finally {
    f.close();
  }
});

test('reports written before 0.8 are normalised so every decision and tier has a number', async () => {
  const f = await fixture();
  try {
    const target = f.store.upsertTarget('C:/x/old-app', 'old-app');
    const old = fakeReport() as unknown as { summary: Record<string, unknown> };
    old.summary = { components: 1, advisories: 1, findings: 1, byDecision: { Act: 1, Attend: 0, Track: 0 }, byTier: { reachable: 1, unused: 0 }, noiseRemoved: 0 };
    const row = f.store.addScan(target.id, old as unknown as ScanReport);
    const report = (await (await f.api(`/api/scans/${row.id}`)).json()) as ScanReport;
    assert.equal(report.summary.byDecision['Track*'], 0);
    assert.equal(report.summary.byTier['image-only'], 0);
    assert.equal(report.summary.byTier['dev-only'], 0);
    assert.equal(report.summary.byTier.reachable, 1);
    const scans = (await (await f.api(`/api/targets/${target.id}/scans`)).json()) as { summary: ScanReport['summary'] }[];
    assert.equal(scans[0]!.summary.byTier['image-only'], 0);
    const targets = (await (await f.api('/api/targets')).json()) as { lastScan: { summary: ScanReport['summary'] } }[];
    assert.equal(targets[0]!.lastScan.summary.byDecision['Track*'], 0);
    assert.equal(f.store.schemaVersion, 2);
  } finally {
    f.close();
  }
});

test('a scan running anywhere on the database blocks new targets and shows in health', async () => {
  const f = await fixture();
  // a second server process (different pid) on the same database
  const other = new Store(f.dbPath, { pid: f.store.pid + 100_000 });
  try {
    assert.equal(other.acquireServerLock('127.0.0.1', 8791)?.pid, f.store.pid, 'the second server is warned about the first');
    assert.equal(f.store.otherServer()?.pid, other.pid, 'the first server sees the second');
    const h1 = (await (await f.api('/api/health')).json()) as { scanning: { targetId: number | null; stage: string; startedAt: string } | null; otherServer?: { pid: number; port: number; since: string }; dbPath: string; cachePath: string };
    assert.equal(h1.otherServer?.pid, other.pid);
    assert.equal(h1.otherServer?.port, 8791);
    assert.ok(h1.otherServer?.since);
    assert.equal(h1.scanning, null);
    assert.ok(h1.dbPath && h1.cachePath, 'Settings still gets its paths');

    // the other process starts a scan
    assert.equal(other.beginScan('127.0.0.1', 8791), true);
    assert.equal(other.beginScan('127.0.0.1', 8791), false, 'the lock is exclusive');
    const h2 = (await (await f.api('/api/health')).json()) as { scanning: { targetId: number | null; stage: string; startedAt: string } | null };
    assert.equal(h2.scanning?.targetId, null, 'a scan on another server has no local target');
    assert.equal(h2.scanning?.stage, 'Running on another server');
    assert.ok(h2.scanning?.startedAt);
    writeFileSync(join(f.dir, 'package-lock.json'), '{}');
    const busy = await f.api('/api/targets', { method: 'POST', body: JSON.stringify({ dir: f.dir }) });
    assert.equal(busy.status, 409);
    assert.equal(((await busy.json()) as { error: string }).error, 'A scan is already running; try again when it finishes');
    assert.deepEqual(f.store.listTargets(), [], 'the target was not inserted');
    const t = f.store.upsertTarget('C:/x/other', 'other');
    assert.equal((await f.api(`/api/targets/${t.id}/scan`, { method: 'POST' })).status, 409);

    // it finishes; a dead process's lock expires after 60 s
    other.endScan();
    assert.equal(f.store.scanInProgress(), false);
    assert.equal(f.store.beginScan(), true);
    f.store.endScan();
    other.releaseLocks();
    assert.equal(f.store.otherServer(), undefined);
  } finally {
    other.close();
    f.close();
  }
});

test('tracker calls: one retry after Retry-After, bulk creations spaced out, every link recorded', async () => {
  const tracker = mockTracker({ rateLimitOnce: true });
  const trackerPort = await listen(tracker.server);
  const f = await fixture();
  const spaced = createNextFixServer({ store: f.store, staticDir: f.dir, ticketSpacingMs: 300 });
  const port = await listen(spaced);
  try {
    const report = fakeReport();
    const second = { ...report.findings[0]!, id: 'pkg:npm/lodash@4.17.15|GHSA-second', advisory: { ...report.findings[0]!.advisory, id: 'GHSA-second' } };
    report.findings.push(second);
    report.summary.findings = 2;
    const target = f.store.upsertTarget('C:/x/express-shop', 'express-shop');
    const scan = f.store.addScan(target.id, report);
    f.store.setIntegration('github', { repo: 'acme/shop', token: 't', apiBase: `http://127.0.0.1:${trackerPort}` });
    const started = Date.now();
    const res = await fetch(`http://127.0.0.1:${port}/api/targets/${target.id}/tickets`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ scanId: scan.id, kind: 'github', findingIds: [report.findings[0]!.id, second.id] }) });
    const { results } = (await res.json()) as { results: { findingId: string; key?: string; error?: string }[] };
    assert.deepEqual(results.map((r) => r.key), ['#42', '#42'], JSON.stringify(results));
    const posts = tracker.received.filter((r) => r.url === '/repos/acme/shop/issues');
    assert.equal(posts.length, 3, 'first creation was retried once after the 429');
    assert.ok(posts[1]!.at - posts[0]!.at >= 900, 'Retry-After was honoured');
    assert.ok(posts[2]!.at - posts[1]!.at >= 250, 'creations are spaced apart');
    assert.ok(Date.now() - started < 5000);
    assert.deepEqual(Object.keys(f.store.listTickets(target.id)).sort(), [report.findings[0]!.id, second.id].sort(), 'both links recorded');
  } finally {
    spaced.close();
    tracker.server.close();
    f.close();
  }
});

// ---- history, settings, diff reasons, progress/cancel, payload shape, gzip, retention ----

const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

/** A report whose findings are the given ids (all copies of the fake finding), stamped at `at`. */
function reportWith(ids: string[], at: string, patch: (f: Finding, i: number) => void = () => {}): ScanReport {
  const base = fakeReport();
  const template = base.findings[0]!;
  base.findings = ids.map((id, i) => {
    const f = structuredClone(template);
    f.id = id;
    f.advisory = { ...f.advisory, id: id.split('|')[1] ?? f.advisory.id };
    patch(f, i);
    return f;
  });
  base.summary.findings = base.findings.length;
  base.generatedAt = at;
  return base;
}

const X = 'pkg:npm/lodash@4.17.15|GHSA-x';
const Y = 'pkg:npm/lodash@4.17.15|GHSA-y';

test('finding history: first/last seen, resolved and reopened, derived numbers, first-seen on the list payload', async () => {
  const f = await fixture();
  try {
    const target = f.store.upsertTarget('C:/x/hist', 'hist');
    const s1 = f.store.addScan(target.id, reportWith([X], ago(40)));
    const s2 = f.store.addScan(target.id, reportWith([X, Y], ago(20), (x, i) => { if (i === 1) x.decision = 'Attend'; }));
    const s3 = f.store.addScan(target.id, reportWith([Y], ago(10), (x) => { x.decision = 'Attend'; }));

    let h = (await (await f.api(`/api/targets/${target.id}/history`)).json()) as HistorySummary;
    const rx = h.rows.find((r) => r.findingId === X)!;
    const ry = h.rows.find((r) => r.findingId === Y)!;
    assert.equal(rx.firstScanId, s1.id);
    assert.equal(rx.lastScanId, s2.id);
    assert.equal(rx.resolvedScanId, s3.id, 'X vanished in scan 3');
    assert.equal(rx.resolvedAt, s3.createdAt, 'resolved at the scan that no longer had it');
    assert.equal(ry.firstScanId, s2.id);
    assert.equal(ry.resolvedAt, null);
    assert.equal(ry.decisionLatest, 'Attend');
    assert.deepEqual(h.open.Attend, { '0-7': 0, '8-30': 1, '31-90': 0, '90+': 0 }, 'Y is 20 days old');
    assert.equal(h.open.Act['31-90'], 0, 'X is resolved, so not open');
    assert.equal(h.pastSla.Attend, 0, '20 days is inside the 30-day Attend SLA');
    assert.equal(h.pastSla.Act, 0);
    assert.equal(h.resolvedLast30, 1);
    assert.equal(h.introducedLast30, 1, 'Y arrived 20 days ago; X is older');
    assert.equal(h.medianDaysToResolve, 30, 'X: first seen 40 days ago, resolved 10 days ago');
    assert.deepEqual(h.sla, { slaActDays: 7, slaAttendDays: 30 });
    assert.deepEqual(Object.keys(h.firstSeen), [Y]);

    // X comes back: un-resolved, first seen kept
    const s4 = f.store.addScan(target.id, reportWith([X, Y], ago(1), (x, i) => { if (i === 1) x.decision = 'Attend'; }));
    h = (await (await f.api(`/api/targets/${target.id}/history`)).json()) as HistorySummary;
    const rx2 = h.rows.find((r) => r.findingId === X)!;
    assert.equal(rx2.resolvedAt, null);
    assert.equal(rx2.firstScanId, s1.id);
    assert.equal(rx2.lastScanId, s4.id);
    assert.equal(h.open.Act['31-90'], 1, 'age counts from the first sighting');
    assert.equal(h.pastSla.Act, 1, '40 days is past the 7-day Act SLA');

    // the list payload carries firstSeenAt
    const report = (await (await f.api(`/api/scans/${s4.id}`)).json()) as { findings: { id: string; firstSeenAt?: string }[] };
    assert.equal(report.findings.find((x) => x.id === X)!.firstSeenAt, s1.createdAt);
    assert.equal(report.findings.find((x) => x.id === Y)!.firstSeenAt, s2.createdAt);

    // a tighter SLA via settings
    assert.equal((await f.api('/api/settings', { method: 'PUT', body: JSON.stringify({ slaAttendDays: 2 }) })).status, 200);
    h = (await (await f.api(`/api/targets/${target.id}/history`)).json()) as HistorySummary;
    assert.equal(h.pastSla.Attend, 1);
    assert.equal((await f.api('/api/targets/999/history')).status, 404);
  } finally {
    f.close();
  }
});

test('finding history is backfilled from stored scans when the table arrives', async () => {
  const f = await fixture();
  const target = f.store.upsertTarget('C:/x/old', 'old');
  f.store.addScan(target.id, reportWith([X], ago(30)));
  f.store.addScan(target.id, reportWith([X, Y], ago(20)));
  f.store.addScan(target.id, reportWith([Y], ago(10)));
  const before = f.store.listHistory(target.id);
  f.close();
  // pretend the database predates version 2
  const db = new DatabaseSync(f.dbPath);
  db.exec('DELETE FROM finding_history; PRAGMA user_version = 1');
  db.close();
  const reopened = new Store(f.dbPath);
  try {
    assert.equal(reopened.schemaVersion, 2);
    assert.deepEqual(reopened.listHistory(target.id), before, 'walking the scans oldest to newest rebuilds the same rows');
  } finally {
    reopened.close();
  }
});

test('settings: defaults, validation, retention prunes old scans, deleting a target cascades', async () => {
  const f = await fixture();
  try {
    assert.deepEqual(await (await f.api('/api/settings')).json(), { slaActDays: 7, slaAttendDays: 30, retentionScans: 50 });
    assert.equal((await f.api('/api/settings', { method: 'PUT', body: JSON.stringify({ slaActDays: 0 }) })).status, 400);
    assert.equal((await f.api('/api/settings', { method: 'PUT', body: JSON.stringify({ slaActDays: 'soon' }) })).status, 400);
    const put = await f.api('/api/settings', { method: 'PUT', body: JSON.stringify({ slaActDays: 3, retentionScans: 2, bogus: 1 }) });
    assert.deepEqual(await put.json(), { slaActDays: 3, slaAttendDays: 30, retentionScans: 2 });

    const target = f.store.upsertTarget('C:/x/ret', 'ret');
    const s1 = f.store.addScan(target.id, reportWith([X], ago(3)));
    const s2 = f.store.addScan(target.id, reportWith([X], ago(2)));
    const s3 = f.store.addScan(target.id, reportWith([X], ago(1)));
    assert.deepEqual(f.store.listScans(target.id).map((s) => s.id), [s2.id, s3.id], 'only the newest 2 scans are kept');
    assert.equal(f.store.getReport(s1.id), undefined);
    assert.equal(f.store.listHistory(target.id)[0]!.firstScanId, s1.id, 'history remembers the pruned scan');
    const targets = f.store.listTargets();
    assert.equal(targets[0]!.lastScan?.id, s3.id);

    f.store.addTicket(target.id, X, 'github', '#1', 'https://github.com/x/y/issues/1');
    assert.equal((await f.api(`/api/targets/${target.id}`, { method: 'DELETE' })).status, 204);
    assert.deepEqual(f.store.listScans(target.id), []);
    assert.deepEqual(f.store.listHistory(target.id), []);
    assert.deepEqual(f.store.listTickets(target.id), {});
    assert.deepEqual(f.store.listTargets(), []);
  } finally {
    f.close();
  }
});

test('diff: reasons for tier, decision, fix, KEV and request data; PyPI names compare case-insensitively', () => {
  const prev = reportWith([X, Y, 'pkg:pypi/PyYAML@5.3|GHSA-p', 'pkg:npm/old@1|GHSA-gone'], ago(2), (f, i) => {
    if (i === 0) { f.decision = 'Attend'; f.reach.tier = 'called-unreached'; f.reach.paths = []; f.advisory = { ...f.advisory, fixedVersion: undefined }; }
    if (i === 1) { f.decision = 'Act'; f.kev = { dateAdded: '2024-01-01', ransomware: false }; }
  });
  const cur = reportWith([X, Y, 'pkg:pypi/pyyaml@5.3|GHSA-p', 'pkg:npm/new@1|GHSA-new'], ago(1), (f, i) => {
    if (i === 0) { f.decision = 'Act'; f.advisory = { ...f.advisory, fixedVersion: '4.18.0' }; }
    if (i === 1) { f.decision = 'Attend'; f.kev = undefined; f.reach.paths[0]!.userInput = false; }
  });
  const d = diffReports(cur, prev);
  assert.deepEqual(d.added.map((f) => f.id), ['pkg:npm/new@1|GHSA-new']);
  assert.deepEqual(d.resolved.map((f) => f.id), ['pkg:npm/old@1|GHSA-gone']);
  const x = d.changed.find((c) => c.finding.id === X)!;
  assert.equal(x.from, 'Attend');
  assert.equal(x.to, 'Act');
  assert.deepEqual(x.reasons, ['decision Attend → Act', 'new entry point reaches it', 'request data now reaches it', 'fix published 4.18.0']);
  const y = d.changed.find((c) => c.finding.id === Y)!;
  assert.deepEqual(y.reasons, ['decision Act → Attend', 'left KEV', 'request data no longer reaches it']);
  assert.equal(d.changed.some((c) => c.finding.id.startsWith('pkg:pypi/')), false, 'the renamed PyPI finding is unchanged');
  assert.deepEqual(d.summary, { added: 1, resolved: 1, escalated: 1, deescalated: 1 });
  assert.deepEqual(diffReports(cur, undefined).summary, { added: 0, resolved: 0, escalated: 0, deescalated: 0 });
});

test('scan progress shows the stage, DELETE /api/scan cancels, nothing is stored', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-test-'));
  const store = new Store(join(dir, 'test.sqlite'));
  let seenSignal: AbortSignal | undefined;
  const scanner = (_dir: string, o: { log?: (m: string) => void; signal?: AbortSignal }) =>
    new Promise<ScanReport>((_resolve, reject) => {
      seenSignal = o.signal;
      o.log?.('Inventory: reading package-lock.json');
      o.log?.('Code: building call graph and entry points');
      setTimeout(() => o.log?.('Advisories: OSV'), 20);
      o.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
    });
  const app = createNextFixServer({ store, staticDir: dir, scanner });
  const port = await listen(app);
  const api = (path: string, init: RequestInit = {}) => fetch(`http://127.0.0.1:${port}${path}`, { ...init, headers: { 'content-type': 'application/json' } });
  try {
    assert.equal((await api('/api/scan', { method: 'DELETE' })).status, 404, 'nothing to cancel yet');
    assert.equal(await (await api('/api/scan/progress')).json(), null);
    const target = store.upsertTarget('C:/x/slow', 'slow');
    const started = api(`/api/targets/${target.id}/scan`, { method: 'POST' });
    type Progress = { targetId: number; stage: string; lines: string[]; startedAt: string } | null;
    const readProgress = async () => (await (await api('/api/scan/progress')).json()) as Progress;
    let progress = await readProgress();
    for (let i = 0; i < 50 && progress?.stage !== 'Advisories'; i++) {
      await new Promise((r) => setTimeout(r, 10));
      progress = await readProgress();
    }
    assert.equal(progress?.targetId, target.id);
    assert.equal(progress?.stage, 'Advisories');
    assert.deepEqual(progress?.lines, ['Inventory: reading package-lock.json', 'Code: building call graph and entry points', 'Advisories: OSV']);
    assert.ok(progress?.startedAt);
    const health = (await (await api('/api/health')).json()) as { scanning: { targetId: number; stage: string; startedAt: string } | null };
    assert.deepEqual(health.scanning, { targetId: target.id, stage: 'Advisories', startedAt: progress!.startedAt });
    assert.equal((await api(`/api/targets/${target.id}/scan`, { method: 'POST' })).status, 409, 'one scan at a time');

    const cancel = await api('/api/scan', { method: 'DELETE' });
    assert.equal(cancel.status, 202);
    assert.deepEqual(await cancel.json(), { cancelled: true });
    const res = await started;
    assert.equal(res.status, 409);
    assert.equal(((await res.json()) as { error: string }).error, 'Scan cancelled');
    assert.equal(seenSignal?.aborted, true, 'the signal reached the engine');
    assert.deepEqual(store.listScans(target.id), [], 'a cancelled scan stores nothing');
    assert.equal(store.scanInProgress(), false, 'the lock is released');
    assert.equal(await (await api('/api/scan/progress')).json(), null);
    assert.equal(((await (await api('/api/health')).json()) as { scanning: unknown }).scanning, null);
  } finally {
    app.close();
    store.close();
  }
});

test('report payload: no advisory details, references capped at 6, full finding on its own route, full JSON download', async () => {
  const f = await fixture();
  try {
    const target = f.store.upsertTarget('C:/x/shape', 'shape');
    const report = reportWith([X], ago(1), (x) => {
      x.advisory = { ...x.advisory, details: 'A very long advisory text '.repeat(50), references: Array.from({ length: 9 }, (_, i) => `https://example.test/ref/${i}`) };
    });
    const scan = f.store.addScan(target.id, report);
    const list = (await (await f.api(`/api/scans/${scan.id}`)).json()) as { findings: { id: string; firstSeenAt?: string; advisory: Record<string, unknown> & { references: string[]; referenceCount: number } }[] };
    const a = list.findings[0]!.advisory;
    assert.equal('details' in a, false);
    assert.equal(a.references.length, 6);
    assert.equal(a.referenceCount, 9);
    assert.equal(list.findings[0]!.firstSeenAt, scan.createdAt);

    const full = await f.api(`/api/scans/${scan.id}/findings/${encodeURIComponent(X)}`);
    assert.equal(full.status, 200);
    const fb = (await full.json()) as Finding & { firstSeenAt?: string };
    assert.equal(fb.advisory.references.length, 9);
    assert.ok(fb.advisory.details.startsWith('A very long'));
    assert.equal(fb.firstSeenAt, scan.createdAt);
    assert.equal((await f.api(`/api/scans/${scan.id}/findings/${encodeURIComponent('pkg:npm/nope@1|GHSA-no')}`)).status, 404);

    const dl = await f.api(`/api/scans/${scan.id}/json`);
    assert.equal(dl.status, 200);
    const stamp = localStamp(report.generatedAt);
    assert.match(stamp, /^\d{4}-\d{2}-\d{2}-\d{4}$/);
    assert.equal(dl.headers.get('content-disposition'), `attachment; filename="express-shop-${stamp}.nextfix.json"`);
    const dlBody = (await dl.json()) as ScanReport;
    assert.equal(dlBody.findings[0]!.advisory.references.length, 9, 'the download is the whole report');
    assert.ok(dlBody.findings[0]!.advisory.details.length > 100);
    const vex = await f.api(`/api/scans/${scan.id}/vex`);
    assert.equal(vex.headers.get('content-disposition'), `attachment; filename="express-shop-${stamp}.openvex.json"`);
  } finally {
    f.close();
  }
});

test('gzip when accepted, identity otherwise, HEAD carries headers and no body', async () => {
  const f = await fixture();
  try {
    const target = f.store.upsertTarget('C:/x/gz', 'gz');
    const scan = f.store.addScan(target.id, reportWith(Array.from({ length: 30 }, (_, i) => `pkg:npm/lodash@4.17.15|GHSA-${i}`), ago(1)));
    const plain = await raw(f.port, `/api/scans/${scan.id}`, { host: 'localhost' });
    assert.equal(plain.headers['content-encoding'], undefined);
    assert.equal(Number(plain.headers['content-length']), plain.bytes.length);
    const gz = await raw(f.port, `/api/scans/${scan.id}`, { host: 'localhost', 'accept-encoding': 'gzip, deflate, br' });
    assert.equal(gz.headers['content-encoding'], 'gzip');
    assert.equal(gz.headers.vary, 'accept-encoding');
    assert.ok(gz.bytes.length < plain.bytes.length / 2, `gzip ${gz.bytes.length} vs ${plain.bytes.length}`);
    assert.equal(gunzipSync(gz.bytes).toString(), plain.body);
    const small = await raw(f.port, '/api/settings', { host: 'localhost', 'accept-encoding': 'gzip' });
    assert.equal(small.headers['content-encoding'], undefined, 'tiny bodies are not compressed');
    const refused = await raw(f.port, `/api/scans/${scan.id}`, { host: 'localhost', 'accept-encoding': 'gzip;q=0, identity' });
    assert.equal(refused.headers['content-encoding'], undefined);

    const head = await raw(f.port, `/api/scans/${scan.id}`, { host: 'localhost' }, 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(head.bytes.length, 0);
    assert.equal(head.headers['content-length'], plain.headers['content-length']);
    assert.equal(head.headers['content-type'], 'application/json; charset=utf-8');
    writeFileSync(join(f.dir, 'index.html'), `<!doctype html><title>t</title>${'<p>hello</p>'.repeat(200)}`);
    const staticHead = await raw(f.port, '/', { host: 'localhost', 'accept-encoding': 'gzip' }, 'HEAD');
    assert.equal(staticHead.status, 200);
    assert.equal(staticHead.bytes.length, 0);
    assert.equal(staticHead.headers['content-encoding'], 'gzip');
    const staticGz = await raw(f.port, '/', { host: 'localhost', 'accept-encoding': 'gzip' });
    assert.ok(gunzipSync(staticGz.bytes).toString().startsWith('<!doctype html>'));
  } finally {
    f.close();
  }
});

test('redecide: the decision step re-runs over the latest report with EPSS/KEV from the cache, stores nothing', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-test-'));
  const store = new Store(join(dir, 'test.sqlite'));
  const cachePath = join(dir, 'cache.sqlite');
  const app = createNextFixServer({ store, staticDir: dir, cachePath });
  const port = await listen(app);
  const api = (path: string, init: RequestInit = {}) => fetch(`http://127.0.0.1:${port}${path}`, { ...init, headers: { 'content-type': 'application/json' } });
  try {
    const target = store.upsertTarget('C:/x/redecide', 'redecide');
    assert.equal((await api(`/api/targets/${target.id}/redecide`, { method: 'POST' })).status, 404, 'no scan yet');
    // reachable only behind auth, nothing known about exploitation: Attend
    const report = reportWith([X], ago(1), (x) => {
      x.decision = 'Attend';
      x.reach.paths[0]!.entry = { ...x.reach.paths[0]!.entry, authenticated: true, guards: ['requireLogin'] };
    });
    const scan = store.addScan(target.id, report);
    // a seeded cache: the CVE is now in KEV, the EPSS lookup is cached as empty
    const cache = new DatabaseSync(cachePath);
    cache.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp INTEGER NOT NULL)');
    const exp = Date.now() + DAY;
    cache.prepare('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?)').run('kev:catalog', JSON.stringify({ 'CVE-2021-23337': { dateAdded: '2026-10-01', ransomware: false } }), exp);
    cache.prepare('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?)').run('epss:CVE-2021-23337', 'null', exp);
    cache.close();

    const res = await api(`/api/targets/${target.id}/redecide`, { method: 'POST' });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { scanId: number; changed: { finding: Finding; from: string; to: string; reasons: string[] }[]; summary: { changed: number; escalated: number; deescalated: number } };
    assert.equal(body.scanId, scan.id);
    assert.equal(body.changed.length, 1);
    assert.equal(body.changed[0]!.from, 'Attend');
    assert.equal(body.changed[0]!.to, 'Act');
    assert.deepEqual(body.changed[0]!.reasons, ['decision Attend → Act', 'entered KEV']);
    assert.equal(body.changed[0]!.finding.kev?.cve, 'CVE-2021-23337');
    assert.equal(body.changed[0]!.finding.exploitation, 'active');
    assert.deepEqual(body.summary, { changed: 1, escalated: 1, deescalated: 0 });
    assert.equal(store.getReport(scan.id)!.findings[0]!.decision, 'Attend', 'the stored report is untouched');
    assert.equal(store.listScans(target.id).length, 1);
  } finally {
    app.close();
    store.close();
  }
});
