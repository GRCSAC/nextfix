import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from './store.ts';
import { createNextFixServer } from './server.ts';
import type { ScanReport } from '../../engine/src/types.ts';

/** A tiny tracker double that records what it is sent. */
function mockTracker() {
  const received: { method: string; url: string; auth?: string; body?: unknown }[] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const text = Buffer.concat(chunks).toString();
    received.push({ method: req.method ?? '', url: req.url ?? '', auth: req.headers.authorization, body: text ? JSON.parse(text) : undefined });
    res.setHeader('content-type', 'application/json');
    if (req.url === '/repos/acme/shop' && req.method === 'GET') return res.end(JSON.stringify({ full_name: 'acme/shop', permissions: { push: true } }));
    if (req.url === '/repos/acme/shop/issues' && req.method === 'POST') return res.end(JSON.stringify({ number: 42, html_url: 'https://github.com/acme/shop/issues/42' }));
    if (req.url === '/rest/api/3/project/SEC' && req.method === 'GET') return res.end(JSON.stringify({ key: 'SEC', name: 'Security' }));
    if (req.url === '/rest/api/3/issue' && req.method === 'POST') return res.end(JSON.stringify({ id: '1', key: 'SEC-7' }));
    res.statusCode = 404;
    res.end(JSON.stringify({ message: 'not found' }));
  });
  return { server, received };
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
