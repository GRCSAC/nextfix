import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffReports, surfaceDiff, wideningCount } from './diff.ts';
import { LODASH, ago, reportWith } from './features/testing.ts';
import type { EntryPoint, ScanReport } from '../../engine/src/types.ts';

const entry = (method: string, path: string, authenticated = false, traffic?: EntryPoint['traffic']): EntryPoint => ({ method, path, file: 'src/app.js', line: 1, authenticated, guards: authenticated ? ['requireAuth'] : [], mounted: true, handlerIds: ['h'], traffic });

/** A report whose single finding is reached through `reachedBy`, with the given entry points. */
function report(entries: EntryPoint[], reachedBy: EntryPoint, patch: (r: ScanReport) => void = () => {}): ScanReport {
  const r = reportWith([LODASH], ago(1), (f) => { f.reach.paths[0]!.entry = reachedBy; });
  r.entryPoints = entries;
  patch(r);
  return r;
}

test('surfaceDiff: new and removed routes, guards, exposure, reach, ports, traffic and links, widening first', () => {
  const preview = entry('POST', '/preview');
  const admin = entry('POST', '/admin/export', true);
  const prev = report([preview, admin, entry('GET', '/old')], preview, (r) => {
    r.exposure = { network: 'local-only', ports: [], evidence: ['app.listen binds to loopback only'] };
    r.links = { identity: { names: ['shop'], hosts: [] }, outbound: [{ host: 'ledger', kind: 'compose', evidence: 'docker-compose.yml: ledger', external: false }] };
  });
  const adminOpen = entry('POST', '/admin/export', false);
  const cur = report([preview, adminOpen, entry('POST', '/export'), entry('GET', '/me', true)], adminOpen, (r) => {
    r.exposure = { network: 'published', ports: [3000, 5432], evidence: ['Dockerfile: EXPOSE 3000'], reach: 'internet', reachEvidence: ['infra/alb.tf: aws_lb "shop" is internet-facing'] };
    r.links = { identity: { names: ['shop'], hosts: [] }, outbound: [{ host: 'billing', kind: 'compose', evidence: 'docker-compose.yml: services.shop.depends_on billing', external: false }, { host: 'api.stripe.com', kind: 'env', evidence: '.env: STRIPE=https://api.stripe.com', external: true }] };
  });
  const changes = surfaceDiff(cur, prev);
  const texts = changes.map((c) => `${c.level} ${c.kind}: ${c.text}`);
  assert.deepEqual(texts, [
    'act guard-removed: Auth guard removed from POST /admin/export (was behind requireAuth; reaches 1 finding, worst Fix now)',
    'act reach: Now internet-facing: infra/alb.tf: aws_lb "shop" is internet-facing',
    'attend route-added: New route without a login: POST /export (reaches no vulnerable call)'.replace('attend', 'info'),
    'info route-added: New route behind a login: GET /me (requireAuth; reaches no vulnerable call)',
    'attend network: Service is now network-published (Dockerfile: EXPOSE 3000); it was bound to loopback before',
    'attend port-added: Port 3000 is now published',
    'attend port-added: Port 5432 is now published',
    'info route-removed: Route removed: GET /old',
    'info link-added: Now calls billing: docker-compose.yml: services.shop.depends_on billing',
    'info link-added: Now calls api.stripe.com (outside service): .env: STRIPE=https://api.stripe.com',
    'info link-removed: No longer calls ledger',
  ].sort((a, b) => ['act', 'attend', 'info', 'good'].indexOf(a.split(' ')[0]!) - ['act', 'attend', 'info', 'good'].indexOf(b.split(' ')[0]!)));
  assert.equal(wideningCount(changes), 5);
  assert.equal(changes[0]!.route, 'POST /admin/export');
  assert.equal(changes[0]!.findings, 1);

  // The other direction narrows the surface.
  const back = surfaceDiff(prev, cur);
  assert.ok(back.some((c) => c.level === 'good' && c.text === 'POST /admin/export is now behind requireAuth'));
  assert.ok(back.some((c) => c.level === 'good' && c.text === 'Service now binds to loopback only'));
  assert.ok(back.some((c) => c.level === 'info' && c.text === 'Internet reach is no longer confirmed (was internet)'));
  assert.ok(back.some((c) => c.level === 'good' && c.text === 'Port 5432 is no longer published'));
  assert.ok(back.some((c) => c.level === 'info' && c.text === 'Route removed: POST /export'), back.map((c) => c.text).join('\n'));
  assert.equal(back[back.length - 1]!.level, 'good', 'narrowing changes sort last');

  // Traffic: a route that went from quiet to public, and one that went quiet.
  const p2 = report([entry('POST', '/preview', false, { requests: 0, public: 0, internal: 0 }), entry('GET', '/go', false, { requests: 10, public: 10, internal: 0 })], entry('POST', '/preview', false, { requests: 0, public: 0, internal: 0 }));
  const c2 = report([entry('POST', '/preview', false, { requests: 300, public: 280, internal: 20 }), entry('GET', '/go', false, { requests: 2, public: 0, internal: 2 })], entry('POST', '/preview', false, { requests: 300, public: 280, internal: 20 }));
  const t = surfaceDiff(c2, p2);
  assert.deepEqual(t.map((c) => `${c.level} ${c.kind}`), ['act traffic-public', 'info traffic-quiet']);
  assert.equal(t[0]!.text, 'Public traffic has started on POST /preview: 280 requests from public addresses; reaches 1 finding, worst Fix now');

  // No previous report, or identical reports: nothing.
  assert.deepEqual(surfaceDiff(cur, undefined), []);
  assert.deepEqual(surfaceDiff(cur, structuredClone(cur)), []);
  const d = diffReports(cur, prev);
  assert.equal(d.surface.length, changes.length);
  assert.equal(d.summary.surface, 5);
});
