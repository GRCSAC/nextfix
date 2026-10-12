import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dispatch, makeContext } from './core.ts';
import { matchHost, portfolioMap, routes } from './surface.ts';
import { proposeException } from './exceptions.ts';
import { ADMIN, VIEWER, LODASH, ago, openDb, reportWith } from './testing.ts';
import type { ScanReport } from '../../../engine/src/types.ts';

function withLinks(r: ScanReport, names: string[], hosts: string[], outbound: { host: string; evidence?: string; external?: boolean }[], reach?: 'internet' | 'internal'): ScanReport {
  r.links = { identity: { names, hosts }, outbound: outbound.map((l) => ({ host: l.host, kind: 'compose', evidence: l.evidence ?? `docker-compose.yml: ${l.host}`, external: l.external ?? false })) };
  if (reach) {
    r.exposure = { ...r.exposure, reach, reachEvidence: [reach === 'internet' ? 'infra/alb.tf: aws_lb "x" is internet-facing' : 'infra/alb.tf: aws_lb "x" is internal'] };
    for (const f of r.findings) f.exposure = r.exposure;
  }
  return r;
}

test('matchHost: exact names, cluster-local first labels, and host suffixes', () => {
  const keys = new Map<number, Set<string>>([[1, new Set(['shop', 'shop.acme.com'])], [2, new Set(['billing'])], [3, new Set(['shop'])]]);
  assert.deepEqual(matchHost('billing', keys, 1), [2]);
  assert.deepEqual(matchHost('billing:8080', keys, 1), [2]);
  assert.deepEqual(matchHost('billing.default.svc.cluster.local', keys, 1), [2]);
  assert.deepEqual(matchHost('api.shop.acme.com', keys, 2), [1], 'a sub-host of a known host');
  assert.deepEqual(matchHost('shop', keys, 1), [3], 'never itself');
  assert.deepEqual(matchHost('api.stripe.com', keys, 1), []);
  assert.deepEqual(matchHost('billing.example.com', keys, 1), [], 'a public domain does not match a bare service name');
});

test('portfolio map: edges from links to known applications, external hosts, internet-facing nodes, blast radius both ways; viewers may read it', async () => {
  const f = openDb();
  try {
    const shop = f.store.upsertTarget('C:/x/shop', 'shop');
    const billing = f.store.upsertTarget('C:/x/billing', 'billing');
    const ledger = f.store.upsertTarget('C:/x/ledger', 'ledger');
    const fresh = f.store.upsertTarget('C:/x/fresh', 'fresh');
    // shop (internet-facing) → billing → ledger; shop also calls stripe and an unknown "search"
    f.store.addScan(shop.id, withLinks(reportWith([LODASH], ago(1), () => {}, 'shop'), ['shop', 'shop-api'], ['shop.acme.com'], [{ host: 'billing', evidence: 'docker-compose.yml: services.shop.depends_on billing' }, { host: 'api.stripe.com', external: true }, { host: 'search' }], 'internet'));
    f.store.addScan(billing.id, withLinks(reportWith([LODASH], ago(1), (x) => { x.decision = 'Attend'; }, 'billing'), ['billing'], [], [{ host: 'ledger.default.svc.cluster.local', evidence: 'k8s/deploy.yaml: Deployment billing env' }, { host: 'api.stripe.com', external: true }], 'internal'));
    f.store.addScan(ledger.id, withLinks(reportWith([], ago(1), () => {}, 'ledger'), ['ledger'], [], []));

    const m = portfolioMap(f.db);
    assert.deepEqual(m.nodes.map((n) => n.name), ['billing', 'fresh', 'ledger', 'shop']);
    const node = (name: string) => m.nodes.find((n) => n.name === name)!;
    assert.deepEqual(m.edges.map((e) => `${e.from}->${e.to} ${e.host}`), [`${billing.id}->${ledger.id} ledger.default.svc.cluster.local`, `${shop.id}->${billing.id} billing`]);
    assert.equal(m.edges[1]!.evidence, 'docker-compose.yml: services.shop.depends_on billing');
    assert.deepEqual(m.internet, [shop.id]);
    assert.equal(node('shop').reach, 'internet');
    assert.equal(node('billing').reach, 'internal');
    assert.equal(node('ledger').reach, 'unknown');
    assert.equal(node('shop').posture, 'Exposed');
    assert.match(node('shop').headline ?? '', /^One vulnerability is reachable without a login/);
    assert.equal(node('billing').posture, 'Attention');
    assert.equal(node('fresh').posture, 'Never scanned');
    // blast radius
    assert.deepEqual(node('ledger').upstream, [shop.id, billing.id].sort((a, b) => a - b), 'ledger is depended on by billing, and through it by shop');
    assert.deepEqual(node('shop').downstream, [billing.id, ledger.id].sort((a, b) => a - b));
    assert.deepEqual(node('shop').upstream, []);
    assert.deepEqual(node('fresh').downstream, []);
    // external hosts, busiest first, with their callers
    assert.deepEqual(m.external.map((x) => [x.host, x.external, x.callers.length]), [['api.stripe.com', true, 2], ['search', false, 1]]);

    // an exception that clears shop's Act changes its posture on the map too
    proposeException(f.db, { targetId: shop.id, findingId: LODASH, kind: 'mitigated', reason: 'WAF rule 12 blocks the template parameter', user: ADMIN });
    assert.equal(portfolioMap(f.db).nodes.find((n) => n.name === 'shop')!.posture, 'Clean');

    // the route, as a viewer
    const out = await dispatch(routes, 'GET', '/api/portfolio/map', makeContext(f.db, { user: VIEWER }));
    assert.equal((out.body as { nodes: unknown[] }).nodes.length, 4);
  } finally {
    f.close();
  }
});
