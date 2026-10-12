import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dispatch, FeatureError, makeContext } from './core.ts';
import { proposeException } from './exceptions.ts';
import { portfolio, routes, verdict, type PortfolioRow, type TargetMeta } from './portfolio.ts';
import { ADMIN, ANALYST, VIEWER, LODASH, ago, openDb, reportWith } from './testing.ts';

const Y = 'pkg:npm/lodash@4.17.15|GHSA-y';
const Z = 'pkg:npm/lodash@4.17.15|GHSA-z';

test('portfolio: posture, SLA age, trend and exceptions from two seeded targets plus one never scanned', async () => {
  const f = openDb();
  try {
    // shop: three scans; the latest has an Act finding first seen 12 days ago (past the 7-day SLA) and an Attend one
    const shop = f.store.upsertTarget('C:/x/shop', 'shop');
    f.store.addScan(shop.id, reportWith([LODASH], ago(12), () => {}, 'shop'));
    f.store.addScan(shop.id, reportWith([LODASH, Y], ago(6), (x, i) => { if (i === 1) x.decision = 'Attend'; }, 'shop'));
    f.store.addScan(shop.id, reportWith([LODASH, Y, Z], ago(1), (x, i) => { if (i === 1) x.decision = 'Attend'; if (i === 2) { x.decision = 'Track'; x.reach.tier = 'unused'; x.reach.paths = []; } }, 'shop'));
    // api: one Attend finding behind auth, first seen 40 days ago (past the 30-day SLA), then excepted
    const api = f.store.upsertTarget('C:/x/api', 'api');
    const apiReport = (at: string) => {
      const r = reportWith([Y], at, (x) => { x.decision = 'Attend'; x.reach.paths[0]!.entry = { ...x.reach.paths[0]!.entry, authenticated: true, guards: ['requireLogin'] }; }, 'api');
      r.entryPoints[0] = { ...r.entryPoints[0]!, authenticated: true, guards: ['requireLogin'] };
      return r;
    };
    f.store.addScan(api.id, apiReport(ago(40)));
    f.store.addScan(api.id, apiReport(ago(2)));
    // fresh: never scanned
    const fresh = f.store.upsertTarget('C:/x/fresh', 'fresh');

    let rows = portfolio(f.db).targets;
    assert.deepEqual(rows.map((r) => r.name), ['api', 'fresh', 'shop'], 'sorted by name');
    const byName = (name: string) => rows.find((r) => r.name === name)!;

    const s = byName('shop');
    assert.equal(s.posture, 'Exposed');
    assert.deepEqual(s.byDecision, { Act: 1, Attend: 1, 'Track*': 0, Track: 1 });
    assert.deepEqual(s.trend, [1, 2, 2], 'actionable per scan, oldest first');
    assert.equal(s.oldestPastSlaDays, 5, 'Act first seen 12 days ago, SLA 7');
    assert.deepEqual(s.exposedSurface, { open: 1, total: 2 }, 'POST /preview is reached, GET /health is not');
    assert.equal(s.pendingExceptions, 0);
    assert.equal(s.lastScanId, 3);
    assert.equal(s.owner, null);
    assert.equal(s.schedule, null);
    assert.match(s.headline, /^One vulnerability is reachable without a login, carries request data, and has a 42% chance of exploitation within 30 days\.$/);

    const a = byName('api');
    assert.equal(a.posture, 'Attention');
    assert.equal(a.oldestPastSlaDays, 10, 'Attend first seen 40 days ago, SLA 30');
    assert.deepEqual(a.exposedSurface, { open: 0, total: 1 }, 'the vulnerable route is behind auth; /health is open but clean');

    const n = byName('fresh');
    assert.equal(n.posture, 'Never scanned');
    assert.equal(n.lastScanAt, undefined);
    assert.deepEqual(n.trend, []);
    assert.equal(n.id, fresh.id);

    // a pending exception counts; an approved one changes the posture and takes the finding off the SLA list
    proposeException(f.db, { targetId: shop.id, findingId: Y, kind: 'accepted-risk', reason: 'Accepted until the Q4 upgrade window', user: ANALYST });
    proposeException(f.db, { targetId: api.id, findingId: Y, kind: 'mitigated', reason: 'Gateway strips the template parameter', user: ADMIN });
    rows = portfolio(f.db).targets;
    assert.equal(rows.find((r) => r.name === 'shop')!.pendingExceptions, 1);
    const a2 = rows.find((r) => r.name === 'api')!;
    assert.equal(a2.posture, 'Clean');
    assert.deepEqual(a2.byDecision, { Act: 0, Attend: 0, 'Track*': 0, Track: 1 });
    assert.equal(a2.oldestPastSlaDays, undefined);
    assert.equal(a2.pendingExceptions, 0);

    // a tighter SLA from settings
    f.store.setSetting('slaActDays', 3);
    assert.equal(portfolio(f.db).targets.find((r) => r.name === 'shop')!.oldestPastSlaDays, 9);

    // the route is open to viewers
    const viaRoute = (await dispatch(routes, 'GET', '/api/portfolio', makeContext(f.db, { user: VIEWER }))).body as { targets: PortfolioRow[] };
    assert.equal(viaRoute.targets.length, 3);
    const anonymous = (await dispatch(routes, 'GET', '/api/portfolio', makeContext(f.db))).body as { targets: PortfolioRow[] };
    assert.equal(anonymous.targets.length, 3, 'no user means viewer while auth is not wired');
  } finally {
    f.close();
  }
});

test('PATCH /api/targets/:id: owner and schedule, validated, analyst only', async () => {
  const f = openDb();
  try {
    const t = f.store.upsertTarget('C:/x/shop', 'shop');
    const ctx = (user = ANALYST, body: Record<string, unknown> = {}) => makeContext(f.db, { user, body });
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(VIEWER, { owner: 'platform' })), (e: unknown) => e instanceof FeatureError && e.status === 403);
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/999`, ctx(ANALYST, { owner: 'platform' })), (e: unknown) => e instanceof FeatureError && e.status === 404);
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { schedule: { everyHours: 0 } })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { schedule: 'daily' })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { owner: 'x'.repeat(201) })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    const audited: unknown[] = [];
    let meta = (await dispatch(routes, 'PATCH', `/api/targets/${t.id}`, makeContext(f.db, { user: ANALYST, body: { owner: '  platform team ', schedule: { everyHours: 24 }, bogus: 1 }, audit: (a, target, d) => audited.push([a, target, d]) }))).body as TargetMeta;
    assert.deepEqual(meta, { id: t.id, name: 'shop', dir: 'C:/x/shop', owner: 'platform team', schedule: { everyHours: 24 }, accessLogs: [] });
    assert.deepEqual(audited, [['target.update', `target:${t.id}`, { owner: 'platform team', schedule: { everyHours: 24 } }]]);
    // keys left out are untouched; null clears
    meta = (await dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { schedule: null }))).body as TargetMeta;
    assert.equal(meta.owner, 'platform team');
    assert.equal(meta.schedule, null);
    // access logs: a trimmed, de-duplicated list; empty clears; shape and size are checked
    meta = (await dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { accessLogs: [' /var/log/nginx/access.log ', 'logs', '/var/log/nginx/access.log', ''] }))).body as TargetMeta;
    assert.deepEqual(meta.accessLogs, ['/var/log/nginx/access.log', 'logs']);
    assert.equal(meta.owner, 'platform team', 'other fields untouched');
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { accessLogs: 'logs' })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { accessLogs: Array.from({ length: 21 }, (_, i) => `l${i}`) })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { accessLogs: ['a\nb'] })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    meta = (await dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { accessLogs: [] }))).body as TargetMeta;
    assert.deepEqual(meta.accessLogs, []);
    meta = (await dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { owner: '' }))).body as TargetMeta;
    assert.equal(meta.owner, null);
    // the columns are where the migration put them
    const raw = f.db.prepare('SELECT owner, schedule_hours FROM targets WHERE id = ?').get(t.id) as { owner: string | null; schedule_hours: number | null };
    assert.deepEqual({ ...raw }, { owner: null, schedule_hours: null });
    // the portfolio reflects them
    await dispatch(routes, 'PATCH', `/api/targets/${t.id}`, ctx(ANALYST, { owner: 'ops', schedule: { everyHours: 6 } }));
    const row = portfolio(f.db).targets[0]!;
    assert.equal(row.owner, 'ops');
    assert.deepEqual(row.schedule, { everyHours: 6 });
  } finally {
    f.close();
  }
});

test('verdict: the four postures and their sentences', () => {
  const act = reportWith([LODASH], ago(1));
  assert.equal(verdict(act).posture, 'Exposed');
  assert.equal(verdict(act).findingId, LODASH);
  const kev = reportWith([LODASH, Y], ago(1), (x) => { x.kev = { dateAdded: '2026-10-01', ransomware: true }; });
  assert.equal(verdict(kev).headline, "2 vulnerabilities are reachable without a login, carry request data, and the worst is on CISA's known-exploited list.");
  const attend = reportWith([LODASH, Y], ago(1), (x, i) => { x.decision = 'Attend'; if (i === 1) x.reach.paths[0]!.entry = { ...x.reach.paths[0]!.entry, authenticated: true }; });
  assert.equal(verdict(attend).posture, 'Attention');
  assert.equal(verdict(attend).headline, '2 findings need fixing in the next release cycle; nothing is both reachable without a login and known to be exploited.');
  assert.equal(verdict(attend).detail, '1 of them is reachable without a login.');
  const watch = reportWith([LODASH], ago(1), (x) => { x.decision = 'Track*'; });
  assert.equal(verdict(watch).posture, 'Contained');
  assert.equal(verdict(watch).headline, '1 finding is being watched; nothing needs a fix this cycle.');
  const aside = reportWith([LODASH, Y], ago(1), (x) => { x.decision = 'Track'; });
  assert.equal(verdict(aside).posture, 'Clean');
  assert.equal(verdict(aside).headline, '2 findings, all set aside with evidence; nothing needs action.');
  assert.equal(verdict(reportWith([], ago(1))).headline, 'No findings. Keep scanning after each release.');
});
