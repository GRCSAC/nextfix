import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import type { ChangedFinding } from '../diff.ts';
import { dispatch, FeatureError, makeContext } from './core.ts';
import { proposeException, listExceptions } from './exceptions.ts';
import { dueTargets, isNightlyDue, lastOccurrence, listRedecideEvents, parseClock, redecideReport, routes, runRedecideAll, startScheduler, REDECIDE_LAST_RUN_KEY, type RedecideEvent } from './schedule.ts';
import { ADMIN, VIEWER, LODASH, DAY_MS, ago, openDb, reportWith } from './testing.ts';

const HOUR_MS = 3_600_000;
const Y = 'pkg:npm/lodash@4.17.15|GHSA-y';

/** A local-time instant: today at hh:mm. */
function todayAt(h: number, m: number, base = new Date()): number {
  const d = new Date(base);
  d.setHours(h, m, 0, 0);
  return d.getTime();
}

test('dueTargets: schedule hours against the last scan, with an injected clock', () => {
  const f = openDb();
  try {
    const now = Date.now();
    const a = f.store.upsertTarget('C:/x/a', 'a'); // every 6 h, last scan 7 h ago: due
    const b = f.store.upsertTarget('C:/x/b', 'b'); // every 24 h, last scan 2 h ago: not due
    const c = f.store.upsertTarget('C:/x/c', 'c'); // scheduled, never scanned: due
    f.store.upsertTarget('C:/x/d', 'd'); // no schedule: never due
    f.store.addScan(a.id, reportWith([LODASH], new Date(now - 7 * HOUR_MS).toISOString()));
    f.store.addScan(b.id, reportWith([LODASH], new Date(now - 2 * HOUR_MS).toISOString()));
    f.db.prepare('UPDATE targets SET schedule_hours = ? WHERE id = ?').run(6, a.id);
    f.db.prepare('UPDATE targets SET schedule_hours = ? WHERE id = ?').run(24, b.id);
    f.db.prepare('UPDATE targets SET schedule_hours = ? WHERE id = ?').run(1, c.id);
    assert.deepEqual(dueTargets(f.db, now).map((t) => t.id), [a.id, c.id]);
    assert.deepEqual(dueTargets(f.db, now + 23 * HOUR_MS).map((t) => t.id), [a.id, b.id, c.id], 'b comes due 24 h after its scan');
    assert.deepEqual(dueTargets(f.db, now - 2 * HOUR_MS).map((t) => t.id), [c.id], 'two hours earlier a was 5 h old, inside its 6 h');
    assert.deepEqual(dueTargets(f.db, now - HOUR_MS).map((t) => t.id), [a.id, c.id], 'at exactly 6 h a is due');
  } finally {
    f.close();
  }
});

test('nightly due-logic: once per day after the configured clock time, restart-safe', () => {
  assert.equal(parseClock('03:00'), 180);
  assert.equal(parseClock('23:59'), 23 * 60 + 59);
  assert.equal(parseClock('25:00'), 180, 'bad input falls back to 03:00');
  assert.equal(parseClock(undefined), 180);
  const at = '03:00';
  const twoAm = todayAt(2, 0);
  const fourAm = todayAt(4, 0);
  assert.equal(lastOccurrence(fourAm, 180), todayAt(3, 0));
  assert.equal(lastOccurrence(twoAm, 180), todayAt(3, 0) - DAY_MS, 'before 03:00 the last occurrence was yesterday');
  assert.equal(isNightlyDue(undefined, fourAm, at), true, 'never run: due');
  assert.equal(isNightlyDue(new Date(fourAm - 30 * 60_000).toISOString(), fourAm, at), false, 'ran at 03:30 today: not due again');
  assert.equal(isNightlyDue(new Date(fourAm - DAY_MS).toISOString(), fourAm, at), true, 'ran yesterday at 04:00: due');
  assert.equal(isNightlyDue(new Date(twoAm - HOUR_MS).toISOString(), twoAm, at), false, 'ran at 01:00, now 02:00: yesterday\'s slot already covered');
  assert.equal(isNightlyDue(new Date(twoAm - 2 * DAY_MS).toISOString(), twoAm, at), true, 'ran two days ago: due');
});

test('scheduler tick: scans due targets through runScan, runs the nightly re-decide once and records the promotions', async () => {
  const f = openDb();
  try {
    const now = todayAt(4, 0);
    const a = f.store.upsertTarget('C:/x/a', 'a');
    const b = f.store.upsertTarget('C:/x/b', 'b');
    f.store.addScan(a.id, reportWith([LODASH, Y], new Date(now - 10 * HOUR_MS).toISOString(), (x) => { x.decision = 'Attend'; }, 'a'));
    f.store.addScan(b.id, reportWith([LODASH], new Date(now - HOUR_MS).toISOString(), () => {}, 'b'));
    f.db.prepare('UPDATE targets SET schedule_hours = 6 WHERE id = ?').run(a.id);
    f.db.prepare('UPDATE targets SET schedule_hours = 6 WHERE id = ?').run(b.id);
    // an approved exception that expires before "now" gets flipped by the tick
    proposeException(f.db, { targetId: b.id, findingId: LODASH, kind: 'mitigated', reason: 'Temporary gateway rule for the quarter', user: ADMIN, now: new Date(now - 3 * DAY_MS).toISOString(), expiresAt: new Date(now - DAY_MS).toISOString().slice(0, 10) });

    const scanned: number[] = [];
    const redecided: string[] = [];
    const logs: string[] = [];
    const fakeRedecide = async (report: { target: { name?: string }; findings: { id: string; decision: string }[] }): Promise<ChangedFinding[]> => {
      redecided.push(report.target.name ?? '?');
      // every Attend finding is promoted to Act, Act ones are left alone
      return report.findings.filter((x) => x.decision === 'Attend').map((x) => ({ finding: { ...x, decision: 'Act' } as unknown as ChangedFinding['finding'], from: 'Attend' as const, to: 'Act' as const, reasons: ['decision Attend → Act', 'entered KEV'] }));
    };
    const s = startScheduler({ db: f.db, runScan: async (id) => { scanned.push(id); }, redecide: fakeRedecide, log: (m) => logs.push(m), now: () => now, tickMs: 60_000, redecideAt: '03:00', digest: false });
    try {
      const r1 = await s.tick();
      assert.deepEqual(r1.scanned, [a.id], 'a is 10 h old on a 6 h schedule; b is 1 h old');
      assert.equal(r1.redecided, true, '04:00 is past the 03:00 slot and it never ran');
      assert.deepEqual(r1.errors, []);
      assert.deepEqual(redecided, ['a', 'b'], 'every scanned target is re-decided');
      assert.equal(listExceptions(f.db, b.id)[0]!.status, 'expired', 'the tick ran the expiry pass');

      const events = listRedecideEvents(f.db, a.id);
      assert.equal(events.length, 2);
      assert.deepEqual(events.map((e) => [e.findingId, e.from, e.to, e.promoted]).sort(), [[LODASH, 'Attend', 'Act', true], [Y, 'Attend', 'Act', true]]);
      assert.deepEqual(events[0]!.reasons, ['decision Attend → Act', 'entered KEV']);
      assert.equal(events[0]!.at, new Date(now).toISOString());
      assert.equal(listRedecideEvents(f.db, b.id).length, 0, 'b had nothing to promote');
      const last = f.db.prepare('SELECT value FROM settings WHERE key = ?').get(REDECIDE_LAST_RUN_KEY) as { value: string };
      assert.equal(JSON.parse(last.value), new Date(now).toISOString());

      // a second tick a minute later: the nightly pass does not repeat; a is scanned again only because the
      // fake runScan stored nothing (the server's runScan adds the scan, which is what resets the clock)
      const r2 = await s.tick(now + 60_000);
      assert.deepEqual(r2.scanned, [a.id]);
      assert.equal(r2.redecided, false);
      f.store.addScan(a.id, reportWith([LODASH, Y], new Date(now).toISOString(), (x) => { x.decision = 'Attend'; }, 'a'));
      const r2b = await s.tick(now + 120_000);
      assert.deepEqual(r2b.scanned, [], 'with a fresh scan stored, a is no longer due');
    } finally {
      s.stop();
    }
    // Scans within a tick run one after another, and a tick that overlaps a running one is a no-op.
    const order: string[] = [];
    const s2 = startScheduler({ db: f.db, runScan: async (id) => { order.push(`start ${id}`); await new Promise((r) => setTimeout(r, 5)); order.push(`end ${id}`); }, redecide: fakeRedecide, now: () => now, redecideAt: '03:00', digest: false });
    try {
      f.db.prepare('UPDATE targets SET schedule_hours = 1').run();
      const [r3, r4] = await Promise.all([s2.tick(now + 2 * HOUR_MS), s2.tick(now + 2 * HOUR_MS)]);
      assert.deepEqual(order, [`start ${a.id}`, `end ${a.id}`, `start ${b.id}`, `end ${b.id}`], 'scans run one after another');
      assert.deepEqual([r3.scanned.length, r4.scanned.length].sort(), [0, 2], 'the overlapping tick is a no-op');
      assert.equal(r3.redecided || r4.redecided, false, 'the nightly pass already ran today');
    } finally {
      s2.stop();
    }

    // a failing scan is reported, not fatal, and the next target still runs
    const s3 = startScheduler({ db: f.db, runScan: async (id) => { if (id === a.id) throw new Error('A scan is already running'); }, redecide: fakeRedecide, now: () => now + DAY_MS, redecideAt: '03:00', digest: false, log: (m) => logs.push(m) });
    try {
      const r5 = await s3.tick();
      assert.deepEqual(r5.scanned, [b.id]);
      assert.equal(r5.errors.length, 1);
      assert.match(r5.errors[0]!, /scan of target \d+ failed: A scan is already running/);
      assert.equal(r5.redecided, true, 'a day later the nightly pass runs again');
    } finally {
      s3.stop();
    }
    assert.equal(listRedecideEvents(f.db, a.id).length, 4, 'two more promotions recorded by the second pass');

    // the route, with since
    const sinceLater = new Date(now + DAY_MS - 1000).toISOString();
    const viaRoute = (await dispatch(routes, 'GET', `/api/targets/${a.id}/redecide-events`, makeContext(f.db, { user: VIEWER, query: { since: sinceLater } }))).body as RedecideEvent[];
    assert.equal(viaRoute.length, 2);
    assert.ok(viaRoute.every((e) => e.at >= sinceLater));
    await assert.rejects(dispatch(routes, 'GET', `/api/targets/${a.id}/redecide-events`, makeContext(f.db, { query: { since: 'yesterday' } })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'GET', `/api/targets/999/redecide-events`, makeContext(f.db)), (e: unknown) => e instanceof FeatureError && e.status === 404);
  } finally {
    f.close();
  }
});

test('redecideReport: the copied re-decide step promotes a finding when the cache says it entered KEV', async () => {
  const f = openDb();
  try {
    const target = f.store.upsertTarget('C:/x/redecide', 'redecide');
    const report = reportWith([LODASH], ago(1), (x) => {
      x.decision = 'Attend';
      x.epss = undefined;
      x.reach.paths[0]!.entry = { ...x.reach.paths[0]!.entry, authenticated: true, guards: ['requireLogin'] };
    });
    f.store.addScan(target.id, report);
    const cachePath = join(f.dir, 'cache.sqlite');
    const cache = new DatabaseSync(cachePath);
    cache.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp INTEGER NOT NULL)');
    const exp = Date.now() + DAY_MS;
    cache.prepare('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?)').run('kev:catalog', JSON.stringify({ 'CVE-2021-23337': { dateAdded: '2026-10-01', ransomware: false } }), exp);
    cache.prepare('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?)').run('epss:CVE-2021-23337', 'null', exp);
    cache.close();
    const changed = await redecideReport(report, cachePath);
    assert.equal(changed.length, 1);
    assert.equal(changed[0]!.from, 'Attend');
    assert.equal(changed[0]!.to, 'Act');
    assert.deepEqual(changed[0]!.reasons, ['decision Attend → Act', 'entered KEV']);
    const summary = await runRedecideAll(f.db, (r) => redecideReport(r, cachePath), new Date().toISOString());
    assert.deepEqual(summary, { targets: 1, changed: 1 });
    assert.equal(listRedecideEvents(f.db, target.id)[0]!.scanId, 1);
  } finally {
    f.close();
  }
});
