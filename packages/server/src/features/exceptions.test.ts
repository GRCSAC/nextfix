import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toOpenVex } from '../../../engine/src/report/vex.ts';
import { dispatch, FeatureError, makeContext } from './core.ts';
import { applyExceptions, expireExceptions, listExceptions, proposeException, reviewException, routes, toVexException, type ExceptionRow } from './exceptions.ts';
import { ADMIN, ANALYST, VIEWER, LODASH, ago, fakeReport, openDb, reportWith } from './testing.ts';

const Y = 'pkg:npm/lodash@4.17.15|GHSA-y';

async function expectStatus(p: Promise<unknown>, status: number, label: string) {
  await assert.rejects(p, (err: unknown) => err instanceof FeatureError && err.status === status, `${label}: expected ${status}`);
}

test('exceptions: propose, approve, revoke; one active per finding; roles', async () => {
  const f = openDb();
  try {
    const target = f.store.upsertTarget('C:/x/shop', 'shop');
    f.store.addScan(target.id, reportWith([LODASH, Y], ago(1)));
    const ctx = (user = ANALYST, body: Record<string, unknown> = {}) => makeContext(f.db, { user, body });

    // a viewer cannot propose
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(VIEWER, { findingId: LODASH, kind: 'mitigated', reason: 'WAF blocks the template parameter' })), 403, 'viewer');
    // validation
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'mitigated', reason: 'short' })), 400, 'short reason');
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'bogus', reason: 'WAF blocks the template parameter' })), 400, 'bad kind');
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'mitigated', reason: 'WAF blocks the template parameter', expiresAt: ago(-800).slice(0, 10) })), 400, 'expiry over 2 years');
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'mitigated', reason: 'WAF blocks the template parameter', expiresAt: 'next week' })), 400, 'bad expiry');
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: 'pkg:npm/nope@1|GHSA-z', kind: 'mitigated', reason: 'WAF blocks the template parameter' })), 404, 'finding not in scan');
    await expectStatus(dispatch(routes, 'POST', `/api/targets/999/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'mitigated', reason: 'WAF blocks the template parameter' })), 404, 'no target');

    // an analyst's proposal is pending
    const audited: string[] = [];
    const proposed = await dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, makeContext(f.db, { user: ANALYST, body: { findingId: LODASH, kind: 'mitigated', reason: 'WAF blocks the template parameter', expiresAt: ago(-30).slice(0, 10) }, audit: (a) => audited.push(a) }));
    assert.equal(proposed.status, 201);
    const row = proposed.body as ExceptionRow;
    assert.equal(row.status, 'pending');
    assert.equal(row.proposedBy, 'ana');
    assert.equal(row.approvedBy, null);
    assert.equal(typeof row.id, 'string');
    assert.ok(row.expiresAt!.endsWith('T23:59:59.999Z'), 'expiry normalised to end of day');
    assert.deepEqual(audited, ['exception.propose']);

    // a second active exception on the same finding is refused, even with a different kind
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'accepted-risk', reason: 'We accept this until the next release' })), 409, 'duplicate');

    // only an admin reviews
    await expectStatus(dispatch(routes, 'PATCH', `/api/exceptions/${row.id}`, ctx(ANALYST, { status: 'approved' })), 403, 'analyst review');
    await expectStatus(dispatch(routes, 'PATCH', `/api/exceptions/${row.id}`, ctx(ADMIN, { status: 'expired' })), 400, 'bad status');
    await expectStatus(dispatch(routes, 'PATCH', `/api/exceptions/${row.id}`, ctx(ADMIN, { status: 'revoked' })), 409, 'revoke a pending one');
    const approved = (await dispatch(routes, 'PATCH', `/api/exceptions/${row.id}`, ctx(ADMIN, { status: 'approved', reason: 'Confirmed with the WAF rule set' }))).body as ExceptionRow;
    assert.equal(approved.status, 'approved');
    assert.equal(approved.approvedBy, 'root');
    assert.equal(approved.reviewNote, 'Confirmed with the WAF rule set');
    await expectStatus(dispatch(routes, 'PATCH', `/api/exceptions/${row.id}`, ctx(ADMIN, { status: 'approved' })), 409, 'approve twice');
    // still one active: a new proposal is still refused
    await expectStatus(dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'false-positive', reason: 'The template function is not the vulnerable one' })), 409, 'duplicate after approval');

    // revoke, then a new proposal is allowed
    const revoked = (await dispatch(routes, 'PATCH', `/api/exceptions/${row.id}`, ctx(ADMIN, { status: 'revoked' }))).body as ExceptionRow;
    assert.equal(revoked.status, 'revoked');
    assert.equal(revoked.approvedBy, 'root', 'the approver is kept on a revoked row');
    const again = (await dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ANALYST, { findingId: LODASH, kind: 'false-positive', reason: 'The template function is not the vulnerable one' }))).body as ExceptionRow;
    assert.equal(again.status, 'pending');
    const rejected = (await dispatch(routes, 'PATCH', `/api/exceptions/${again.id}`, ctx(ADMIN, { status: 'rejected', reason: 'It is the vulnerable one' }))).body as ExceptionRow;
    assert.equal(rejected.status, 'rejected');
    assert.equal(rejected.approvedBy, null);

    // an admin's own proposal is approved on the spot (and that admin is the approver)
    const own = (await dispatch(routes, 'POST', `/api/targets/${target.id}/exceptions`, ctx(ADMIN, { findingId: Y, kind: 'accepted-risk', reason: 'Accepted until the Q4 upgrade window' }))).body as ExceptionRow;
    assert.equal(own.status, 'approved');
    assert.equal(own.approvedBy, 'root');
    assert.equal(own.expiresAt, null);

    // the list, newest first, is readable by a viewer and refused to no one
    const list = (await dispatch(routes, 'GET', `/api/targets/${target.id}/exceptions`, ctx(VIEWER))).body as ExceptionRow[];
    assert.deepEqual(list.map((e) => [e.findingId, e.status]), [[Y, 'approved'], [LODASH, 'rejected'], [LODASH, 'revoked']]);
    await expectStatus(dispatch(routes, 'GET', `/api/targets/999/exceptions`, ctx(VIEWER)), 404, 'list of missing target');
    await expectStatus(dispatch(routes, 'GET', `/api/nothing`, ctx(VIEWER)), 404, 'unknown route');
    await expectStatus(dispatch(routes, 'DELETE', `/api/targets/${target.id}/exceptions`, ctx(ADMIN)), 405, 'unknown method');

    // without a signed-in user (auth not wired) the proposer is recorded as "local" and nothing is auto-approved
    const anon = proposeException(f.db, { targetId: target.id, findingId: LODASH, kind: 'mitigated', reason: 'Rate limiting on the preview endpoint', user: null });
    assert.equal(anon.status, 'pending');
    assert.equal(anon.proposedBy, 'local');
  } finally {
    f.close();
  }
});

test('applyExceptions: an approved exception moves the finding to Track with a why line; pending and expired ones only annotate', () => {
  const f = openDb();
  try {
    const target = f.store.upsertTarget('C:/x/apply', 'apply');
    const report = reportWith([LODASH, Y], ago(1), (x, i) => {
      if (i === 1) x.decision = 'Attend';
    });
    f.store.addScan(target.id, report);
    const now = '2026-10-10T12:00:00.000Z';
    const approved = proposeException(f.db, { targetId: target.id, findingId: LODASH, kind: 'mitigated', reason: 'WAF blocks the template parameter', expiresAt: '2026-12-31', user: ADMIN, now });
    const pending = proposeException(f.db, { targetId: target.id, findingId: Y, kind: 'accepted-risk', reason: 'Accepted until the Q4 upgrade window', user: ANALYST, now });

    const served = applyExceptions(report, listExceptions(f.db, target.id), now);
    assert.equal(report.findings[0]!.decision, 'Act', 'the input report is not mutated');
    const a = served.findings.find((x) => x.id === LODASH)!;
    assert.equal(a.decision, 'Track');
    assert.equal(a.why[0], 'Accepted by root on 2026-10-10: WAF blocks the template parameter');
    assert.equal(a.why[1], report.findings[0]!.why[0], 'the original why lines follow');
    assert.deepEqual({ id: a.exception!.id, kind: a.exception!.kind, status: a.exception!.status, expiresAt: a.exception!.expiresAt, reason: a.exception!.reason, approvedBy: a.exception!.approvedBy, originalDecision: a.exception!.originalDecision }, { id: approved.id, kind: 'mitigated', status: 'approved', expiresAt: '2026-12-31T23:59:59.999Z', reason: 'WAF blocks the template parameter', approvedBy: 'root', originalDecision: 'Act' });
    const p = served.findings.find((x) => x.id === Y)!;
    assert.equal(p.decision, 'Attend', 'a pending exception does not change the decision');
    assert.equal(p.exception!.id, pending.id);
    assert.equal(p.exception!.status, 'pending');
    assert.equal(p.exception!.originalDecision, undefined);
    assert.deepEqual(served.summary.byDecision, { Act: 0, Attend: 1, 'Track*': 0, Track: 1 });
    assert.equal(served.summary.noiseRemoved, 0.5);

    // past its expiry the approved one no longer applies, with or without the expiry pass
    const later = '2027-01-01T00:00:00.000Z';
    const stale = applyExceptions(report, listExceptions(f.db, target.id), later);
    assert.equal(stale.findings.find((x) => x.id === LODASH)!.decision, 'Act');
    assert.equal(expireExceptions(f.db, later), 1);
    assert.equal(expireExceptions(f.db, later), 0, 'idempotent');
    const rows = listExceptions(f.db, target.id);
    assert.equal(rows.find((e) => e.id === approved.id)!.status, 'expired');
    assert.equal(rows.find((e) => e.id === pending.id)!.status, 'pending', 'pending rows are not expired');
    const afterExpiry = applyExceptions(report, rows, later);
    const ex = afterExpiry.findings.find((x) => x.id === LODASH)!;
    assert.equal(ex.decision, 'Act');
    assert.equal(ex.exception!.status, 'expired', 'the finding still shows the expired exception');
    // an expired row no longer blocks a new proposal
    const renewed = proposeException(f.db, { targetId: target.id, findingId: LODASH, kind: 'mitigated', reason: 'WAF rule renewed for the new quarter', user: ANALYST, now: later });
    assert.equal(renewed.status, 'pending');
    // approving a proposal whose expiry has passed is refused
    reviewException(f.db, { id: pending.id, status: 'rejected', user: ADMIN });
    const old = proposeException(f.db, { targetId: target.id, findingId: Y, kind: 'mitigated', reason: 'Temporary mitigation in the gateway', user: null, now: '2026-10-01T00:00:00.000Z', expiresAt: '2026-10-05' });
    assert.throws(() => reviewException(f.db, { id: old.id, status: 'approved', user: ADMIN, now: later }), (err: unknown) => err instanceof FeatureError && err.status === 409);
  } finally {
    f.close();
  }
});

test('VEX: approved exceptions become the right OpenVEX statements; pending and expired ones do not', () => {
  const report = reportWith([LODASH, Y, 'pkg:npm/lodash@4.17.15|GHSA-z', 'pkg:npm/lodash@4.17.15|GHSA-w'], ago(1));
  const base = (findingId: string, kind: ExceptionRow['kind'], status: ExceptionRow['status'], expiresAt: string | null): ExceptionRow => ({
    id: '1',
    targetId: 1,
    findingId,
    kind,
    reason: 'Reviewed by the platform team',
    status,
    proposedBy: 'ana',
    approvedBy: status === 'approved' ? 'root' : null,
    reviewNote: null,
    expiresAt,
    createdAt: '2026-10-01T00:00:00.000Z',
    updatedAt: '2026-10-02T09:00:00.000Z',
  });
  const far = ago(-400);
  const exceptions = [
    base(LODASH, 'false-positive', 'approved', far),
    base(Y, 'mitigated', 'approved', null),
    base('pkg:npm/lodash@4.17.15|GHSA-z', 'accepted-risk', 'approved', far),
    base('pkg:npm/lodash@4.17.15|GHSA-w', 'accepted-risk', 'pending', null),
  ].map(toVexException);
  const doc = toOpenVex(report, exceptions) as { statements: Record<string, unknown>[] };
  const [fp, mit, risk, pend] = doc.statements;
  assert.equal(fp!.status, 'not_affected');
  assert.equal(fp!.justification, 'vulnerable_code_not_present');
  assert.match(String(fp!.impact_statement), /^False positive: Reviewed by the platform team \(approved by root on 2026-10-02, valid until \d{4}-\d{2}-\d{2}\)\.$/);
  assert.equal(mit!.status, 'not_affected');
  assert.equal(mit!.justification, 'inline_mitigations_already_exist');
  assert.match(String(mit!.impact_statement), /valid until revoked/);
  assert.equal(risk!.status, 'affected', 'accepted risk stays affected: OpenVEX has no justification for it');
  assert.equal(risk!.justification, undefined);
  assert.equal(risk!.action_statement, `Risk accepted by root until ${far.slice(0, 10)}: Reviewed by the platform team`);
  assert.equal(risk!.action_statement_timestamp, '2026-10-02T09:00:00.000Z');
  assert.match(String(risk!.impact_statement), /^Accepted risk: /);
  assert.equal(pend!.status, 'affected');
  assert.equal(pend!.action_statement, 'Upgrade lodash 4.17.15 → 4.17.21', 'a pending exception leaves the reachability statement alone');

  // an expired one is ignored even when passed
  const expired = toOpenVex(report, [{ ...toVexException(base(LODASH, 'mitigated', 'approved', ago(1))) }]) as { statements: Record<string, unknown>[] };
  assert.equal(expired.statements[0]!.status, 'affected');

  // a report the server already decorated carries the exception on the finding
  const served = applyExceptions(report, [base(Y, 'mitigated', 'approved', null)]);
  const fromFinding = toOpenVex(served) as { statements: Record<string, unknown>[] };
  assert.equal(fromFinding.statements[1]!.justification, 'inline_mitigations_already_exist');
  assert.equal(fromFinding.statements[0]!.status, 'affected');

  // the plain document is unchanged when no exceptions are passed
  const plain = toOpenVex(fakeReport()) as { statements: Record<string, unknown>[] };
  assert.equal(plain.statements[0]!.status, 'affected');
});
