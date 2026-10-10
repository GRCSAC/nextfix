import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createNetServer, type Socket } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { dispatch, FeatureError, makeContext, settingsFor } from './core.ts';
import { proposeException } from './exceptions.ts';
import { recordRedecideEvents } from './schedule.ts';
import {
  buildDigest,
  buildMessage,
  digestSubject,
  encodeHeader,
  getDigestSettings,
  isDigestDue,
  lastScheduledInstant,
  leverageSentence,
  mergeDigestSettings,
  publicDigestSettings,
  rfc5322Date,
  routes,
  sendDigestIfDue,
  sendMail,
  teamsCard,
  DIGEST_SETTING_KEY,
  type Digest,
  type DigestSettings,
  type PublicDigestSettings,
} from './digest.ts';
import { ADMIN, ANALYST, VIEWER, LODASH, DAY_MS, ago, openDb, reportWith } from './testing.ts';

const Y = 'pkg:npm/lodash@4.17.15|GHSA-y';
const Z = 'pkg:npm/lodash@4.17.15|GHSA-z';

// ---------------------------------------------------------------------------------------------
// Doubles

interface FakeSmtpOptions {
  /** Reject AUTH PLAIN so the client falls back to LOGIN. */
  rejectPlain?: boolean;
  /** Advertise STARTTLS (the double cannot actually upgrade; used to check the client asks). */
  starttls?: boolean;
}

/** An SMTP server double on a random port: records every command and the DATA payload. */
function fakeSmtp(opts: FakeSmtpOptions = {}) {
  const commands: string[] = [];
  let message = '';
  const server = createNetServer((socket: Socket) => {
    let buffer = '';
    let inData = false;
    let loginStep = 0;
    socket.write('220 fake.test ESMTP ready\r\n');
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end === -1) return;
          message = buffer.slice(0, end);
          buffer = buffer.slice(end + 5);
          inData = false;
          socket.write('250 2.0.0 queued as 42\r\n');
          continue;
        }
        const nl = buffer.indexOf('\r\n');
        if (nl === -1) return;
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 2);
        commands.push(line);
        const upper = line.toUpperCase();
        if (loginStep === 1) {
          loginStep = 2;
          socket.write('334 UGFzc3dvcmQ6\r\n');
        } else if (loginStep === 2) {
          loginStep = 0;
          socket.write(Buffer.from(line, 'base64').toString() === 'sekret' ? '235 2.7.0 Authentication successful\r\n' : '535 5.7.8 Authentication credentials invalid\r\n');
        } else if (upper.startsWith('EHLO')) socket.write(`250-fake.test greets you\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n${opts.starttls ? '250-STARTTLS\r\n' : ''}250-AUTH PLAIN LOGIN\r\n250 OK\r\n`);
        else if (upper.startsWith('AUTH PLAIN')) {
          if (opts.rejectPlain) socket.write('535 5.7.8 PLAIN not accepted here\r\n');
          else {
            const [, user, pass] = Buffer.from(line.slice(11), 'base64').toString().split('\0');
            socket.write(user === 'mailer' && pass === 'sekret' ? '235 2.7.0 Authentication successful\r\n' : '535 5.7.8 Authentication credentials invalid\r\n');
          }
        } else if (upper === 'AUTH LOGIN') {
          loginStep = 1;
          socket.write('334 VXNlcm5hbWU6\r\n');
        } else if (upper.startsWith('MAIL FROM:')) socket.write('250 2.1.0 Ok\r\n');
        else if (upper.startsWith('RCPT TO:')) socket.write(line.includes('bounce@') ? '550 5.1.1 No such user\r\n' : '250 2.1.5 Ok\r\n');
        else if (upper === 'DATA') {
          inData = true;
          socket.write('354 End data with <CR><LF>.<CR><LF>\r\n');
        } else if (upper === 'STARTTLS') socket.write('454 4.7.0 TLS not available in this double\r\n');
        else if (upper === 'QUIT') {
          socket.write('221 2.0.0 Bye\r\n');
          socket.end();
        } else socket.write('500 5.5.1 Command unrecognized\r\n');
      }
    });
  });
  return {
    server,
    commands,
    message: () => message,
    listen: () => new Promise<number>((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port))),
  };
}

/** A webhook double: records JSON bodies and answers 200 "ok" (or a failure for /broken). */
function fakeWebhook() {
  const received: { url: string; headers: Record<string, string | string[] | undefined>; body: unknown }[] = [];
  const server = createHttpServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    received.push({ url: req.url ?? '', headers: req.headers, body: JSON.parse(Buffer.concat(chunks).toString() || 'null') });
    if (req.url === '/broken') {
      res.statusCode = 400;
      return res.end('invalid_payload');
    }
    res.end(req.url?.startsWith('/teams') ? '1' : 'ok');
  });
  return { server, received, listen: () => new Promise<number>((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port))) };
}

// ---------------------------------------------------------------------------------------------
// Settings

test('digest settings: merge, validation, secrets stored but never returned', async () => {
  const f = openDb();
  try {
    const settings = settingsFor(f.db);
    assert.deepEqual(getDigestSettings(settings), { channel: null, weekday: 1, hour: 8 });
    const ctx = (user = ADMIN, body: Record<string, unknown> = {}) => makeContext(f.db, { user, body, settings });
    await assert.rejects(dispatch(routes, 'GET', '/api/settings/digest', ctx(ANALYST)), (e: unknown) => e instanceof FeatureError && e.status === 403);
    await assert.rejects(dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { channel: 'pigeon' })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { weekday: 7 })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { hour: 24 })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { channel: 'email' })), (e: unknown) => e instanceof FeatureError && e.status === 400 && /email\.to/.test(e.message), 'channel needs its settings');
    await assert.rejects(dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { channel: 'slack' })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { email: { to: ['not an address'], from: 'nextfix@acme.test', smtpHost: 'smtp.acme.test' } })), (e: unknown) => e instanceof FeatureError && e.status === 400);
    await assert.rejects(dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { slackWebhook: 'http://hooks.slack.com/x' })), (e: unknown) => e instanceof FeatureError && e.status === 400 && /https/.test(e.message));

    // email, with the password nested
    let pub = (await dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { channel: 'email', weekday: 5, hour: 7, email: { to: 'sec@acme.test, ops@acme.test', from: 'nextfix@acme.test', smtpHost: 'smtp.acme.test', smtpPort: 587, smtpUser: 'mailer', smtpPassword: 'sekret', secure: true } }))).body as PublicDigestSettings;
    assert.deepEqual(pub, { channel: 'email', weekday: 5, hour: 7, email: { to: ['sec@acme.test', 'ops@acme.test'], from: 'nextfix@acme.test', smtpHost: 'smtp.acme.test', smtpPort: 587, smtpUser: 'mailer', secure: true, hasPassword: true } });
    assert.equal(JSON.stringify(pub).includes('sekret'), false);
    assert.equal(getDigestSettings(settings).email!.smtpPassword, 'sekret', 'stored');
    // a merge without the password keeps it; the dashboard's top-level secret key also works
    pub = (await dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { email: { to: ['sec@acme.test'], from: 'nextfix@acme.test', smtpHost: 'smtp.acme.test', smtpPort: 25, smtpUser: 'mailer', secure: false, hasPassword: true } }))).body as PublicDigestSettings;
    assert.equal(pub.email!.hasPassword, true);
    assert.equal(pub.email!.smtpPort, 25);
    assert.equal(getDigestSettings(settings).email!.smtpPassword, 'sekret');
    await dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { smtpPassword: 'newer', email: { to: ['sec@acme.test'], from: 'nextfix@acme.test', smtpHost: 'smtp.acme.test' } }));
    assert.equal(getDigestSettings(settings).email!.smtpPassword, 'newer');

    // slack and teams webhooks, both spellings
    pub = (await dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { channel: 'slack', slackWebhook: 'https://hooks.slack.com/services/T0/B0/x' }))).body as PublicDigestSettings;
    assert.deepEqual(pub.slack, { hasWebhook: true });
    assert.equal(pub.email!.hasPassword, true, 'other channels keep their settings');
    pub = (await dispatch(routes, 'PUT', '/api/settings/digest', ctx(ADMIN, { channel: 'teams', teams: { webhook: 'https://acme.webhook.office.com/webhookb2/x' } }))).body as PublicDigestSettings;
    assert.deepEqual(pub.teams, { hasWebhook: true });
    assert.equal(JSON.stringify(pub).includes('hooks.slack.com'), false);
    const stored = settings.get(DIGEST_SETTING_KEY) as DigestSettings;
    assert.equal(stored.slack!.webhook, 'https://hooks.slack.com/services/T0/B0/x');
    assert.deepEqual((await dispatch(routes, 'GET', '/api/settings/digest', ctx(ADMIN))).body, pub, 'GET returns what PUT returned');
    assert.deepEqual(publicDigestSettings(mergeDigestSettings(stored, { channel: null })).channel, null);
  } finally {
    f.close();
  }
});

// ---------------------------------------------------------------------------------------------
// Content

test('buildDigest: subject from the postures, per-application sentences, bridge, SLA, exceptions, links', async () => {
  const f = openDb();
  try {
    const settings = settingsFor(f.db);
    const nowMs = Date.now();
    // shop: previous scan 8 days ago with one Act; latest has two Act (one new) and one Track; one Act finding is 12 days old (past SLA)
    const shop = f.store.upsertTarget('C:/x/shop', 'shop');
    f.store.addScan(shop.id, reportWith([LODASH, Z], ago(12, nowMs), (x, i) => { if (i === 1) x.decision = 'Track*'; }, 'shop'));
    f.store.addScan(shop.id, reportWith([LODASH, Y], ago(1, nowMs), () => {}, 'shop'));
    // api: single scan, one Attend behind auth, exception pending; a second finding with an approved exception expiring in 10 days
    const api = f.store.upsertTarget('C:/x/api', 'api');
    f.store.addScan(api.id, reportWith([Y, Z], ago(3, nowMs), (x) => { x.decision = 'Attend'; x.reach.paths[0]!.entry = { ...x.reach.paths[0]!.entry, authenticated: true, guards: ['requireLogin'] }; }, 'api'));
    proposeException(f.db, { targetId: api.id, findingId: Y, kind: 'accepted-risk', reason: 'Accepted until the Q4 upgrade window', user: ANALYST });
    proposeException(f.db, { targetId: api.id, findingId: Z, kind: 'mitigated', reason: 'Gateway strips the template parameter', user: ADMIN, expiresAt: ago(-10, nowMs).slice(0, 10) });
    // docs: never scanned
    f.store.upsertTarget('C:/x/docs', 'docs');
    // a promotion recorded by the nightly pass two days ago
    recordRedecideEvents(f.db, shop.id, 2, [{ finding: { id: Y } as never, from: 'Attend', to: 'Act', reasons: ['entered KEV'] }], ago(2, nowMs));
    settings.set('publicUrl', 'https://nextfix.acme.test/');

    const d = buildDigest(f.db, settings, nowMs);
    assert.equal(d.subject, 'NextFix · 3 applications · 1 Exposed, 1 Attention, 1 Never scanned');
    assert.deepEqual(d.apps.map((a) => [a.name, a.posture]), [['api', 'Attention'], ['docs', 'Never scanned'], ['shop', 'Exposed']]);

    const shopApp = d.apps.find((a) => a.name === 'shop')!;
    assert.equal(shopApp.url, `https://nextfix.acme.test/#/overview?target=${shop.id}`);
    assert.equal(shopApp.verdict, '2 vulnerabilities are reachable without a login, carry request data, and the worst has a 42% chance of exploitation within 30 days.');
    assert.match(shopApp.lines[0]!, /^Since the previous scan on \d{1,2} \w{3}: 1 new, 1 resolved, 1 promoted \(1 by new exploit data\)\.$/);
    assert.equal(shopApp.lines[1], '1 package upgrade clears everything that needs action.');
    assert.equal(shopApp.lines[2], '1 finding is past the SLA; the oldest is 5 days overdue (Act, first seen 12 days ago).');
    assert.equal(shopApp.lines.length, 3, 'no exception sentence without exceptions');

    const apiApp = d.apps.find((a) => a.name === 'api')!;
    assert.equal(apiApp.verdict, '1 finding needs fixing in the next release cycle; nothing is both reachable without a login and known to be exploited.');
    assert.equal(apiApp.detail, 'None is reachable without a login.');
    assert.equal(apiApp.lines[0], 'First scan; nothing to compare with yet.');
    assert.equal(apiApp.lines[1], '1 package upgrade clears everything that needs action.');
    assert.match(apiApp.lines[2]!, /^1 exception is waiting for approval; 1 exception expires within 30 days \(lodash@4\.17\.15 GHSA-z on \d{4}-\d{2}-\d{2}\)\.$/);

    const docsApp = d.apps.find((a) => a.name === 'docs')!;
    assert.equal(docsApp.verdict, 'Not scanned yet; add a schedule or run a scan.');

    // renderings
    assert.ok(d.text.startsWith(`${d.subject}\nWeekly digest, `));
    assert.ok(d.text.includes('shop — Exposed\n2 vulnerabilities are reachable'));
    assert.ok(d.text.includes(`Dashboard: https://nextfix.acme.test/#/overview?target=${api.id}`));
    assert.ok(d.markdown.includes('## shop — Exposed'));
    assert.ok(d.markdown.includes('- 1 package upgrade clears everything that needs action.'));
    assert.ok(d.markdown.includes(`[Open the dashboard](https://nextfix.acme.test/#/overview?target=${shop.id})`));
    const blocks = d.blocks as { type: string; text?: { type: string; text: string } }[];
    assert.equal(blocks[0]!.type, 'header');
    assert.equal(blocks[0]!.text!.text, d.subject);
    assert.deepEqual(blocks.slice(1).map((b) => b.type), ['divider', 'section', 'divider', 'section', 'divider', 'section', 'context']);
    assert.ok(blocks[2]!.text!.text.startsWith('*api — Attention*\n'));
    assert.ok(blocks[6]!.text!.text.includes(`<https://nextfix.acme.test/#/overview?target=${shop.id}|Open the dashboard>`));
    const card = teamsCard(d, 'https://nextfix.acme.test');
    assert.equal(card.version, '1.4');
    assert.equal(card.type, 'AdaptiveCard');
    const body = card.body as { type: string; text?: string; items?: { text: string }[] }[];
    assert.equal(body[0]!.text, d.subject);
    assert.equal(body.filter((b) => b.type === 'Container').length, 3);
    assert.equal(body[3]!.items![0]!.text, 'shop — Exposed');

    // one application: the subject is its verdict sentence
    f.db.prepare('DELETE FROM targets WHERE id != ?').run(shop.id);
    assert.equal(buildDigest(f.db, settings, nowMs).subject, `NextFix · shop: ${shopApp.verdict}`);
    f.db.prepare('DELETE FROM targets').run();
    assert.equal(buildDigest(f.db, settings, nowMs).subject, 'NextFix · no applications yet');
    assert.equal(digestSubject([]), 'NextFix · no applications yet');

    // the preview route is the same content
    const preview = (await dispatch(routes, 'POST', '/api/digest/preview', makeContext(f.db, { user: ADMIN, settings }))).body as Digest;
    assert.equal(preview.subject, 'NextFix · no applications yet');
    await assert.rejects(dispatch(routes, 'POST', '/api/digest/preview', makeContext(f.db, { user: VIEWER, settings })), (e: unknown) => e instanceof FeatureError && e.status === 403);
  } finally {
    f.close();
  }
});

test('leverageSentence: the dashboard rules', () => {
  const r = reportWith([LODASH, Y, Z], ago(1), (x, i) => {
    if (i === 1) { x.decision = 'Attend'; x.advisory = { ...x.advisory, fixedVersion: undefined }; }
    if (i === 2) { x.decision = 'Track'; }
  });
  assert.equal(leverageSentence(r), '1 package upgrade clears all but 1 of the findings that need action. 1 actionable finding has no fix published yet; mitigate at the entry point.');
  const clean = reportWith([LODASH], ago(1), (x) => { x.decision = 'Track'; });
  assert.equal(leverageSentence(clean), 'Nothing needs action; upgrades would close watched or set-aside findings only.');
  const image = reportWith([LODASH, Y], ago(1), (x, i) => { if (i === 1) { x.component = { ...x.component, purl: 'pkg:deb/debian/openssl@3.0.1', name: 'openssl', origin: 'image' }; } });
  assert.equal(leverageSentence(image), '1 package upgrade and one base-image refresh clear everything that needs action.');
});

// ---------------------------------------------------------------------------------------------
// Email

test('SMTP: EHLO, AUTH PLAIN, MAIL/RCPT/DATA with 8-bit headers and dot-stuffing, QUIT', async () => {
  const smtp = fakeSmtp();
  const port = await smtp.listen();
  try {
    const { transcript } = await sendMail({ host: '127.0.0.1', port, user: 'mailer', password: 'sekret', secure: false, ehloName: 'nextfix.test' }, { from: 'nextfix@acme.test', to: ['sec@acme.test', 'ops@acme.test'], subject: 'NextFix · 2 applications · 1 Exposed, 1 Clean', text: 'Line one\n.starts with a dot\nnon-ascii → ok\n' });
    assert.deepEqual(smtp.commands.filter((c) => !c.startsWith('AUTH')), ['EHLO nextfix.test', 'MAIL FROM:<nextfix@acme.test> BODY=8BITMIME', 'RCPT TO:<sec@acme.test>', 'RCPT TO:<ops@acme.test>', 'DATA', 'QUIT']);
    const auth = smtp.commands.find((c) => c.startsWith('AUTH'))!;
    assert.equal(auth, `AUTH PLAIN ${Buffer.from('\0mailer\0sekret').toString('base64')}`);
    assert.ok(transcript.includes('C: [credentials]'), 'the transcript redacts the credentials');
    assert.equal(transcript.some((l) => l.includes('sekret')), false);
    assert.equal(transcript[0], 'S: 220 fake.test ESMTP ready');
    assert.ok(transcript.includes('S: 250 2.0.0 queued as 42'));

    const msg = smtp.message();
    const [head, body] = msg.split('\r\n\r\n');
    const headers = Object.fromEntries(head!.split('\r\n').map((l) => [l.slice(0, l.indexOf(':')).toLowerCase(), l.slice(l.indexOf(':') + 2)]));
    assert.equal(headers.from, 'nextfix@acme.test');
    assert.equal(headers.to, 'sec@acme.test, ops@acme.test');
    assert.equal(headers.subject, `=?UTF-8?B?${Buffer.from('NextFix · 2 applications · 1 Exposed, 1 Clean').toString('base64')}?=`);
    assert.match(headers.date!, /^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}$/);
    assert.match(headers['message-id']!, /^<[0-9a-f]{24}@acme\.test>$/);
    assert.equal(headers['mime-version'], '1.0');
    assert.equal(headers['content-type'], 'text/plain; charset=utf-8');
    assert.equal(headers['content-transfer-encoding'], '8bit');
    assert.match(headers['x-mailer']!, /^NextFix\//);
    assert.equal(body, 'Line one\r\n..starts with a dot\r\nnon-ascii → ok\r\n', 'CRLF line ends, a leading dot doubled, UTF-8 kept as is');
  } finally {
    smtp.server.close();
  }
});

test('SMTP: AUTH LOGIN fallback, rejected recipient, bad password, STARTTLS refused when not offered', async () => {
  const plainRefused = fakeSmtp({ rejectPlain: true });
  const port = await plainRefused.listen();
  try {
    await sendMail({ host: '127.0.0.1', port, user: 'mailer', password: 'sekret', secure: false, ehloName: 'nextfix.test' }, { from: 'a@acme.test', to: ['b@acme.test'], subject: 'x', text: 'y' });
    const idx = plainRefused.commands.findIndex((c) => c === 'AUTH LOGIN');
    assert.ok(idx > 0, 'falls back to AUTH LOGIN after PLAIN is refused');
    assert.equal(plainRefused.commands[idx + 1], Buffer.from('mailer').toString('base64'));
    assert.equal(plainRefused.commands[idx + 2], Buffer.from('sekret').toString('base64'));
    await assert.rejects(sendMail({ host: '127.0.0.1', port, user: 'mailer', password: 'wrong', secure: false }, { from: 'a@acme.test', to: ['b@acme.test'], subject: 'x', text: 'y' }), /Authentication failed|535/);
    await assert.rejects(sendMail({ host: '127.0.0.1', port, user: 'mailer', password: 'sekret', secure: false }, { from: 'a@acme.test', to: ['bounce@acme.test'], subject: 'x', text: 'y' }), /RCPT failed: 550/);
    await assert.rejects(sendMail({ host: '127.0.0.1', port, secure: true }, { from: 'a@acme.test', to: ['b@acme.test'], subject: 'x', text: 'y' }), /does not offer STARTTLS/);
    assert.equal(plainRefused.commands.includes('STARTTLS'), false, 'never sends STARTTLS to a server that did not advertise it');
    // no credentials: no AUTH at all
    const before = plainRefused.commands.length;
    await sendMail({ host: '127.0.0.1', port, secure: false }, { from: 'a@acme.test', to: ['b@acme.test'], subject: 'x', text: 'y' });
    assert.equal(plainRefused.commands.slice(before).some((c) => c.startsWith('AUTH')), false);
  } finally {
    plainRefused.server.close();
  }
  // a server that offers STARTTLS gets the command when secure is on
  const offers = fakeSmtp({ starttls: true });
  const port2 = await offers.listen();
  try {
    await assert.rejects(sendMail({ host: '127.0.0.1', port: port2, secure: true }, { from: 'a@acme.test', to: ['b@acme.test'], subject: 'x', text: 'y' }), /STARTTLS failed: 454/);
    assert.deepEqual(offers.commands, ['EHLO ' + offers.commands[0]!.slice(5), 'STARTTLS']);
  } finally {
    offers.server.close();
  }
  await assert.rejects(sendMail({ host: '127.0.0.1', port: 1, secure: false }, { from: 'a@acme.test', to: ['b@acme.test'], subject: 'x', text: 'y' }), /ECONNREFUSED/);
});

test('message helpers', () => {
  assert.equal(encodeHeader('plain ascii'), 'plain ascii');
  assert.equal(encodeHeader('é'), '=?UTF-8?B?w6k=?=');
  assert.match(rfc5322Date(new Date('2026-10-10T12:34:56Z')), /^Sat, 10 Oct 2026 \d{2}:\d{2}:56 [+-]\d{4}$/);
  const m = buildMessage({ from: 'a@x.test', to: ['b@x.test'], subject: 'Hi', text: '.\n..\nend' });
  assert.ok(m.endsWith('\r\n\r\n..\r\n...\r\nend'));
});

// ---------------------------------------------------------------------------------------------
// Webhooks, the weekly job and the test route

test('Slack and Teams: payload shapes against a local webhook, logged in digest_log; weekly due-logic', async () => {
  const hook = fakeWebhook();
  const port = await hook.listen();
  const f = openDb();
  try {
    const settings = settingsFor(f.db);
    const shop = f.store.upsertTarget('C:/x/shop', 'shop');
    f.store.addScan(shop.id, reportWith([LODASH], ago(1), () => {}, 'shop'));
    const ctx = (body: Record<string, unknown> = {}) => makeContext(f.db, { user: ADMIN, body, settings });

    await assert.rejects(dispatch(routes, 'POST', '/api/digest/test', ctx()), (e: unknown) => e instanceof FeatureError && e.status === 400, 'no channel yet');

    // Slack: a test message, then the weekly digest
    await dispatch(routes, 'PUT', '/api/settings/digest', ctx({ channel: 'slack', slackWebhook: `http://127.0.0.1:${port}/slack` }));
    const t = (await dispatch(routes, 'POST', '/api/digest/test', ctx())).body as { ok: boolean; message: string };
    assert.deepEqual(t, { ok: true, message: 'Test message sent over slack' });
    assert.equal(hook.received.length, 1);
    assert.equal(hook.received[0]!.url, '/slack');
    assert.equal(hook.received[0]!.headers['content-type'], 'application/json');
    const slackTest = hook.received[0]!.body as { text: string; blocks: { type: string }[] };
    assert.equal(slackTest.text, 'NextFix · test message');
    assert.deepEqual(slackTest.blocks.map((b) => b.type), ['header', 'section']);

    const s = getDigestSettings(settings);
    const nowMs = lastScheduledInstant(s, Date.now()) + 60_000; // one minute after this week's slot
    assert.equal(isDigestDue(s, undefined, nowMs), true);
    assert.equal(isDigestDue(s, new Date(nowMs - 30_000).toISOString(), nowMs), false, 'sent after the slot: not due');
    assert.equal(isDigestDue(s, new Date(nowMs - 3 * DAY_MS).toISOString(), nowMs), true, 'last send before the slot: due');
    assert.equal(isDigestDue({ ...s, channel: null }, undefined, nowMs), false, 'no channel: never due');
    assert.equal(isDigestDue(s, undefined, lastScheduledInstant(s, Date.now()) - 60_000), true, 'a minute before the slot the previous week\'s slot counts');
    assert.equal(lastScheduledInstant(s, nowMs) % 60_000, 0);
    assert.equal(new Date(lastScheduledInstant(s, nowMs)).getDay(), s.weekday);
    assert.equal(new Date(lastScheduledInstant(s, nowMs)).getHours(), s.hour);

    assert.equal(await sendDigestIfDue(f.db, nowMs), true);
    assert.equal(await sendDigestIfDue(f.db, nowMs + 60_000), false, 'not twice in the same week');
    assert.equal(hook.received.length, 2);
    const weekly = hook.received[1]!.body as { text: string; blocks: { type: string; text?: { text: string } }[] };
    assert.ok(weekly.text.startsWith('NextFix · shop: One vulnerability is reachable'));
    assert.equal(weekly.blocks[0]!.type, 'header');
    const log = f.db.prepare('SELECT kind, channel, subject, recipients, ok, error FROM digest_log ORDER BY id').all() as { kind: string; channel: string; subject: string; recipients: string; ok: number; error: string | null }[];
    assert.deepEqual(log.map((r) => [r.kind, r.channel, r.ok, r.error]), [['test', 'slack', 1, null], ['weekly', 'slack', 1, null]]);
    assert.equal(log[1]!.subject, weekly.text);

    // Teams: the Adaptive Card inside a message attachment
    await dispatch(routes, 'PUT', '/api/settings/digest', ctx({ channel: 'teams', teamsWebhook: `http://127.0.0.1:${port}/teams/x` }));
    await dispatch(routes, 'POST', '/api/digest/test', ctx());
    const teams = hook.received[2]!.body as { type: string; attachments: { contentType: string; contentUrl: null; content: { type: string; version: string; body: { text?: string }[] } }[] };
    assert.equal(teams.type, 'message');
    assert.equal(teams.attachments[0]!.contentType, 'application/vnd.microsoft.card.adaptive');
    assert.equal(teams.attachments[0]!.contentUrl, null);
    assert.equal(teams.attachments[0]!.content.version, '1.4');
    assert.equal(teams.attachments[0]!.content.body[0]!.text, 'NextFix · test message');

    // a failing webhook is a 502 and a logged failure; the weekly job does not retry until the next slot
    await dispatch(routes, 'PUT', '/api/settings/digest', ctx({ channel: 'slack', slackWebhook: `http://127.0.0.1:${port}/broken` }));
    await assert.rejects(dispatch(routes, 'POST', '/api/digest/test', ctx()), (e: unknown) => e instanceof FeatureError && e.status === 502 && /400: invalid_payload/.test(e.message));
    const later = nowMs + 7 * DAY_MS;
    assert.equal(await sendDigestIfDue(f.db, later), false, 'the send failed');
    assert.equal(await sendDigestIfDue(f.db, later + 60_000), false, 'and is not retried this week');
    const failures = f.db.prepare("SELECT kind, ok, error FROM digest_log WHERE ok = 0 ORDER BY id").all() as { kind: string; ok: number; error: string }[];
    assert.deepEqual(failures.map((r) => r.kind), ['test', 'weekly']);
    assert.match(failures[1]!.error, /Slack webhook answered 400/);

    // email through the SMTP double, driven by the weekly job
    const smtp = fakeSmtp();
    const smtpPort = await smtp.listen();
    try {
      await dispatch(routes, 'PUT', '/api/settings/digest', ctx({ channel: 'email', email: { to: ['sec@acme.test'], from: 'nextfix@acme.test', smtpHost: '127.0.0.1', smtpPort, smtpUser: 'mailer', smtpPassword: 'sekret', secure: false } }));
      assert.equal(await sendDigestIfDue(f.db, later + 14 * DAY_MS), true);
      assert.ok(smtp.message().includes('Content-Transfer-Encoding: 8bit'));
      assert.ok(smtp.message().includes('shop — Exposed'));
      const last = f.db.prepare('SELECT channel, recipients, ok FROM digest_log ORDER BY id DESC LIMIT 1').get() as { channel: string; recipients: string; ok: number };
      assert.deepEqual({ ...last }, { channel: 'email', recipients: 'sec@acme.test', ok: 1 });
    } finally {
      smtp.server.close();
    }
  } finally {
    f.close();
    hook.server.close();
  }
});
