import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildMatchers, cleanPath, expandSources, isPublicAddress, matchRoute, observeTraffic, parseClfTime, parseLine, routeRegex } from './traffic.ts';
import { decide } from '../decide/ssvc.ts';
import type { Advisory, Component, EntryPoint, Exposure, ReachPath } from '../types.ts';

const entry = (method: string, path: string, authenticated = false, traffic?: EntryPoint['traffic']): EntryPoint => ({ method, path, file: 'src/app.js', line: 1, authenticated, guards: authenticated ? ['requireAuth'] : [], mounted: true, handlerIds: ['src/app.js#h@1:1'], traffic });

test('addresses: private, loopback, link-local, CGNAT and ULA are internal, the rest public', () => {
  for (const ip of ['10.0.0.1', '172.16.5.5', '172.31.255.1', '192.168.1.9', '127.0.0.1', '169.254.1.1', '100.64.0.1', '::1', 'fd12::1', 'fe80::1', '::ffff:10.1.1.1', '[::1]']) assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '203.0.113.9', '2606:4700::1111', '::ffff:93.184.216.34', '[2001:db8::1]']) assert.equal(isPublicAddress(ip), true, ip);
  assert.equal(isPublicAddress('not-an-ip'), false);
});

test('line formats: combined, ALB and JSON lines are read; junk is skipped', () => {
  const c = parseLine('93.184.216.34 - - [10/Oct/2026:14:22:01 +0000] "POST /preview?x=1 HTTP/1.1" 200 512 "-" "curl/8"');
  assert.equal(c?.format, 'combined');
  assert.deepEqual([c?.req.method, c?.req.path, c?.req.ip, c?.req.public], ['POST', '/preview', '93.184.216.34', true]);
  assert.equal(c?.req.at, Date.UTC(2026, 9, 10, 14, 22, 1));
  assert.equal(parseClfTime('10/Oct/2026:16:22:01 +0200'), Date.UTC(2026, 9, 10, 14, 22, 1));

  const alb = parseLine('https 2026-10-10T14:22:01.123456Z app/my-alb/50dc6c495c0c9188 203.0.113.9:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET https://shop.example.com:443/go?to=x HTTP/1.1" "curl/7.46.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337281-1d84f3d73c47ec4e58577259" "-" "-" 0 2026-10-10T14:22:01.000000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-"');
  assert.equal(alb?.format, 'alb');
  assert.deepEqual([alb?.req.method, alb?.req.path, alb?.req.ip, alb?.req.public], ['GET', '/go', '203.0.113.9', true]);

  const caddy = parseLine('{"level":"info","ts":1791642121.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.1.2.3","remote_port":"51234","proto":"HTTP/2.0","method":"GET","host":"shop.internal","uri":"/orders/42?full=1","headers":{"X-Forwarded-For":["198.51.100.7, 10.1.2.3"]}},"status":200}');
  assert.equal(caddy?.format, 'json');
  assert.deepEqual([caddy?.req.method, caddy?.req.path, caddy?.req.ip, caddy?.req.public], ['GET', '/orders/42', '198.51.100.7', true]);
  assert.equal(caddy?.req.at, 1791642121500);

  const cf = parseLine('{"ClientIP":"198.51.100.20","ClientRequestMethod":"POST","ClientRequestPath":"/login","ClientRequestURI":"/login?next=%2Fhome","EdgeStartTimestamp":"2026-10-10T14:22:01Z","EdgeResponseStatus":302}');
  assert.deepEqual([cf?.req.method, cf?.req.path, cf?.req.public], ['POST', '/login', true]);

  const pino = parseLine('{"level":30,"time":1791642121500,"req":{"method":"GET","url":"/healthz","remoteAddress":"::ffff:127.0.0.1"},"res":{"statusCode":200}}');
  assert.deepEqual([pino?.req.method, pino?.req.path, pino?.req.public], ['GET', '/healthz', false]);

  assert.equal(parseLine('{"msg":"started server"}'), undefined);
  assert.equal(parseLine('not a log line at all'), undefined);
  assert.equal(parseLine(''), undefined);
});

test('paths are cleaned: host, query, encoding, duplicate and trailing slashes', () => {
  assert.equal(cleanPath('https://shop.example.com:443/go?to=x#frag'), '/go');
  assert.equal(cleanPath('/a//b/'), '/a/b');
  assert.equal(cleanPath('/users/%7Bid%7D'), '/users/{id}');
  assert.equal(cleanPath('preview'), '/preview');
  assert.equal(cleanPath('/'), '/');
});

test('route patterns from Express, Flask, FastAPI, Django and Go match cleaned paths', () => {
  const ok = (pattern: string, path: string) => assert.equal(routeRegex(pattern).test(path), true, `${pattern} should match ${path}`);
  const no = (pattern: string, path: string) => assert.equal(routeRegex(pattern).test(path), false, `${pattern} should not match ${path}`);
  ok('/users/:id', '/users/42');
  no('/users/:id', '/users/42/orders');
  ok('/users/:id?', '/users');
  ok('/users/:id?', '/users/7');
  ok('/files/*', '/files/a/b/c.txt');
  ok('/user/<int:id>', '/user/9');
  ok('/items/{item_id}', '/items/abc');
  ok('/static/{path:path}', '/static/css/app.css');
  ok('^users/(?P<id>\\d+)/$', '/users/12');
  no('^users/(?P<id>\\d+)/$', '/users/abc');
  ok('/api/v1/orders/{id}', '/api/v1/orders/x-1');
  ok('/preview', '/PREVIEW');
  no('/preview', '/preview/extra');
  ok('/', '/');
});

test('the most specific route wins and ALL/USE routes match any method', () => {
  const entries = [entry('GET', '/users/:id'), entry('GET', '/users/me'), entry('ALL', '/admin/*'), entry('POST', '/preview')];
  const m = buildMatchers(entries);
  assert.equal(matchRoute(m, 'GET', '/users/me'), 1);
  assert.equal(matchRoute(m, 'GET', '/users/42'), 0);
  assert.equal(matchRoute(m, 'HEAD', '/users/42'), 0, 'HEAD is answered by GET routes');
  assert.equal(matchRoute(m, 'DELETE', '/admin/users/1'), 2);
  assert.equal(matchRoute(m, 'GET', '/preview'), undefined, 'method must match');
  assert.equal(matchRoute(m, 'POST', '/preview'), 3);
  assert.equal(matchRoute(m, 'GET', '/nothing'), undefined);
});

function clf(ip: string, method: string, path: string, when: Date): string {
  const d = String(when.getUTCDate()).padStart(2, '0');
  const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][when.getUTCMonth()];
  const t = when.toISOString().slice(11, 19);
  return `${ip} - - [${d}/${mon}/${when.getUTCFullYear()}:${t} +0000] "${method} ${path} HTTP/1.1" 200 12 "-" "ua"`;
}

test('observeTraffic counts per route inside the window, separates public from internal, and flags cold and stale', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-traffic-'));
  const now = Date.UTC(2026, 9, 12, 12, 0, 0);
  const day = (n: number) => new Date(now - n * 86_400_000);
  const lines = [
    clf('93.184.216.34', 'POST', '/preview', day(1)),
    clf('93.184.216.35', 'POST', '/preview?x=1', day(2)),
    clf('10.0.0.5', 'POST', '/preview', day(3)),
    clf('10.0.0.5', 'GET', '/healthz', day(1)),
    clf('93.184.216.34', 'GET', '/static/app.css', day(1)),
    clf('93.184.216.34', 'POST', '/preview', day(45)), // outside the 30-day window
    'garbage line',
  ];
  writeFileSync(join(dir, 'access.log'), lines.join('\n') + '\n');
  writeFileSync(join(dir, 'access.log.1'), clf('198.51.100.1', 'GET', '/go', day(5)) + '\n');
  writeFileSync(join(dir, 'notes.md'), 'not a log');
  const entries = [entry('POST', '/preview'), entry('GET', '/go'), entry('GET', '/healthz', true), entry('POST', '/admin/users/normalize', true)];
  const logs: string[] = [];
  const r = await observeTraffic(dir, ['.'], entries, { now, log: (m) => logs.push(m) });
  assert.equal(r.summary.files.length, 2, 'the folder expands to its log files');
  assert.equal(r.summary.files[0]!.format, 'combined');
  assert.equal(r.summary.requests, 6, 'one line is outside the window, one is junk');
  assert.equal(r.summary.public, 4);
  assert.equal(r.summary.internal, 2);
  assert.equal(r.summary.unmatched, 1, 'the static file matched no route');
  assert.deepEqual(r.perEntry.map((t) => [t.requests, t.public, t.internal]), [[3, 2, 1], [1, 1, 0], [1, 0, 1], [0, 0, 0]]);
  assert.equal(r.perEntry[0]!.lastSeenAt, day(1).toISOString());
  assert.equal(r.summary.routesSeen, 3);
  assert.equal(r.summary.routesCold, 1);
  assert.equal(r.summary.stale, false);
  assert.equal(r.observed.routesSeen, 3);
  assert.equal(r.summary.to, day(1).toISOString());
  assert.ok(logs.some((l) => l.includes('6 requests in the 30 days')), logs.join('\n'));

  // Logs that end long ago are read but marked stale.
  const old = await observeTraffic(dir, ['access.log'], entries, { now: now + 90 * 86_400_000 });
  assert.equal(old.summary.stale, true);

  // Problems are reported per source, never thrown.
  const bad = await observeTraffic(dir, ['missing.log', 'access.log.gz'], entries, { now });
  assert.deepEqual(bad.summary.files.map((f) => f.format), ['unreadable', 'unreadable']);
  assert.equal(bad.summary.requests, 0);
  assert.equal(expandSources(dir, ['nope'])[0]!.problem, 'not found');
});

// ---------------------------------------------------------------------------------------------
// Decisions with observed traffic

const lodash: Component = { ecosystem: 'npm', name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', dev: false, optional: false, direct: true, path: 'node_modules/lodash' };
const advisory = (cvss: number): Advisory => ({ id: 'GHSA-x', aliases: ['CVE-2021-0001'], cve: 'CVE-2021-0001', summary: 'Command injection', details: '', cvssScore: cvss, fixedVersion: '4.17.21', references: [] });
const path = (e: EntryPoint, userInput: boolean): ReachPath => ({ entry: e, hops: [], callSite: { file: 'src/app.js', line: 5, col: 1, text: 'lodash.template', symbol: 'template', userInput }, userInput });
const observed = (over: Partial<NonNullable<Exposure['observed']>> = {}): Exposure => ({ network: 'published', ports: [3000], evidence: ['Dockerfile: EXPOSE 3000'], observed: { public: 100, internal: 20, days: 30, to: '2026-10-11T00:00:00.000Z', stale: false, routesSeen: 3, ...over } });

function run(e: EntryPoint, cvss: number, userInput: boolean, exposure: Exposure) {
  return decide({ id: 'x', component: lodash, advisory: advisory(cvss), reach: { tier: 'reachable', confidence: 'confirmed', importedIn: ['src/app.js'], callSites: [], paths: [path(e, userInput)] }, exposure });
}

test('public traffic on an open route lifts a moderate finding to Act, and says so', () => {
  const quiet = run(entry('POST', '/preview', false, { requests: 0, public: 0, internal: 0 }), 6.1, true, observed());
  assert.equal(quiet.decision, 'Attend', 'CVSS 6.1 with request data, no exploitation, is Attend by the code alone');
  const hot = run(entry('POST', '/preview', false, { requests: 1200, public: 900, internal: 300, lastSeenAt: '2026-10-11T08:00:00.000Z' }), 6.1, true, observed());
  assert.equal(hot.decision, 'Act');
  assert.ok(hot.why.some((w) => w.startsWith('Observed: POST /preview received 1,200 requests in the 30 days to 2026-10-11, 900 from public addresses, the last on 2026-10-11. The internet is already calling this route')), hot.why.join('\n'));
  assert.ok(hot.score > quiet.score);
  // Without request data the bar is CVSS 7.
  assert.equal(run(entry('GET', '/go', false, { requests: 50, public: 50, internal: 0 }), 6.1, false, observed()).decision, 'Attend');
  assert.equal(run(entry('GET', '/go', false, { requests: 50, public: 50, internal: 0 }), 7.5, false, observed()).decision, 'Act');
});

test('a cold route demotes an Act that rests on severity alone, but not with exploitation evidence, a short window or stale logs', () => {
  const cold = entry('POST', '/preview', false, { requests: 0, public: 0, internal: 0 });
  const byCode = run(cold, 9.8, true, { network: 'published', ports: [3000], evidence: [] });
  assert.equal(byCode.decision, 'Act');
  const demoted = run(cold, 9.8, true, observed());
  assert.equal(demoted.decision, 'Attend');
  assert.ok(demoted.why.some((w) => w === 'Observed: no request reached POST /preview in the 30 days of logs to 2026-10-11.'), demoted.why.join('\n'));
  assert.ok(demoted.why.some((w) => w.startsWith('Demoted from Act to Attend: the route is reachable in the code but nobody has called it')));
  assert.ok(demoted.score < byCode.score);

  const kev = decide({ id: 'x', component: lodash, advisory: advisory(9.8), reach: { tier: 'reachable', confidence: 'confirmed', importedIn: [], callSites: [], paths: [path(cold, true)] }, exposure: observed(), kev: { dateAdded: '2026-01-01', ransomware: false } });
  assert.equal(kev.decision, 'Act', 'known exploitation keeps Act on a cold route');

  const short = run(cold, 9.8, true, observed({ days: 7 }));
  assert.equal(short.decision, 'Act');
  assert.ok(short.why.some((w) => w.includes('shorter than two weeks')));
  const stale = run(cold, 9.8, true, observed({ stale: true }));
  assert.equal(stale.decision, 'Act');
  assert.ok(stale.why.some((w) => w.includes('end more than a month before this scan')));
  const otherService = run(cold, 9.8, true, observed({ routesSeen: 0 }));
  assert.equal(otherService.decision, 'Act', 'logs that match none of the routes say nothing');
});

test('internet reach: internal-only services demote severity-only Acts; internet-facing ones are quoted', () => {
  const open = entry('POST', '/preview');
  const internal = run(open, 9.8, true, { network: 'published', ports: [3000], evidence: [], reach: 'internal', reachEvidence: ['infra/alb.tf: aws_lb "app" is internal'] });
  assert.equal(internal.decision, 'Attend');
  assert.ok(internal.why.some((w) => w.startsWith('Demoted from Act to Attend: the service is not reachable from the internet (infra/alb.tf')), internal.why.join('\n'));
  assert.ok(internal.why.some((w) => w.startsWith('Not reachable from the internet: infra/alb.tf')));
  const inet = run(open, 9.8, true, { network: 'published', ports: [3000], evidence: [], reach: 'internet', reachEvidence: ['infra/alb.tf: aws_lb "app" is internet-facing'] });
  assert.equal(inet.decision, 'Act');
  assert.ok(inet.why.some((w) => w === 'Internet-facing: infra/alb.tf: aws_lb "app" is internet-facing.'));
  // Behind a login, reach does not change the decision.
  const auth = run(entry('POST', '/admin', true), 9.8, true, { network: 'published', ports: [], evidence: [], reach: 'internal', reachEvidence: ['x'] });
  assert.equal(auth.decision, 'Attend');
});
