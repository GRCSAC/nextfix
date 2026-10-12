/**
 * In-browser stand-in for the server, active when `localStorage['nextfix.mock'] === '1'`.
 * It intercepts `fetch` for `/api/*` and answers from in-memory sample data that follows the
 * 0.10 contract (session, users, tokens, SSO, audit, exceptions, portfolio, digest) as well as
 * the routes the dashboard already used. State lives for the page session; a reload resets it,
 * except the signed-in user, which is kept in sessionStorage so hash navigation keeps working.
 *
 * Knobs (localStorage): `nextfix.mock.setup = '1'` starts on the Setup page;
 * `nextfix.mock.authMode = 'none' | 'local' | 'oidc'` (default `oidc`).
 * Sign in as `admin`, `analyst` or `viewer` with any password; the password `wrong` answers 401
 * and the username `locked` answers 429 with Retry-After.
 */
import type {
  ApiToken, AuditRow, Component, Decision, DigestSettings, EntryPoint, Exception, ExceptionKind, Finding, History, Integrations, ListReport,
  ExternalNode, InternetReach, MapEdge, MapNode, OidcProvider, Portfolio, PortfolioMap, PortfolioTarget, ReachTier, Role, ScanDiff, ScanMeta, ScanReport, ScanSummary, Session, Settings, Target, TicketMap, User,
} from './api.ts';

const VERSION = '0.10.0-mock';
const DAY = 86_400_000;
const now = () => Date.now();
const iso = (msAgo: number) => new Date(now() - msAgo).toISOString();
const daysAgo = (d: number) => iso(d * DAY);
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------
// Users, tokens, SSO, audit, digest

const users: User[] = [
  { id: 'u1', username: 'admin', displayName: 'Dana Whitfield', role: 'admin', createdAt: daysAgo(120), lastLoginAt: daysAgo(0.1) },
  { id: 'u2', username: 'analyst', displayName: 'Priya Raman', role: 'analyst', createdAt: daysAgo(90), lastLoginAt: daysAgo(1.2) },
  { id: 'u3', username: 'viewer', displayName: 'Tom Okafor', role: 'viewer', createdAt: daysAgo(40), lastLoginAt: daysAgo(6) },
  { id: 'u4', username: 'jlee', displayName: 'Jordan Lee', role: 'analyst', disabled: true, createdAt: daysAgo(200), lastLoginAt: daysAgo(70) },
];

const tokens: ApiToken[] = [
  { id: 't1', name: 'CI pipeline', scopes: ['read', 'scan'], createdAt: daysAgo(60), lastUsedAt: daysAgo(0.3), createdBy: 'admin' },
  { id: 't2', name: 'Grafana read-only', scopes: ['read'], createdAt: daysAgo(14), lastUsedAt: null, createdBy: 'admin' },
];

const origin = () => location.origin;
const oidc: { providers: OidcProvider[] } = {
  providers: [
    { id: 'entra', name: 'Microsoft Entra ID', preset: 'entra', issuer: 'https://login.microsoftonline.com/9a1f2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d/v2.0', clientId: '7b2e4c1a-0d9f-4a6b-9c3e-1f2a3b4c5d6e', hasSecret: true, scopes: 'openid profile email', roleClaim: 'groups', roleMap: { 'sec-admins': 'admin', 'sec-analysts': 'analyst' }, defaultRole: 'viewer', allowedDomains: ['acme.com'], redirectUri: `${origin()}/api/auth/oidc/entra/callback` },
  ],
};

const audit: AuditRow[] = [];
{
  const actions: [string, string, string?][] = [
    ['admin', 'login', undefined], ['analyst', 'exception.propose', 'shop-api · lodash CVE-2021-23337'], ['admin', 'exception.approve', 'shop-api · lodash CVE-2021-23337'],
    ['admin', 'token.create', 'Grafana read-only'], ['admin', 'user.create', 'viewer'], ['analyst', 'scan.start', 'billing-worker'], ['viewer', 'login', undefined],
    ['admin', 'settings.oidc', 'Microsoft Entra ID'], ['admin', 'settings.digest', 'email, Monday 08:00'], ['analyst', 'target.update', 'shop-api · owner'],
    ['admin', 'user.disable', 'jlee'], ['analyst', 'ticket.create', 'shop-api · GHSA-35jh-r3h4-6jhm'], ['admin', 'logout', undefined],
  ];
  for (let i = 0; i < 140; i++) {
    const a = actions[i % actions.length]!;
    audit.push({ id: 1000 - i, at: iso(i * 5.3 * 3_600_000), username: a[0], action: a[1], target: a[2], detail: a[1] === 'login' ? 'password' : undefined, ip: i % 3 ? '10.0.4.21' : '192.168.1.40' });
  }
}

let digest: DigestSettings = {
  channel: 'email',
  email: { to: ['security@acme.com', 'cto@acme.com'], from: 'nextfix@acme.com', smtpHost: 'smtp.acme.com', smtpPort: 587, smtpUser: 'nextfix', hasPassword: true, secure: true },
  weekday: 1,
  hour: 8,
};

let integrations: Integrations = { github: { repo: 'acme/shop-api', labels: ['security', 'nextfix'], hasToken: true } };
let settings: Settings = { slaActDays: 14, slaAttendDays: 60, retentionScans: 50 };

// ---------------------------------------------------------------------------------------------
// Findings

interface Tpl {
  name: string; version: string; direct?: boolean; dev?: boolean;
  id: string; cve?: string; summary: string; sev: string; cvss: number; fixed?: string;
  tier: ReachTier; decision: Decision; score: number; epss?: number; kev?: boolean;
  entry?: { method: string; path: string; auth: boolean; input: boolean; file: string; line: number };
  symbol?: string; firstSeenDays: number;
}

const EXPOSURE_PUBLISHED: ScanReport['exposure'] = { network: 'published', ports: [3000], evidence: ['Dockerfile: EXPOSE 3000', 'docker-compose.yml: publishes port 3000'] };
/** The shop's logs: 30 days of nginx access logs, read by the scan. */
const SHOP_TRAFFIC: Record<string, EntryPoint['traffic']> = {
  'POST /preview': { requests: 41_230, public: 39_880, internal: 1350, firstSeenAt: daysAgo(30), lastSeenAt: daysAgo(0) },
  'POST /login': { requests: 12_410, public: 12_300, internal: 110, firstSeenAt: daysAgo(30), lastSeenAt: daysAgo(0) },
  'GET /go': { requests: 0, public: 0, internal: 0 },
  'POST /admin/upload': { requests: 36, public: 0, internal: 36, firstSeenAt: daysAgo(22), lastSeenAt: daysAgo(2) },
  'GET /orders': { requests: 2840, public: 2790, internal: 50, firstSeenAt: daysAgo(30), lastSeenAt: daysAgo(0) },
};
const SHOP_TRAFFIC_SUMMARY: ScanReport['traffic'] = {
  files: [{ path: '/var/log/nginx/access.log', format: 'combined', lines: 61_204, parsed: 61_180, matched: 56_516 }, { path: '/var/log/nginx/access.log.1', format: 'combined', lines: 58_911, parsed: 58_900, matched: 54_120 }],
  windowDays: 30, from: daysAgo(30), to: daysAgo(0), requests: 61_180, public: 59_460, internal: 1720, unmatched: 4664, routesSeen: 4, routesCold: 1, stale: false,
};
const SHOP_EXPOSURE: ScanReport['exposure'] = { ...EXPOSURE_PUBLISHED, reach: 'internet', reachEvidence: ['access logs: 59,460 requests from public addresses in the 30 days to today', 'infra/alb.tf: aws_lb "shop" is internet-facing on :443'], observed: { public: 59_460, internal: 1720, days: 30, to: daysAgo(0), stale: false, routesSeen: 4 } };
const EXPOSURE_UNKNOWN = { network: 'unknown' as const, ports: [], evidence: [] };

function entryPoint(e: NonNullable<Tpl['entry']>, exposure?: ScanReport['exposure']): EntryPoint {
  const traffic = exposure?.observed ? SHOP_TRAFFIC[`${e.method} ${e.path}`] ?? { requests: 0, public: 0, internal: 0 } : undefined;
  return { method: e.method, path: e.path, file: e.file, line: e.line, authenticated: e.auth, guards: e.auth ? ['requireAuth'] : [], mounted: true, handlerIds: [`${e.file}#<handler>@${e.line}:12`], ...(traffic ? { traffic } : {}) };
}

function finding(t: Tpl, exposure: ScanReport['exposure']): Finding {
  const purl = `pkg:npm/${t.name}@${t.version}`;
  const component: Component = { ecosystem: 'npm', name: t.name, version: t.version, purl, dev: !!t.dev, optional: false, direct: !!t.direct, path: `node_modules/${t.name}` };
  const symbol = t.symbol ?? 'parse';
  const callSite = { file: `src/services/${t.name}.js`, line: 14, col: 9, text: `${t.name}.${symbol}`, symbol, userInput: !!t.entry?.input };
  const paths = t.entry ? [{
    entry: entryPoint(t.entry, exposure),
    hops: [{ functionId: `${t.entry.file}#<handler>@${t.entry.line}:12`, name: '<handler>', file: t.entry.file, line: t.entry.line }, { functionId: `src/services/${t.name}.js#handle@12:1`, name: 'handle', file: `src/services/${t.name}.js`, line: 12 }],
    callSite,
    userInput: t.entry.input,
    inputEntersAt: t.entry.input ? { file: t.entry.file, line: t.entry.line, name: '<handler>' } : undefined,
    inputSource: t.entry.input ? 'req.body' : undefined,
  }] : [];
  const imported = t.tier !== 'unused' && t.tier !== 'dev-only';
  const why = [
    `${t.name} ${t.version} is affected by ${t.cve ?? t.id}: ${t.summary} (CVSS ${t.cvss.toFixed(1)} ${t.sev}).`,
    t.entry ? `Reachable: ${t.entry.method} ${t.entry.path} → <handler> (${t.entry.file}:${t.entry.line}) → handle (src/services/${t.name}.js:12) → ${t.name}.${symbol}() at src/services/${t.name}.js:14.`
      : t.tier === 'called-unreached' ? `${t.name}.${symbol}() is called at src/services/${t.name}.js:14, but no entry point reaches that code.`
      : t.tier === 'imported-unknown-symbol' ? `${t.name} is imported in src/services/${t.name}.js; no function-level data is available for this advisory yet.`
      : t.tier === 'imported-not-called' ? `${t.name} is imported, but the vulnerable function ${symbol}() is never called.`
      : t.tier === 'dev-only' ? `${t.name} is a development dependency and is not shipped.` : `${t.name} is installed but never imported by application code.`,
    t.entry?.input ? `User-controlled request data enters the chain in <handler> (${t.entry.file}:${t.entry.line}) and is passed down to the vulnerable call.` : '',
    t.entry ? (t.entry.auth ? `The entry point ${t.entry.method} ${t.entry.path} is behind requireAuth.` : `The entry point ${t.entry.method} ${t.entry.path} has no auth guard.`) : '',
    t.kev ? `${t.cve} is on CISA's Known Exploited Vulnerabilities list.` : t.epss !== undefined ? `EPSS puts the chance of exploitation in the next 30 days at ${Math.round(t.epss * 100)}%.` : '',
    t.entry && exposure.observed ? (() => { const tr = SHOP_TRAFFIC[`${t.entry.method} ${t.entry.path}`]; return tr?.requests ? `Observed: ${t.entry.method} ${t.entry.path} received ${tr.requests.toLocaleString('en-US')} requests in the 30 days to today, ${tr.public.toLocaleString('en-US')} from public addresses${t.entry.auth ? ' (behind a login)' : ''}.` : `Observed: no request reached ${t.entry.method} ${t.entry.path} in the 30 days of logs to today.`; })() : '',
    exposure.network === 'published' ? `Service is network-published: ${exposure.evidence.join('; ')}.` : 'Network exposure could not be determined from the project files.',
    exposure.reach === 'internet' ? `Internet-facing: ${(exposure.reachEvidence ?? []).join('; ')}.` : '',
  ].filter(Boolean);
  return {
    id: `${purl}|${t.id}`,
    component,
    advisory: { id: t.id, aliases: t.cve ? [t.cve] : [], cve: t.cve, summary: t.summary, details: `${t.summary}. Versions before ${t.fixed ?? 'the next release'} are affected. See the references for the upstream advisory and the fix commit.`, severityLabel: t.sev, cvssScore: t.cvss, fixedVersion: t.fixed, references: [`https://github.com/advisories/${t.id}`, ...(t.cve ? [`https://nvd.nist.gov/vuln/detail/${t.cve}`] : [])] },
    symbols: imported ? { ids: [t.id], ecosystem: 'npm', package: t.name, symbols: [symbol], source: 'curated', confidence: 'confirmed', references: [`https://github.com/advisories/${t.id}`] } : undefined,
    reach: { tier: t.tier, confidence: imported ? 'confirmed' : 'package-level', importedIn: imported ? [`src/services/${t.name}.js`] : [], callSites: t.tier === 'reachable' || t.tier === 'called-unreached' ? [callSite] : [], paths },
    exposure,
    epss: t.epss !== undefined ? { score: t.epss, percentile: Math.min(0.99, 0.5 + t.epss) } : undefined,
    kev: t.kev ? { dateAdded: daysAgo(30), ransomware: false, cve: t.cve } : undefined,
    exploitation: t.kev ? 'active' : (t.epss ?? 0) >= 0.1 ? 'likely' : 'none',
    decision: t.decision,
    score: t.score,
    why,
    fix: t.fixed ? `Upgrade ${t.name} to ${t.fixed}.` : undefined,
  };
}

const SHOP: Tpl[] = [
  { name: 'lodash', version: '4.17.15', direct: true, id: 'GHSA-35jh-r3h4-6jhm', cve: 'CVE-2021-23337', summary: 'Command injection in lodash template', sev: 'HIGH', cvss: 7.2, fixed: '4.17.21', tier: 'reachable', decision: 'Act', score: 81, epss: 0.21, entry: { method: 'POST', path: '/preview', auth: false, input: true, file: 'src/app.js', line: 12 }, symbol: 'template', firstSeenDays: 41 },
  { name: 'jsonwebtoken', version: '8.5.1', direct: true, id: 'GHSA-8cf7-32gw-wr33', cve: 'CVE-2022-23529', summary: 'Arbitrary code execution via crafted key', sev: 'HIGH', cvss: 7.6, fixed: '9.0.0', tier: 'reachable', decision: 'Act', score: 77, kev: true, epss: 0.44, entry: { method: 'POST', path: '/login', auth: false, input: true, file: 'src/auth.js', line: 22 }, symbol: 'verify', firstSeenDays: 9 },
  { name: 'express', version: '4.17.1', direct: true, id: 'GHSA-rv95-896h-c2vc', cve: 'CVE-2024-29041', summary: 'Open redirect in res.location', sev: 'MEDIUM', cvss: 6.1, fixed: '4.19.2', tier: 'reachable', decision: 'Attend', score: 58, epss: 0.02, entry: { method: 'GET', path: '/go', auth: false, input: true, file: 'src/app.js', line: 18 }, symbol: 'redirect', firstSeenDays: 75 },
  { name: 'multer', version: '1.4.4', direct: true, id: 'GHSA-4pg4-qvpc-4q3h', cve: 'CVE-2025-47935', summary: 'Denial of service through unhandled stream errors', sev: 'HIGH', cvss: 7.5, fixed: '2.0.0', tier: 'reachable', decision: 'Attend', score: 55, epss: 0.01, entry: { method: 'POST', path: '/admin/upload', auth: true, input: true, file: 'src/admin.js', line: 31 }, symbol: 'single', firstSeenDays: 20 },
  { name: 'moment', version: '2.29.1', id: 'GHSA-wc69-rhjr-hc9g', cve: 'CVE-2022-31129', summary: 'Inefficient regular expression in date parsing', sev: 'HIGH', cvss: 7.5, fixed: '2.29.4', tier: 'reachable', decision: 'Attend', score: 49, epss: 0.004, entry: { method: 'GET', path: '/orders', auth: true, input: false, file: 'src/orders.js', line: 9 }, symbol: 'parse', firstSeenDays: 95 },
  { name: 'qs', version: '6.7.0', id: 'GHSA-hrpp-h998-j3pp', cve: 'CVE-2022-24999', summary: 'Prototype pollution in query parsing', sev: 'HIGH', cvss: 7.5, fixed: '6.7.3', tier: 'called-unreached', decision: 'Track*', score: 31, epss: 0.01, firstSeenDays: 60 },
  { name: 'semver', version: '6.3.0', id: 'GHSA-c2qf-rxjj-qqgw', cve: 'CVE-2022-25883', summary: 'Regular expression denial of service', sev: 'MEDIUM', cvss: 5.3, fixed: '6.3.1', tier: 'imported-unknown-symbol', decision: 'Track*', score: 24, epss: 0.003, firstSeenDays: 60 },
  { name: 'body-parser', version: '1.19.0', id: 'GHSA-qwcr-r2fm-qrc7', cve: 'CVE-2024-45590', summary: 'Denial of service when URL encoding is enabled', sev: 'HIGH', cvss: 7.5, fixed: '1.20.3', tier: 'imported-not-called', decision: 'Track', score: 12, epss: 0.002, symbol: 'urlencoded', firstSeenDays: 110 },
  { name: 'path-to-regexp', version: '0.1.7', id: 'GHSA-9wv6-86v2-598j', cve: 'CVE-2024-45296', summary: 'Backtracking regular expressions', sev: 'HIGH', cvss: 7.5, fixed: '0.1.10', tier: 'unused', decision: 'Track', score: 8, epss: 0.001, firstSeenDays: 110 },
  { name: 'minimist', version: '1.2.5', dev: true, id: 'GHSA-xvch-5gv4-984h', cve: 'CVE-2021-44906', summary: 'Prototype pollution', sev: 'CRITICAL', cvss: 9.8, fixed: '1.2.6', tier: 'dev-only', decision: 'Track', score: 4, epss: 0.01, firstSeenDays: 110 },
  { name: 'cookie', version: '0.4.0', id: 'GHSA-pxg6-pf52-xh8x', cve: 'CVE-2024-47764', summary: 'Out-of-bounds characters accepted in cookie fields', sev: 'LOW', cvss: 3.1, fixed: '0.7.0', tier: 'unused', decision: 'Track', score: 3, firstSeenDays: 110 },
];

const BILLING: Tpl[] = [
  { name: 'axios', version: '0.21.1', direct: true, id: 'GHSA-wf5p-g6vw-rhxx', cve: 'CVE-2023-45857', summary: 'Cross-site request forgery token leaked to third parties', sev: 'MEDIUM', cvss: 6.5, fixed: '1.6.0', tier: 'reachable', decision: 'Attend', score: 52, epss: 0.03, entry: { method: 'POST', path: '/webhooks/stripe', auth: false, input: true, file: 'src/webhooks.js', line: 7 }, symbol: 'post', firstSeenDays: 70 },
  { name: 'xml2js', version: '0.4.19', id: 'GHSA-776f-qx25-q3cc', cve: 'CVE-2023-0842', summary: 'Prototype pollution via __proto__ keys', sev: 'MEDIUM', cvss: 5.3, fixed: '0.5.0', tier: 'reachable', decision: 'Attend', score: 47, epss: 0.005, entry: { method: 'POST', path: '/invoices/import', auth: true, input: true, file: 'src/invoices.js', line: 40 }, symbol: 'parseString', firstSeenDays: 33 },
  { name: 'ws', version: '7.4.6', id: 'GHSA-3h5v-q93c-6h6q', cve: 'CVE-2024-37890', summary: 'Denial of service through many HTTP headers', sev: 'HIGH', cvss: 7.5, fixed: '7.5.10', tier: 'called-unreached', decision: 'Track*', score: 28, epss: 0.006, firstSeenDays: 33 },
  { name: 'tar', version: '6.1.0', id: 'GHSA-5955-9wpr-37jh', cve: 'CVE-2021-37713', summary: 'Arbitrary file creation on Windows', sev: 'HIGH', cvss: 8.2, fixed: '6.1.9', tier: 'unused', decision: 'Track', score: 6, epss: 0.004, firstSeenDays: 120 },
  { name: 'ansi-regex', version: '5.0.0', dev: true, id: 'GHSA-93q8-gq69-wqmw', cve: 'CVE-2021-3807', summary: 'Inefficient regular expression', sev: 'HIGH', cvss: 7.5, fixed: '5.0.1', tier: 'dev-only', decision: 'Track', score: 2, firstSeenDays: 120 },
];

const PORTAL: Tpl[] = [
  { name: 'node-fetch', version: '2.6.1', id: 'GHSA-r683-j2x4-v87g', cve: 'CVE-2022-0235', summary: 'Authorization header leaked on redirect', sev: 'HIGH', cvss: 8.8, fixed: '2.6.7', tier: 'imported-not-called', decision: 'Track', score: 10, epss: 0.004, symbol: 'fetch', firstSeenDays: 50 },
  { name: 'ejs', version: '3.1.6', id: 'GHSA-phwq-j96m-2c2q', cve: 'CVE-2022-29078', summary: 'Server-side template injection', sev: 'CRITICAL', cvss: 9.8, fixed: '3.1.7', tier: 'unused', decision: 'Track', score: 9, epss: 0.3, firstSeenDays: 50 },
  { name: 'nth-check', version: '1.0.2', dev: true, id: 'GHSA-rp65-9cf3-cjxr', cve: 'CVE-2021-3803', summary: 'Inefficient regular expression', sev: 'HIGH', cvss: 7.5, fixed: '2.0.1', tier: 'dev-only', decision: 'Track', score: 2, firstSeenDays: 50 },
];

const TIERS: ReachTier[] = ['reachable', 'called-unreached', 'imported-unknown-symbol', 'image-only', 'imported-not-called', 'unused', 'dev-only'];

function summarize(findings: Finding[], components: number): ScanSummary {
  const byDecision: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
  const byTier = Object.fromEntries(TIERS.map((t) => [t, 0])) as Record<ReachTier, number>;
  for (const f of findings) { byDecision[f.decision]++; byTier[f.reach.tier]++; }
  const actionable = byDecision.Act + byDecision.Attend;
  return { components, advisories: findings.length, findings: findings.length, byDecision, byTier, noiseRemoved: findings.length ? (findings.length - actionable) / findings.length : 0 };
}

function cleanComponents(prefix: string, n: number): Component[] {
  return Array.from({ length: n }, (_, i) => ({ ecosystem: 'npm' as const, name: `${prefix}-${i + 1}`, version: `1.${i}.0`, purl: `pkg:npm/${prefix}-${i + 1}@1.${i}.0`, dev: false, optional: false, direct: i < 3, path: `node_modules/${prefix}-${i + 1}` }));
}

interface MockTarget { target: Target; templates: Tpl[]; exposure: ScanReport['exposure']; scans: { meta: ScanMeta; report: ScanReport }[]; firstSeen: Record<string, string> }

let nextScanId = 100;
function buildScans(targetId: number, name: string, dir: string, templates: Tpl[], exposure: ScanReport['exposure'], history: number[], spacingDays: number, lastHoursAgo = 0): { meta: ScanMeta; report: ScanReport }[] {
  const out: { meta: ScanMeta; report: ScanReport }[] = [];
  const all = templates.map((t) => finding(t, exposure));
  const entries = templates.filter((t) => t.entry).map((t) => entryPoint(t.entry!, exposure));
  const quiet = exposure.observed ? { traffic: { requests: 0, public: 0, internal: 0 } } : {};
  const extraEntries: EntryPoint[] = [
    { method: 'GET', path: '/healthz', file: 'src/app.js', line: 23, authenticated: false, guards: [], mounted: true, handlerIds: ['src/app.js#<handler>@23:21'], ...(exposure.observed ? { traffic: { requests: 8640, public: 0, internal: 8640, firstSeenAt: daysAgo(30), lastSeenAt: daysAgo(0) } } : {}) },
    { method: 'GET', path: '/account', file: 'src/app.js', line: 40, authenticated: true, guards: ['requireAuth'], mounted: true, handlerIds: ['src/app.js#<handler>@40:21'], ...quiet },
  ];
  const components = [...all.map((f) => f.component), ...cleanComponents(name.slice(0, 4), 40)];
  history.forEach((actionable, i) => {
    const scansFromEnd = history.length - 1 - i;
    const at = iso(scansFromEnd * spacingDays * DAY + lastHoursAgo * 3_600_000);
    // Older scans carry the actionable count the trend shows; the latest scan carries the real findings.
    let findings = all;
    if (scansFromEnd > 0) {
      const act = all.filter((f) => f.decision === 'Act' || f.decision === 'Attend');
      const rest = all.filter((f) => f.decision !== 'Act' && f.decision !== 'Attend');
      findings = [...act.slice(0, actionable), ...rest];
      if (actionable > act.length) findings = [...findings, ...rest.slice(0, actionable - act.length).map((f) => ({ ...f, decision: 'Attend' as Decision }))];
    }
    const report: ScanReport = { tool: { name: 'NextFix', version: VERSION }, target: { dir, name, version: '1.4.0' }, generatedAt: at, summary: summarize(findings, components.length), exposure, entryPoints: [...entries, ...extraEntries], ...(exposure.observed && scansFromEnd === 0 ? { traffic: SHOP_TRAFFIC_SUMMARY } : {}), components, findings };
    const meta: ScanMeta = { id: nextScanId++, targetId, createdAt: at, toolVersion: VERSION, summary: report.summary };
    out.push({ meta, report });
  });
  return out;
}

const targets: MockTarget[] = [];
function addMockTarget(id: number, name: string, dir: string, owner: string | null, schedule: Target['schedule'], templates: Tpl[], exposure: ScanReport['exposure'], history: number[], spacingDays: number, lastHoursAgo = 0) {
  const scans = history.length ? buildScans(id, name, dir, templates, exposure, history, spacingDays, lastHoursAgo) : [];
  const last = scans[scans.length - 1];
  const firstSeen: Record<string, string> = {};
  for (const t of templates) firstSeen[`pkg:npm/${t.name}@${t.version}|${t.id}`] = daysAgo(t.firstSeenDays);
  targets.push({ target: { id, dir, name, createdAt: daysAgo(130), lastScan: last?.meta, owner, schedule }, templates, exposure, scans, firstSeen });
}
addMockTarget(1, 'shop-api', 'C:\\src\\shop-api', 'Priya Raman', { everyHours: 24 }, SHOP, SHOP_EXPOSURE, [3, 4, 4, 6, 5, 5, 4, 5], 7, 3);
addMockTarget(2, 'billing-worker', 'C:\\src\\billing-worker', 'Jordan Lee', { everyHours: 168 }, BILLING, EXPOSURE_UNKNOWN, [1, 2, 2], 14, 31);
addMockTarget(3, 'partner-portal', 'C:\\src\\partner-portal', null, null, PORTAL, EXPOSURE_PUBLISHED, [2, 1, 0, 0], 10, 6 * 24);
addMockTarget(4, 'marketing-site', 'C:\\src\\marketing-site', 'Tom Okafor', null, [], EXPOSURE_UNKNOWN, [], 0);

const fid = (name: string, version: string, id: string) => `pkg:npm/${name}@${version}|${id}`;
let nextExceptionId = 10;
const exceptions: Record<number, Exception[]> = {
  1: [
    { id: 'e1', findingId: fid('moment', '2.29.1', 'GHSA-wc69-rhjr-hc9g'), kind: 'mitigated', reason: 'Input length is capped at 32 characters by the orders validator before it reaches moment; the pathological pattern cannot trigger.', status: 'approved', proposedBy: 'analyst', approvedBy: 'admin', expiresAt: iso(-22 * DAY), createdAt: daysAgo(30), updatedAt: daysAgo(29) },
    { id: 'e2', findingId: fid('multer', '1.4.4', 'GHSA-4pg4-qvpc-4q3h'), kind: 'accepted-risk', reason: 'Upload endpoint is admin-only and rate-limited at the gateway; upgrade to multer 2 is scheduled with the Q1 Express 5 migration.', status: 'pending', proposedBy: 'analyst', expiresAt: iso(-90 * DAY), createdAt: daysAgo(2), updatedAt: daysAgo(2) },
    { id: 'e3', findingId: fid('express', '4.17.1', 'GHSA-rv95-896h-c2vc'), kind: 'false-positive', reason: 'The redirect target comes from a server-side allowlist.', status: 'rejected', proposedBy: 'analyst', approvedBy: 'admin', createdAt: daysAgo(12), updatedAt: daysAgo(11) },
  ],
  2: [
    { id: 'e4', findingId: fid('xml2js', '0.4.19', 'GHSA-776f-qx25-q3cc'), kind: 'mitigated', reason: 'Imports run behind SSO and the parser is called with explicitArray and no prototype keys.', status: 'pending', proposedBy: 'analyst', expiresAt: iso(-180 * DAY), createdAt: daysAgo(1), updatedAt: daysAgo(1) },
  ],
  3: [],
  4: [],
};

const ticketMap: Record<number, TicketMap> = {
  1: { [fid('lodash', '4.17.15', 'GHSA-35jh-r3h4-6jhm')]: [{ kind: 'github', key: '#142', url: 'https://github.com/acme/shop-api/issues/142', createdAt: daysAgo(5) }] },
};

// ---------------------------------------------------------------------------------------------
// Session

function authMode(): 'none' | 'local' | 'oidc' {
  const v = localStorage.getItem('nextfix.mock.authMode');
  return v === 'none' || v === 'local' ? v : 'oidc';
}
function setupRequired() { return localStorage.getItem('nextfix.mock.setup') === '1'; }
function currentUser(): User | undefined {
  if (authMode() === 'none') return undefined;
  const id = sessionStorage.getItem('nextfix.mock.user');
  return users.find((u) => u.id === id && !u.disabled);
}
function session(): Session {
  const s: Session = { setupRequired: setupRequired(), authMode: authMode(), user: currentUser() };
  if (authMode() === 'oidc') s.oidc = { providers: oidc.providers.map((p) => ({ id: p.id, name: p.name })) };
  return s;
}
const roleOf = (u?: User): Role => (authMode() === 'none' ? 'admin' : u?.role ?? 'viewer');

// ---------------------------------------------------------------------------------------------
// Derived views

function trimmed(report: ScanReport, targetId: number): ListReport {
  const t = targets.find((x) => x.target.id === targetId)!;
  const latest = latestExceptionByFinding(targetId);
  return {
    ...report,
    findings: report.findings.map((f) => {
      const { details: _d, ...adv } = f.advisory;
      const ex = latest[f.id];
      return { ...f, advisory: { ...adv, references: f.advisory.references.slice(0, 6), referenceCount: f.advisory.references.length }, firstSeenAt: t.firstSeen[f.id], exception: ex ? { id: ex.id, kind: ex.kind, status: ex.status, expiresAt: ex.expiresAt } : undefined };
    }),
  };
}

function latestExceptionByFinding(targetId: number): Record<string, Exception> {
  const out: Record<string, Exception> = {};
  for (const e of [...(exceptions[targetId] ?? [])].sort((a, b) => a.updatedAt.localeCompare(b.updatedAt))) out[e.findingId] = e;
  return out;
}

function diffFor(t: MockTarget, scanId: number): ScanDiff | null {
  const i = t.scans.findIndex((s) => s.meta.id === scanId);
  if (i <= 0) return null;
  const cur = t.scans[i]!.report;
  const prev = t.scans[i - 1]!;
  const curIds = new Set(cur.findings.map((f) => f.id));
  const prevIds = new Map(prev.report.findings.map((f) => [f.id, f]));
  const added = cur.findings.filter((f) => !prevIds.has(f.id));
  const resolved = prev.report.findings.filter((f) => !curIds.has(f.id));
  const changed = cur.findings.filter((f) => prevIds.has(f.id) && prevIds.get(f.id)!.decision !== f.decision).map((f) => ({ finding: f, from: prevIds.get(f.id)!.decision, to: f.decision, reasons: ['EPSS rose above 10%'] }));
  const order: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];
  return { previous: prev.meta, added, resolved, changed, summary: { added: added.length, resolved: resolved.length, escalated: changed.filter((c) => order.indexOf(c.to) < order.indexOf(c.from)).length, deescalated: changed.filter((c) => order.indexOf(c.to) > order.indexOf(c.from)).length } };
}

function historyFor(t: MockTarget): History {
  const buckets = ['0-7', '8-30', '31-90', '90+'] as const;
  const bucket = (days: number) => (days <= 7 ? '0-7' : days <= 30 ? '8-30' : days <= 90 ? '31-90' : '90+');
  const open = Object.fromEntries((['Act', 'Attend', 'Track*', 'Track'] as Decision[]).map((d) => [d, Object.fromEntries(buckets.map((b) => [b, 0]))])) as History['open'];
  const pastSla: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
  const last = t.scans[t.scans.length - 1];
  const rows: History['rows'] = [];
  for (const f of last?.report.findings ?? []) {
    const tpl = t.templates.find((x) => fid(x.name, x.version, x.id) === f.id)!;
    open[f.decision][bucket(tpl.firstSeenDays)]++;
    const sla = f.decision === 'Act' ? settings.slaActDays : f.decision === 'Attend' ? settings.slaAttendDays : Infinity;
    if (tpl.firstSeenDays > sla) pastSla[f.decision]++;
    rows.push({ targetId: t.target.id, findingId: f.id, firstSeenAt: t.firstSeen[f.id]!, lastSeenAt: last!.meta.createdAt, firstScanId: t.scans[0]!.meta.id, lastScanId: last!.meta.id, resolvedAt: null, resolvedScanId: null, decisionLatest: f.decision });
  }
  return { rows, open, pastSla, sla: { slaActDays: settings.slaActDays, slaAttendDays: settings.slaAttendDays }, medianDaysToResolve: 11, resolvedLast30: 3, introducedLast30: 2, firstSeen: t.firstSeen, computedAt: iso(0) };
}

/** Links between the mock applications: shop calls billing; the portal calls shop; shop and billing use Stripe. */
const MOCK_LINKS: Record<number, { host: string; evidence: string; external: boolean }[]> = {
  1: [{ host: 'billing-worker', evidence: 'docker-compose.yml: services.shop-api.depends_on billing-worker', external: false }, { host: 'api.stripe.com', evidence: 'docker-compose.yml: services.shop-api.environment: STRIPE_API=https://api.stripe.com', external: true }, { host: 'search', evidence: '.env.example: SEARCH_HOST=search', external: false }],
  2: [{ host: 'api.stripe.com', evidence: '.env.example: STRIPE_URL=https://api.stripe.com/v1', external: true }, { host: 'warehouse.acme.internal', evidence: 'config/app.json: warehouse.acme.internal:5432', external: false }],
  3: [{ host: 'shop-api', evidence: 'k8s/deploy.yaml: Deployment partner-portal env: SHOP_URL=http://shop-api.default.svc.cluster.local', external: false }, { host: 'smtp.sendgrid.net', evidence: '.env.example: MAIL_HOST=smtp.sendgrid.net', external: true }],
};
const MOCK_REACH: Record<number, { reach: InternetReach; evidence: string[] }> = {
  1: { reach: 'internet', evidence: ['access logs: 59,460 requests from public addresses in the 30 days to today', 'infra/alb.tf: aws_lb "shop" is internet-facing on :443'] },
  2: { reach: 'internal', evidence: ['infra/alb.tf: aws_lb "billing" is internal'] },
  3: { reach: 'internet', evidence: ['k8s/ingress.yaml: Ingress partner for partners.acme.com'] },
};

function portfolioMap(): PortfolioMap {
  const rows = portfolio().targets;
  const names = new Map(rows.map((t) => [t.name.toLowerCase(), t.id]));
  const edges: MapEdge[] = [];
  const external = new Map<string, ExternalNode>();
  for (const t of rows) {
    for (const l of MOCK_LINKS[t.id] ?? []) {
      const to = names.get(l.host.toLowerCase());
      if (to !== undefined && to !== t.id) edges.push({ from: t.id, to, host: l.host, evidence: l.evidence });
      else {
        const x = external.get(l.host) ?? { host: l.host, external: l.external, callers: [] };
        x.callers.push({ id: t.id, evidence: l.evidence });
        external.set(l.host, x);
      }
    }
  }
  const reach = (id: number, dir: 'from' | 'to') => {
    const seen = new Set<number>();
    const stack = edges.filter((e) => e[dir] === id).map((e) => (dir === 'from' ? e.to : e.from));
    while (stack.length) { const n = stack.pop()!; if (n === id || seen.has(n)) continue; seen.add(n); for (const e of edges) if (e[dir] === n) stack.push(dir === 'from' ? e.to : e.from); }
    return [...seen].sort((a, b) => a - b);
  };
  const nodes: MapNode[] = rows.map((t) => ({ id: t.id, name: t.name, owner: t.owner ?? null, posture: t.posture, byDecision: t.byDecision, reach: MOCK_REACH[t.id]?.reach ?? 'unknown', reachEvidence: MOCK_REACH[t.id]?.evidence ?? [], lastScanAt: t.lastScanAt, identity: { names: [t.name], hosts: [] }, headline: t.posture === 'Exposed' ? targets.find((x) => x.target.id === t.id)?.scans.at(-1)?.report.findings[0]?.why[0] : undefined, exposedSurface: t.exposedSurface, upstream: reach(t.id, 'to'), downstream: reach(t.id, 'from') }));
  return { nodes, edges, external: [...external.values()], internet: nodes.filter((n) => n.reach === 'internet').map((n) => n.id), computedAt: iso(0) };
}

function portfolio(): Portfolio {
  const rows: PortfolioTarget[] = targets.map((t) => {
    const last = t.scans[t.scans.length - 1];
    const s = last?.report.summary;
    const approvedIds = new Set(Object.values(latestExceptionByFinding(t.target.id)).filter((e) => e.status === 'approved').map((e) => e.findingId));
    const effective = (last?.report.findings ?? []).map((f) => (approvedIds.has(f.id) ? { ...f, decision: 'Track' as Decision } : f));
    const byDecision: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
    for (const f of effective) byDecision[f.decision]++;
    const posture = !last ? 'Never scanned' : byDecision.Act ? 'Exposed' : byDecision.Attend ? 'Attention' : byDecision['Track*'] ? 'Contained' : 'Clean';
    const openRoutes = last?.report.entryPoints.filter((e) => !e.authenticated) ?? [];
    const exposed = openRoutes.filter((e) => effective.some((f) => (f.decision === 'Act' || f.decision === 'Attend') && f.reach.paths.some((p) => p.entry.path === e.path && p.entry.method === e.method)));
    let oldest: number | undefined;
    for (const f of effective) {
      const tpl = t.templates.find((x) => fid(x.name, x.version, x.id) === f.id)!;
      const sla = f.decision === 'Act' ? settings.slaActDays : f.decision === 'Attend' ? settings.slaAttendDays : Infinity;
      if (tpl.firstSeenDays > sla) oldest = Math.max(oldest ?? 0, tpl.firstSeenDays - sla);
    }
    return { id: t.target.id, name: t.target.name ?? t.target.dir, dir: t.target.dir, owner: t.target.owner, lastScanAt: last?.meta.createdAt, posture, byDecision, exposedSurface: { open: exposed.length, total: openRoutes.length }, oldestPastSlaDays: oldest, trend: t.scans.slice(-8).map((x) => x.meta.summary.byDecision.Act + x.meta.summary.byDecision.Attend), pendingExceptions: (exceptions[t.target.id] ?? []).filter((e) => e.status === 'pending').length, reach: last ? MOCK_REACH[t.target.id]?.reach ?? 'unknown' : undefined, surfaceChanges: t.target.id === 1 ? 2 : 0, ...(s ? {} : {}) };
  });
  return { targets: rows };
}

// ---------------------------------------------------------------------------------------------
// Router

const json = (status: number, body: unknown, headers: Record<string, string> = {}) => new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
const fail = (status: number, error: string, headers?: Record<string, string>) => json(status, { error }, headers);
let scanning: { targetId: number; stage: string; startedAt: string } | null = null;

function log(username: string, action: string, target?: string, detail?: string) {
  audit.unshift({ id: (audit[0]?.id ?? 1000) + 1, at: iso(0), username, action, target, detail, ip: '127.0.0.1' });
}

async function route(method: string, path: string, query: URLSearchParams, body: Record<string, unknown>): Promise<Response> {
  const user = currentUser();
  const role = roleOf(user);
  const who = user?.username ?? 'local';
  const seg = path.replace(/^\/api\//, '').split('/');
  const [a, b, c, d] = seg;

  // --- session
  if (a === 'session' && method === 'GET') return json(200, session());
  if (a === 'setup' && method === 'POST') {
    if (!setupRequired()) return fail(409, 'Setup has already been completed');
    const username = String(body.username ?? '').trim();
    if (!username || String(body.password ?? '').length < 8) return fail(400, 'Choose a username and a password of at least 8 characters');
    users.unshift({ id: 'u0', username, displayName: String(body.displayName ?? username), role: 'admin', createdAt: iso(0), lastLoginAt: iso(0) });
    localStorage.removeItem('nextfix.mock.setup');
    sessionStorage.setItem('nextfix.mock.user', 'u0');
    log(username, 'setup');
    return json(200, session());
  }
  if (a === 'login' && method === 'POST') {
    const username = String(body.username ?? '').trim().toLowerCase();
    if (username === 'locked') return fail(429, 'Too many attempts. Try again in 5 minutes.', { 'retry-after': '300' });
    const u = users.find((x) => x.username === username);
    if (!u || body.password === 'wrong' || !body.password) return fail(401, 'Wrong username or password');
    if (u.disabled) return fail(401, 'This account is disabled');
    sessionStorage.setItem('nextfix.mock.user', u.id);
    u.lastLoginAt = iso(0);
    log(u.username, 'login', undefined, 'password');
    return json(200, session());
  }
  if (a === 'logout' && method === 'POST') { log(who, 'logout'); sessionStorage.removeItem('nextfix.mock.user'); return json(204, null); }
  if (a === 'auth') return fail(400, 'Single sign-on is not available in the mock');

  if (authMode() !== 'none' && !user && !setupRequired()) return fail(401, 'Sign in to continue');
  if (setupRequired()) return fail(401, 'Set up the first administrator');
  const adminOnly = () => (role === 'admin' ? null : fail(403, 'Only an administrator can do this'));
  const notViewer = () => (role === 'viewer' ? fail(403, 'Viewers cannot change anything') : null);

  // --- users
  if (a === 'users') {
    const deny = adminOnly();
    if (deny && !(method === 'POST' && c === 'password' && b === user?.id)) return deny;
    if (method === 'GET' && !b) return json(200, users);
    if (method === 'POST' && !b) {
      const username = String(body.username ?? '').trim();
      if (!username) return fail(400, 'Username is required');
      if (users.some((u) => u.username === username)) return fail(409, 'That username is taken');
      if (String(body.password ?? '').length < 8) return fail(400, 'Password must be at least 8 characters');
      const u: User = { id: `u${Date.now()}`, username, displayName: String(body.displayName || username), role: (body.role as Role) ?? 'viewer', createdAt: iso(0) };
      users.push(u);
      log(who, 'user.create', username);
      return json(201, u);
    }
    const u = users.find((x) => x.id === b);
    if (!u) return fail(404, 'No such user');
    if (method === 'PATCH') {
      if (u.id === user?.id && (body.role !== undefined && body.role !== 'admin' || body.disabled)) return fail(400, 'You cannot demote or disable your own account');
      if (body.role !== undefined) u.role = body.role as Role;
      if (body.disabled !== undefined) u.disabled = !!body.disabled;
      if (body.displayName !== undefined) u.displayName = String(body.displayName);
      log(who, 'user.update', u.username);
      return json(200, u);
    }
    if (method === 'POST' && c === 'password') {
      if (u.id === user?.id && body.currentPassword === 'wrong') return fail(401, 'Current password is wrong');
      if (String(body.password ?? '').length < 8) return fail(400, 'Password must be at least 8 characters');
      log(who, 'user.password', u.username);
      return json(204, null);
    }
    if (method === 'DELETE') {
      if (u.id === user?.id) return fail(400, 'You cannot delete your own account');
      users.splice(users.indexOf(u), 1);
      log(who, 'user.delete', u.username);
      return json(204, null);
    }
  }

  // --- tokens
  if (a === 'tokens') {
    const deny = adminOnly();
    if (deny) return deny;
    if (method === 'GET') return json(200, tokens);
    if (method === 'POST') {
      const name = String(body.name ?? '').trim();
      const scopes = (body.scopes as ApiToken['scopes']) ?? [];
      if (!name) return fail(400, 'Name is required');
      if (!scopes.length) return fail(400, 'Choose at least one scope');
      const t: ApiToken = { id: `t${Date.now()}`, name, scopes, createdAt: iso(0), lastUsedAt: null, createdBy: who };
      tokens.push(t);
      log(who, 'token.create', name);
      return json(201, { id: t.id, token: `nfx_${Array.from(crypto.getRandomValues(new Uint8Array(24)), (x) => x.toString(16).padStart(2, '0')).join('')}` });
    }
    if (method === 'DELETE' && b) {
      const i = tokens.findIndex((t) => t.id === b);
      if (i < 0) return fail(404, 'No such token');
      log(who, 'token.revoke', tokens[i]!.name);
      tokens.splice(i, 1);
      return json(204, null);
    }
  }

  // --- settings
  if (a === 'settings' && b === 'oidc') {
    const deny = adminOnly();
    if (deny) return deny;
    if (method === 'GET') return json(200, oidc);
    if (method === 'PUT') {
      const incoming = (body.providers as OidcProvider[]) ?? [];
      oidc.providers = incoming.map((p) => {
        const prev = oidc.providers.find((x) => x.id === p.id);
        const { clientSecret, ...rest } = p;
        if (!rest.issuer || !rest.clientId) throw new Error(`${rest.name || rest.id}: issuer and client id are required`);
        return { ...rest, hasSecret: !!clientSecret || !!prev?.hasSecret, redirectUri: `${origin()}/api/auth/oidc/${rest.id}/callback` };
      });
      log(who, 'settings.oidc', oidc.providers.map((p) => p.name).join(', '));
      return json(200, oidc);
    }
  }
  if (a === 'settings' && b === 'digest') {
    const deny = adminOnly();
    if (deny) return deny;
    if (method === 'GET') return json(200, digest);
    if (method === 'PUT') {
      const { smtpPassword, slackWebhook, teamsWebhook, ...rest } = body as unknown as DigestSettings & { smtpPassword?: string; slackWebhook?: string; teamsWebhook?: string };
      digest = {
        ...rest,
        email: rest.email ? { ...rest.email, hasPassword: !!smtpPassword || !!digest.email?.hasPassword } : undefined,
        slack: rest.channel === 'slack' ? { hasWebhook: !!slackWebhook || !!digest.slack?.hasWebhook } : digest.slack,
        teams: rest.channel === 'teams' ? { hasWebhook: !!teamsWebhook || !!digest.teams?.hasWebhook } : digest.teams,
      };
      log(who, 'settings.digest', digest.channel ?? 'off');
      return json(200, digest);
    }
  }
  if (a === 'digest' && b === 'test' && method === 'POST') {
    const deny = adminOnly();
    if (deny) return deny;
    if (!digest.channel) return json(200, { ok: false, message: 'No channel is configured' });
    return json(200, { ok: true, message: digest.channel === 'email' ? `Test message sent to ${digest.email?.to.join(', ')}` : `Test message posted to ${digest.channel}` });
  }
  if (a === 'digest' && b === 'preview' && method === 'POST') {
    const deny = adminOnly();
    if (deny) return deny;
    const p = portfolio().targets;
    const lines = p.map((t) => `${t.name.padEnd(18)} ${t.posture.padEnd(14)} ${t.byDecision.Act} fix now · ${t.byDecision.Attend} next cycle${t.pendingExceptions ? ` · ${t.pendingExceptions} pending` : ''}`);
    return json(200, { subject: `NextFix weekly: ${p.filter((t) => t.posture === 'Exposed').length} exposed, ${p.reduce((n, t) => n + t.byDecision.Act + t.byDecision.Attend, 0)} findings need action`, text: `Posture across ${p.length} applications\n\n${lines.join('\n')}\n\nPending approvals: ${p.reduce((n, t) => n + t.pendingExceptions, 0)}\nOpen the dashboard: ${origin()}/#/portfolio` });
  }
  if (a === 'settings' && !b) {
    if (method === 'GET') return json(200, settings);
    if (method === 'PUT') { const deny = adminOnly(); if (deny) return deny; settings = { ...settings, ...(body as Partial<Settings>) }; return json(200, settings); }
  }

  // --- audit
  if (a === 'audit' && method === 'GET') {
    const deny = adminOnly();
    if (deny) return deny;
    const limit = Number(query.get('limit') ?? 100);
    const before = query.get('before') ? Number(query.get('before')) : null;
    const rows = audit.filter((r) => before === null || r.id < before).slice(0, limit);
    const last = rows[rows.length - 1];
    return json(200, { rows, next: last && audit.some((r) => r.id < last.id) ? last.id : null });
  }

  // --- health, scan progress
  if (a === 'health') return json(200, { ok: true, version: VERSION, scanning, dbPath: 'C:\\Users\\you\\AppData\\Roaming\\nextfix\\history.sqlite', cachePath: 'C:\\Users\\you\\AppData\\Local\\nextfix\\cache' });
  if (a === 'scan' && b === 'progress') return json(200, scanning ? { ...scanning, lines: ['resolving lockfile', 'querying OSV'] } : null);
  if (a === 'scan' && method === 'DELETE') { scanning = null; return json(200, { cancelled: true }); }

  // --- integrations
  if (a === 'integrations') {
    if (method === 'GET') return json(200, integrations);
    const deny = adminOnly();
    if (deny) return deny;
    if (method === 'PUT' && b === 'github') { integrations = { ...integrations, github: { repo: String(body.repo ?? ''), labels: String(body.labels ?? '').split(',').map((s) => s.trim()).filter(Boolean), hasToken: !!body.token || !!integrations.github?.hasToken } }; return json(200, { ok: true }); }
    if (method === 'PUT' && b === 'jira') { integrations = { ...integrations, jira: { baseUrl: String(body.baseUrl ?? ''), email: String(body.email ?? ''), projectKey: String(body.projectKey ?? ''), issueType: String(body.issueType ?? 'Task'), hasToken: !!body.apiToken || !!integrations.jira?.hasToken } }; return json(200, { ok: true }); }
    if (method === 'DELETE' && b) { const { [b as 'github' | 'jira']: _x, ...rest } = integrations; integrations = rest; return json(204, null); }
    if (method === 'POST' && c === 'test') return json(200, { ok: true, message: 'Connected' });
  }

  // --- portfolio
  if (a === 'portfolio' && b === 'map' && method === 'GET') return json(200, portfolioMap());
  if (a === 'portfolio' && method === 'GET') return json(200, portfolio());

  // --- targets
  if (a === 'targets') {
    if (method === 'GET' && !b) return json(200, targets.map((t) => t.target));
    if (method === 'POST' && !b) {
      const deny = notViewer();
      if (deny) return deny;
      const dir = String(body.dir ?? '').trim();
      if (!dir) return fail(400, 'Folder is required');
      const id = Math.max(...targets.map((t) => t.target.id)) + 1;
      const name = dir.split(/[\\/]/).filter(Boolean).pop() ?? dir;
      scanning = { targetId: id, stage: 'querying advisories', startedAt: iso(0) };
      await delay(900);
      scanning = null;
      addMockTarget(id, name, dir, user?.displayName ?? null, null, PORTAL.slice(0, 2), EXPOSURE_UNKNOWN, [0], 0);
      exceptions[id] = [];
      const t = targets[targets.length - 1]!;
      log(who, 'scan.start', name);
      return json(201, { target: t.target, scan: t.scans[0]!.meta, report: t.scans[0]!.report });
    }
    const t = targets.find((x) => x.target.id === Number(b));
    if (!t) return fail(404, 'No such application');
    if (method === 'PATCH' && !c) {
      const deny = notViewer();
      if (deny) return deny;
      if (body.owner !== undefined) t.target.owner = body.owner === null ? null : String(body.owner);
      if (body.schedule !== undefined) t.target.schedule = body.schedule === null ? null : { everyHours: Number((body.schedule as { everyHours: number }).everyHours) };
      log(who, 'target.update', t.target.name ?? t.target.dir);
      return json(200, t.target);
    }
    if (method === 'DELETE' && !c) { const deny = adminOnly(); if (deny) return deny; targets.splice(targets.indexOf(t), 1); return json(204, null); }
    if (method === 'POST' && c === 'scan') {
      const deny = notViewer();
      if (deny) return deny;
      scanning = { targetId: t.target.id, stage: 'tracing reachability', startedAt: iso(0) };
      await delay(900);
      scanning = null;
      const last = t.scans[t.scans.length - 1];
      const history = t.scans.length ? [...t.scans.map((s) => s.meta.summary.byDecision.Act + s.meta.summary.byDecision.Attend), last!.meta.summary.byDecision.Act + last!.meta.summary.byDecision.Attend] : [0];
      t.scans = buildScans(t.target.id, t.target.name ?? '', t.target.dir, t.templates.length ? t.templates : PORTAL.slice(0, 2), t.exposure, history, 7);
      t.target.lastScan = t.scans[t.scans.length - 1]!.meta;
      log(who, 'scan.start', t.target.name ?? t.target.dir);
      return json(200, { scan: t.target.lastScan, report: t.scans[t.scans.length - 1]!.report });
    }
    if (method === 'GET' && c === 'scans') return json(200, t.scans.map((s) => s.meta));
    if (method === 'GET' && c === 'history') return json(200, historyFor(t));
    if (method === 'POST' && c === 'redecide') return json(200, { scanId: t.target.lastScan?.id ?? 0, checkedAt: iso(0), changed: [], summary: { changed: 0, escalated: 0, deescalated: 0 } });
    if (method === 'GET' && c === 'tickets') return json(200, ticketMap[t.target.id] ?? {});
    if (method === 'POST' && c === 'tickets') {
      const deny = notViewer();
      if (deny) return deny;
      const ids = (body.findingIds as string[]) ?? [];
      const map = (ticketMap[t.target.id] ??= {});
      const results = ids.map((id, i) => { const key = `#${150 + i}`; const url = `https://github.com/acme/shop-api/issues/${150 + i}`; (map[id] ??= []).push({ kind: 'github', key, url, createdAt: iso(0) }); return { findingId: id, key, url }; });
      log(who, 'ticket.create', `${t.target.name} · ${ids.length} findings`);
      return json(200, { results });
    }
    if (c === 'exceptions') {
      if (method === 'GET') return json(200, exceptions[t.target.id] ?? []);
      if (method === 'POST') {
        const deny = notViewer();
        if (deny) return deny;
        const reason = String(body.reason ?? '').trim();
        if (!reason) return fail(400, 'A reason is required');
        const e: Exception = { id: `e${nextExceptionId++}`, findingId: String(body.findingId), kind: body.kind as ExceptionKind, reason, status: 'pending', proposedBy: who, expiresAt: body.expiresAt ? String(body.expiresAt) : null, createdAt: iso(0), updatedAt: iso(0) };
        (exceptions[t.target.id] ??= []).push(e);
        log(who, 'exception.propose', `${t.target.name} · ${e.findingId.split('|')[1]}`);
        return json(201, e);
      }
    }
  }

  if (a === 'exceptions' && b && method === 'PATCH') {
    const deny = adminOnly();
    if (deny) return deny;
    for (const list of Object.values(exceptions)) {
      const e = list.find((x) => x.id === b);
      if (!e) continue;
      e.status = body.status as Exception['status'];
      e.approvedBy = who;
      e.updatedAt = iso(0);
      if (body.reason) e.reason = `${e.reason}\n\n${who}: ${String(body.reason)}`;
      log(who, `exception.${e.status === 'approved' ? 'approve' : e.status === 'rejected' ? 'reject' : 'revoke'}`, e.findingId.split('|')[1]);
      return json(200, e);
    }
    return fail(404, 'No such exception');
  }

  // --- scans
  if (a === 'scans' && b) {
    const scanId = Number(b);
    for (const t of targets) {
      const s = t.scans.find((x) => x.meta.id === scanId);
      if (!s) continue;
      if (method === 'GET' && !c) return json(200, trimmed(s.report, t.target.id));
      if (method === 'GET' && c === 'findings' && d) {
        const f = s.report.findings.find((x) => x.id === decodeURIComponent(d));
        return f ? json(200, { ...f, firstSeenAt: t.firstSeen[f.id] }) : fail(404, 'No such finding');
      }
      if (method === 'GET' && c === 'diff') { const df = diffFor(t, scanId); return df ? json(200, df) : fail(404, 'No previous scan'); }
      if (method === 'GET' && c === 'json') return json(200, s.report);
      if (method === 'GET' && c === 'vex') return new Response(JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', statements: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return fail(404, 'No such scan');
  }

  return fail(404, `Mock has no route for ${method} ${path}`);
}

/**
 * Query-string knobs for screenshots and quick checks: `?mock=1&mockUser=admin&mockSetup=1&mockAuth=local&theme=light`.
 * They are copied into storage once, so the hash routes work afterwards without the query.
 */
function readKnobs() {
  try {
    const q = new URLSearchParams(location.search);
    if (!q.has('mock')) return;
    localStorage.setItem('nextfix.mock', q.get('mock') === '0' ? '0' : '1');
    if (q.has('mockSetup')) { if (q.get('mockSetup') === '1') localStorage.setItem('nextfix.mock.setup', '1'); else localStorage.removeItem('nextfix.mock.setup'); }
    if (q.has('mockAuth')) localStorage.setItem('nextfix.mock.authMode', q.get('mockAuth') ?? 'oidc');
    if (q.has('mockUser')) {
      const u = users.find((x) => x.username === q.get('mockUser'));
      if (u) sessionStorage.setItem('nextfix.mock.user', u.id); else sessionStorage.removeItem('nextfix.mock.user');
    }
    if (q.has('theme')) localStorage.setItem('nextfix.theme', q.get('theme') ?? 'dark');
    if (q.has('target')) localStorage.setItem('nextfix.target', q.get('target') ?? '1');
  } catch { /* storage blocked */ }
}

export function installMock() {
  readKnobs();
  let on = false;
  try { on = localStorage.getItem('nextfix.mock') === '1'; } catch { /* storage blocked */ }
  if (!on) return;
  const real = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const u = new URL(url, location.origin);
    if (!u.pathname.startsWith('/api/')) return real(input, init);
    const method = (init?.method ?? (typeof input !== 'string' && !(input instanceof URL) ? input.method : 'GET')).toUpperCase();
    let body: Record<string, unknown> = {};
    if (typeof init?.body === 'string') { try { body = JSON.parse(init.body); } catch { body = {}; } }
    await delay(120);
    if (init?.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    try {
      return await route(method, u.pathname, u.searchParams, body);
    } catch (e) {
      return fail(400, e instanceof Error ? e.message : String(e));
    }
  };
  console.info('NextFix mock API is on (localStorage nextfix.mock = 1).');
}
