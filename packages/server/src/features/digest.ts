import type { DatabaseSync } from 'node:sqlite';
import { connect as netConnect, type Socket } from 'node:net';
import { connect as tlsConnect, type ConnectionOptions as TlsOptions } from 'node:tls';
import { hostname } from 'node:os';
import { randomBytes } from 'node:crypto';
import type { Decision, Finding, ScanReport } from '../../../engine/src/types.ts';
import { compareVersions } from '../../../engine/src/vulns/ecosystems.ts';
import { toolVersion } from '../../../engine/src/version.ts';
import { diffReports } from '../diff.ts';
import { FeatureError, settingsFor, type Route, type SettingsAccess } from './core.ts';
import { activeExceptions, isInForce, type ExceptionRow } from './exceptions.ts';
import { DECISION_ORDER, listTargetMeta, servedReport, slaBreaches, slaSettings, verdict, type Posture, type TargetMeta } from './portfolio.ts';

/*
 * Weekly digest: the portfolio verdict in one subject line, then per application the verdict
 * sentence, what changed, the shortest path to clean, SLA breaches and exceptions, with a link
 * to the dashboard. Sent by email (SMTP, no library), Slack or Teams incoming webhooks.
 */

export const migrations: string[] = [
  // 7: digest sends (weekly and test), successes and failures alike.
  `
    CREATE TABLE IF NOT EXISTS digest_log (
      id INTEGER PRIMARY KEY,
      kind TEXT NOT NULL,
      channel TEXT NOT NULL,
      subject TEXT NOT NULL,
      recipients TEXT NOT NULL,
      ok INTEGER NOT NULL,
      error TEXT,
      sent_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS digest_log_sent ON digest_log(kind, ok, sent_at);
  `,
];

export const DIGEST_SETTING_KEY = 'digest';
export const PUBLIC_URL_KEY = 'publicUrl';
export const DEFAULT_PUBLIC_URL = 'http://localhost:8790';
/** Exceptions expiring within this many days are listed. */
export const EXPIRY_WINDOW_DAYS = 30;
/** Without a previous digest, promotions are counted over this window. */
const DEFAULT_LOOKBACK_DAYS = 7;
const WEBHOOK_TIMEOUT_MS = 20_000;
export const SMTP_TIMEOUT_MS = 30_000;
const DAY_MS = 86_400_000;

export type Channel = 'email' | 'slack' | 'teams';

export interface EmailSettings {
  to: string[];
  from: string;
  smtpHost: string;
  smtpPort: number;
  smtpUser?: string;
  smtpPassword?: string;
  /** STARTTLS after EHLO. */
  secure: boolean;
}

export interface DigestSettings {
  channel: Channel | null;
  email?: EmailSettings;
  slack?: { webhook: string };
  teams?: { webhook: string };
  /** 0 = Sunday … 6 = Saturday, local time. */
  weekday: number;
  /** 0–23, local time. */
  hour: number;
}

/** What the API returns: secrets replaced by booleans. */
export interface PublicDigestSettings {
  channel: Channel | null;
  email?: Omit<EmailSettings, 'smtpPassword'> & { hasPassword: boolean };
  slack?: { hasWebhook: boolean };
  teams?: { hasWebhook: boolean };
  weekday: number;
  hour: number;
}

export const DEFAULT_DIGEST_SETTINGS: DigestSettings = { channel: null, weekday: 1, hour: 8 };

// ---------------------------------------------------------------------------------------------
// Settings

export function getDigestSettings(settings: SettingsAccess): DigestSettings {
  const raw = settings.get(DIGEST_SETTING_KEY);
  if (!raw || typeof raw !== 'object') return { ...DEFAULT_DIGEST_SETTINGS };
  const s = raw as Partial<DigestSettings>;
  return {
    channel: s.channel === 'email' || s.channel === 'slack' || s.channel === 'teams' ? s.channel : null,
    email: s.email,
    slack: s.slack,
    teams: s.teams,
    weekday: Number.isInteger(s.weekday) && s.weekday! >= 0 && s.weekday! <= 6 ? s.weekday! : DEFAULT_DIGEST_SETTINGS.weekday,
    hour: Number.isInteger(s.hour) && s.hour! >= 0 && s.hour! <= 23 ? s.hour! : DEFAULT_DIGEST_SETTINGS.hour,
  };
}

export function publicDigestSettings(s: DigestSettings): PublicDigestSettings {
  const out: PublicDigestSettings = { channel: s.channel, weekday: s.weekday, hour: s.hour };
  if (s.email) {
    const { smtpPassword, ...rest } = s.email;
    out.email = { ...rest, hasPassword: !!smtpPassword };
  }
  if (s.slack) out.slack = { hasWebhook: !!s.slack.webhook };
  if (s.teams) out.teams = { hasWebhook: !!s.teams.webhook };
  return out;
}

export function publicUrl(settings: SettingsAccess): string {
  const v = settings.get(PUBLIC_URL_KEY);
  const s = typeof v === 'string' ? v.trim().replace(/\/+$/, '') : '';
  return s || DEFAULT_PUBLIC_URL;
}

const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;

function isLoopback(host: string): boolean {
  return host === 'localhost' || host === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(host);
}

function validateWebhook(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new FeatureError(400, `${label} webhook must be a URL`);
  let u: URL;
  try {
    u = new URL(value.trim());
  } catch {
    throw new FeatureError(400, `${label} webhook is not a valid URL`);
  }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLoopback(u.hostname))) throw new FeatureError(400, `${label} webhook must use https`);
  if (u.username || u.password) throw new FeatureError(400, `${label} webhook must not carry credentials`);
  return u.toString();
}

function addressList(value: unknown): string[] {
  const items = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[,;\s]+/) : [];
  const out = items.filter((x): x is string => typeof x === 'string').map((x) => x.trim()).filter(Boolean);
  for (const a of out) if (!EMAIL_RE.test(a)) throw new FeatureError(400, `"${a.slice(0, 60)}" is not an email address`);
  return [...new Set(out)];
}

/**
 * Merge a PUT body into the stored settings: unknown keys ignored, secrets kept unless a new value
 * is given. Secrets may come nested (`email.smtpPassword`, `slack.webhook`) or at the top level
 * (`smtpPassword`, `slackWebhook`, `teamsWebhook`), which is how the dashboard sends them.
 */
export function mergeDigestSettings(existing: DigestSettings, body: Record<string, unknown>): DigestSettings {
  const out: DigestSettings = { ...existing };
  const topSecret = (key: string) => (typeof body[key] === 'string' && body[key] ? (body[key] as string) : undefined);
  if ('channel' in body) {
    const c = body.channel;
    if (c !== null && c !== 'email' && c !== 'slack' && c !== 'teams') throw new FeatureError(400, 'channel must be email, slack, teams or null');
    out.channel = c;
  }
  if ('weekday' in body) {
    const n = Number(body.weekday);
    if (!Number.isInteger(n) || n < 0 || n > 6) throw new FeatureError(400, 'weekday must be 0 (Sunday) to 6 (Saturday)');
    out.weekday = n;
  }
  if ('hour' in body) {
    const n = Number(body.hour);
    if (!Number.isInteger(n) || n < 0 || n > 23) throw new FeatureError(400, 'hour must be 0 to 23');
    out.hour = n;
  }
  if (body.email && typeof body.email === 'object') {
    const e = body.email as Record<string, unknown>;
    const prev = existing.email;
    const to = 'to' in e ? addressList(e.to) : prev?.to ?? [];
    const from = 'from' in e ? (typeof e.from === 'string' ? e.from.trim() : '') : prev?.from ?? '';
    if (from && !EMAIL_RE.test(from)) throw new FeatureError(400, 'email.from must be an email address');
    const smtpHost = 'smtpHost' in e ? (typeof e.smtpHost === 'string' ? e.smtpHost.trim() : '') : prev?.smtpHost ?? '';
    const port = 'smtpPort' in e ? Number(e.smtpPort) : prev?.smtpPort ?? 587;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new FeatureError(400, 'email.smtpPort must be 1 to 65535');
    const smtpUser = 'smtpUser' in e ? (typeof e.smtpUser === 'string' ? e.smtpUser.trim() : '') || undefined : prev?.smtpUser;
    const smtpPassword = typeof e.smtpPassword === 'string' && e.smtpPassword ? e.smtpPassword : topSecret('smtpPassword') ?? prev?.smtpPassword;
    const secure = 'secure' in e ? e.secure === true || e.secure === 'true' : prev?.secure ?? true;
    out.email = { to, from, smtpHost, smtpPort: port, smtpUser, smtpPassword, secure };
  }
  const slackGiven = (body.slack && typeof body.slack === 'object' && typeof (body.slack as Record<string, unknown>).webhook === 'string' ? ((body.slack as Record<string, unknown>).webhook as string) : '') || topSecret('slackWebhook');
  if (slackGiven) out.slack = { webhook: validateWebhook(slackGiven, 'Slack') };
  const teamsGiven = (body.teams && typeof body.teams === 'object' && typeof (body.teams as Record<string, unknown>).webhook === 'string' ? ((body.teams as Record<string, unknown>).webhook as string) : '') || topSecret('teamsWebhook');
  if (teamsGiven) out.teams = { webhook: validateWebhook(teamsGiven, 'Teams') };
  if (out.channel === 'email' && !(out.email && out.email.to.length && out.email.from && out.email.smtpHost)) throw new FeatureError(400, 'The email channel needs email.to, email.from and email.smtpHost');
  if (out.channel === 'slack' && !out.slack?.webhook) throw new FeatureError(400, 'The slack channel needs slack.webhook');
  if (out.channel === 'teams' && !out.teams?.webhook) throw new FeatureError(400, 'The teams channel needs teams.webhook');
  return out;
}

// ---------------------------------------------------------------------------------------------
// Content

export interface DigestApp {
  id: number;
  name: string;
  owner: string | null;
  url: string;
  posture: Posture;
  /** The verdict sentence. */
  verdict: string;
  detail?: string;
  /** Every other sentence, in order: bridge, shortest path, SLA, exceptions. */
  lines: string[];
}

export interface Digest {
  subject: string;
  text: string;
  markdown: string;
  /** Slack Block Kit blocks. */
  blocks: unknown[];
  apps: DigestApp[];
  generatedAt: string;
}

const POSTURES: Posture[] = ['Exposed', 'Attention', 'Contained', 'Clean', 'Never scanned'];

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const MONTHS_LONG = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

/** `3 Oct`, independent of the host's ICU data. */
function shortDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getDate()} ${MONTHS[d.getMonth()]}`;
}

/** `3 October 2026`. */
function longDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getDate()} ${MONTHS_LONG[d.getMonth()]} ${d.getFullYear()}`;
}

/** Upgrades grouped by component, as the dashboard's upgrades() does, for the leverage sentence. */
function upgradeGroups(report: ScanReport): { inImage: boolean; actionable: number }[] {
  const groups = new Map<string, { inImage: boolean; actionable: number; target: string; eco: Finding['component']['ecosystem'] }>();
  for (const f of report.findings) {
    if (!f.advisory.fixedVersion) continue;
    const c = f.component;
    let g = groups.get(c.purl);
    if (!g) {
      g = { inImage: c.origin === 'image', actionable: 0, target: f.advisory.fixedVersion, eco: c.ecosystem };
      groups.set(c.purl, g);
    }
    try {
      if (compareVersions(c.ecosystem, f.advisory.fixedVersion, g.target) > 0) g.target = f.advisory.fixedVersion;
    } catch {
      /* unparsable version: the first fixed version stands */
    }
    if (f.decision === 'Act' || f.decision === 'Attend') g.actionable++;
  }
  return [...groups.values()];
}

/**
 * The shortest-path sentence, same rules as leverageSentence() in packages/web/src/analytics.ts
 * (kept in step by hand).
 */
export function leverageSentence(report: ScanReport): string {
  const actionable = report.findings.filter((f) => f.decision === 'Act' || f.decision === 'Attend');
  if (!actionable.length) return 'Nothing needs action; upgrades would close watched or set-aside findings only.';
  const covering = upgradeGroups(report).filter((u) => u.actionable > 0);
  const packages = covering.filter((u) => !u.inImage).length;
  const image = covering.filter((u) => u.inImage).length;
  const noFix = actionable.filter((f) => !f.advisory.fixedVersion).length;
  const parts: string[] = [];
  if (packages) parts.push(`${packages} package upgrade${packages === 1 ? '' : 's'}`);
  if (image) parts.push(`${image === 1 ? 'one' : image} base-image refresh${image === 1 ? '' : 'es'}`);
  const head = parts.length ? `${parts.join(' and ')} clear${parts.length === 1 && packages === 1 ? 's' : ''} ${noFix ? 'all but ' + noFix + ' of' : 'everything'} ${noFix ? 'the findings that need' : 'that needs'} action.` : '';
  const tail = noFix ? ` ${noFix} actionable finding${noFix === 1 ? ' has' : 's have'} no fix published yet; mitigate at the entry point.` : '';
  return (head + tail).trim() || `${noFix} actionable findings have no fix published yet.`;
}

/** The last successful weekly send, the reference point for "since the last digest". */
export function lastDigestSentAt(db: DatabaseSync): string | undefined {
  const r = db.prepare("SELECT sent_at FROM digest_log WHERE kind = 'weekly' AND ok = 1 ORDER BY sent_at DESC LIMIT 1").get() as { sent_at: string } | undefined;
  return r?.sent_at;
}

function previousReport(db: DatabaseSync, targetId: number, scanId: number): ScanReport | undefined {
  const cur = db.prepare('SELECT created_at FROM scans WHERE id = ?').get(scanId) as { created_at: string } | undefined;
  if (!cur) return undefined;
  const r = db.prepare('SELECT report FROM scans WHERE target_id = ? AND (created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT 1').get(targetId, cur.created_at, cur.created_at, scanId) as { report: string } | undefined;
  return r ? (JSON.parse(r.report) as ScanReport) : undefined;
}

/** Findings the nightly re-decide pass moved towards Act since `since` (the schedule module writes the rows). */
function promotedSince(db: DatabaseSync, targetId: number, since: string): Set<string> {
  const rows = db.prepare('SELECT finding_id, from_decision, to_decision FROM redecide_events WHERE target_id = ? AND at >= ?').all(targetId, since) as { finding_id: string; from_decision: string; to_decision: string }[];
  const out = new Set<string>();
  for (const r of rows) if (DECISION_ORDER.indexOf(r.to_decision as Decision) < DECISION_ORDER.indexOf(r.from_decision as Decision)) out.add(r.finding_id);
  return out;
}

/** "Since the last scan on 3 Oct: 2 new, 1 resolved, 1 promoted (1 by new exploit data)." */
function bridgeSentence(db: DatabaseSync, target: TargetMeta, scanId: number, report: ScanReport, since: string): string {
  const prev = previousReport(db, target.id, scanId);
  const diff = diffReports(report, prev);
  const promotedIds = new Set<string>();
  for (const c of diff.changed) if (DECISION_ORDER.indexOf(c.to) < DECISION_ORDER.indexOf(c.from)) promotedIds.add(c.finding.id);
  const byData = promotedSince(db, target.id, since);
  for (const id of byData) promotedIds.add(id);
  const parts: string[] = [];
  if (prev) {
    parts.push(`${diff.summary.added} new`);
    parts.push(`${diff.summary.resolved} resolved`);
  }
  if (promotedIds.size) parts.push(`${promotedIds.size} promoted${byData.size ? ` (${byData.size} by new exploit data)` : ''}`);
  if (!prev && !promotedIds.size) return 'First scan; nothing to compare with yet.';
  if (!prev) return `${plural(promotedIds.size, 'finding was promoted', 'findings were promoted')} by new exploit data since the last digest.`;
  if (!diff.summary.added && !diff.summary.resolved && !promotedIds.size) return `No change since the previous scan on ${shortDate(prev.generatedAt)}.`;
  return `Since the previous scan on ${shortDate(prev.generatedAt)}: ${parts.join(', ')}.`;
}

function slaSentence(db: DatabaseSync, targetId: number, report: ScanReport, nowMs: number): string | undefined {
  const breaches = slaBreaches(db, targetId, report, slaSettings(db), nowMs);
  if (!breaches.length) return undefined;
  const worst = breaches[0]!;
  return `${plural(breaches.length, 'finding is', 'findings are')} past the SLA; the oldest is ${plural(worst.overdueDays, 'day')} overdue (${worst.decision}, first seen ${plural(worst.ageDays, 'day')} ago).`;
}

function exceptionSentence(exceptions: ExceptionRow[], nowMs: number): string | undefined {
  const now = new Date(nowMs).toISOString();
  const pending = exceptions.filter((e) => e.status === 'pending');
  const expiring = exceptions.filter((e) => isInForce(e, now) && e.expiresAt && Date.parse(e.expiresAt) - nowMs <= EXPIRY_WINDOW_DAYS * DAY_MS);
  const parts: string[] = [];
  if (pending.length) parts.push(`${plural(pending.length, 'exception is', 'exceptions are')} waiting for approval`);
  if (expiring.length) parts.push(`${plural(expiring.length, 'exception expires', 'exceptions expire')} within ${EXPIRY_WINDOW_DAYS} days${expiring.length <= 3 ? ` (${expiring.map((e) => `${shortName(e.findingId)} on ${e.expiresAt!.slice(0, 10)}`).join('; ')})` : ''}`);
  return parts.length ? `${parts.join('; ')}.` : undefined;
}

/** `pkg:npm/lodash@4.17.15|GHSA-x` → `lodash@4.17.15 GHSA-x`. */
function shortName(findingId: string): string {
  const [purl, adv] = findingId.split('|');
  const name = (purl ?? '').replace(/^pkg:[^/]+\//, '');
  return adv ? `${name} ${adv}` : name;
}

export function digestApp(db: DatabaseSync, target: TargetMeta, base: string, since: string, nowMs: number): DigestApp {
  const url = `${base}/#/overview?target=${target.id}`;
  const served = servedReport(db, target.id, new Date(nowMs).toISOString());
  const exceptions = activeExceptions(db, target.id, new Date(nowMs).toISOString());
  if (!served) {
    const lines = [exceptionSentence(exceptions, nowMs)].filter((x): x is string => !!x);
    return { id: target.id, name: target.name, owner: target.owner, url, posture: 'Never scanned', verdict: 'Not scanned yet; add a schedule or run a scan.', lines };
  }
  const v = verdict(served.report);
  const lines = [bridgeSentence(db, target, served.scanId, served.report, since), leverageSentence(served.report), slaSentence(db, target.id, served.report, nowMs), exceptionSentence(exceptions, nowMs)].filter((x): x is string => !!x);
  return { id: target.id, name: target.name, owner: target.owner, url, posture: v.posture, verdict: v.headline, detail: v.detail, lines };
}

/** The subject line: the portfolio verdict, or for one application its verdict sentence. */
export function digestSubject(apps: DigestApp[]): string {
  if (!apps.length) return 'NextFix · no applications yet';
  if (apps.length === 1) return `NextFix · ${apps[0]!.name}: ${apps[0]!.verdict}`;
  const counts = POSTURES.map((p) => [p, apps.filter((a) => a.posture === p).length] as const).filter(([, n]) => n > 0);
  return `NextFix · ${plural(apps.length, 'application')} · ${counts.map(([p, n]) => `${n} ${p}`).join(', ')}`;
}

function renderText(d: { subject: string; apps: DigestApp[]; generatedAt: string }, base: string): string {
  const out: string[] = [d.subject, `Weekly digest, ${longDate(d.generatedAt)}`, ''];
  for (const a of d.apps) {
    out.push(`${a.name} — ${a.posture}${a.owner ? ` (owner: ${a.owner})` : ''}`);
    out.push(a.verdict);
    if (a.detail) out.push(a.detail);
    out.push(...a.lines);
    out.push(`Dashboard: ${a.url}`, '');
  }
  if (!d.apps.length) out.push('No applications have been added yet.', `Dashboard: ${base}`, '');
  out.push(`Sent by NextFix ${toolVersion()} · ${base}`);
  return out.join('\n');
}

function renderMarkdown(d: { subject: string; apps: DigestApp[]; generatedAt: string }, base: string): string {
  const out: string[] = [`# ${d.subject}`, '', `Weekly digest, ${longDate(d.generatedAt)}`, ''];
  for (const a of d.apps) {
    out.push(`## ${a.name} — ${a.posture}${a.owner ? ` · owner ${a.owner}` : ''}`, '', `**${a.verdict}**`);
    if (a.detail) out.push('', a.detail);
    out.push('');
    for (const l of a.lines) out.push(`- ${l}`);
    out.push('', `[Open the dashboard](${a.url})`, '');
  }
  if (!d.apps.length) out.push('No applications have been added yet.', '');
  out.push(`_Sent by NextFix ${toolVersion()} · ${base}_`);
  return out.join('\n');
}

/** Slack mrkdwn escapes &, < and >. */
function slackEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Block Kit: a header, then one section per application, divided. Section text stays under Slack's 3000-char limit. */
function renderBlocks(d: { subject: string; apps: DigestApp[]; generatedAt: string }, base: string): unknown[] {
  const blocks: unknown[] = [{ type: 'header', text: { type: 'plain_text', text: d.subject.slice(0, 150), emoji: false } }];
  for (const a of d.apps) {
    const body = [`*${slackEscape(a.name)} — ${a.posture}*${a.owner ? ` · owner ${slackEscape(a.owner)}` : ''}`, slackEscape(a.verdict), ...(a.detail ? [slackEscape(a.detail)] : []), ...a.lines.map((l) => `• ${slackEscape(l)}`), `<${a.url}|Open the dashboard>`].join('\n');
    blocks.push({ type: 'divider' }, { type: 'section', text: { type: 'mrkdwn', text: body.slice(0, 2990) } });
    if (blocks.length >= 48) break;
  }
  if (!d.apps.length) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `No applications have been added yet. <${base}|Open NextFix>` } });
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `Sent by NextFix ${toolVersion()} · <${base}|${slackEscape(base)}>` }] });
  return blocks;
}

/** Build the digest from the database: every target, exceptions applied, changes since the last send. */
export function buildDigest(db: DatabaseSync, settings: SettingsAccess, nowMs = Date.now()): Digest {
  const base = publicUrl(settings);
  const since = lastDigestSentAt(db) ?? new Date(nowMs - DEFAULT_LOOKBACK_DAYS * DAY_MS).toISOString();
  const apps = listTargetMeta(db).map((t) => digestApp(db, t, base, since, nowMs));
  const generatedAt = new Date(nowMs).toISOString();
  const subject = digestSubject(apps);
  const d = { subject, apps, generatedAt };
  return { subject, apps, generatedAt, text: renderText(d, base), markdown: renderMarkdown(d, base), blocks: renderBlocks(d, base) };
}

// ---------------------------------------------------------------------------------------------
// Email over SMTP

export interface MailMessage {
  from: string;
  to: string[];
  subject: string;
  text: string;
}

export interface SmtpOptions {
  host: string;
  port: number;
  user?: string;
  password?: string;
  /** Upgrade with STARTTLS after the first EHLO; refused when the server does not offer it. */
  secure: boolean;
  timeoutMs?: number;
  /** Name sent with EHLO (defaults to the machine's hostname). */
  ehloName?: string;
  /** Extra TLS options (tests pass a CA or rejectUnauthorized). */
  tls?: TlsOptions;
}

export class SmtpError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

/** Minimal line-oriented SMTP client; keeps the conversation in `transcript` for tests and logs. */
class SmtpClient {
  private socket!: Socket;
  private buffer = '';
  private waiting: { resolve: (r: { code: number; lines: string[] }) => void; reject: (e: Error) => void } | null = null;
  private closed: Error | null = null;
  readonly transcript: string[] = [];
  readonly timeoutMs: number;

  constructor(timeoutMs: number) {
    this.timeoutMs = timeoutMs;
  }

  attach(socket: Socket) {
    this.socket = socket;
    socket.setEncoding('utf8');
    socket.setTimeout(this.timeoutMs, () => this.fail(new SmtpError(0, 'SMTP connection timed out')));
    socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.pump();
    });
    socket.on('error', (err) => this.fail(err));
    socket.on('close', () => this.fail(new SmtpError(0, 'SMTP connection closed')));
  }

  detach() {
    this.socket.removeAllListeners('data');
    this.socket.removeAllListeners('error');
    this.socket.removeAllListeners('close');
    this.socket.setTimeout(0);
  }

  private fail(err: Error) {
    if (!this.closed) this.closed = err;
    const w = this.waiting;
    this.waiting = null;
    w?.reject(err);
  }

  /** A reply is complete when a line reads `NNN text` (a space, not a dash, after the code). */
  private pump() {
    if (!this.waiting) return;
    const lines = this.buffer.split('\r\n');
    for (let i = 0; i < lines.length - 1; i++) {
      const line = lines[i]!;
      if (/^\d{3}(?: |$)/.test(line)) {
        const reply = lines.slice(0, i + 1);
        this.buffer = lines.slice(i + 1).join('\r\n');
        for (const l of reply) this.transcript.push(`S: ${l}`);
        const w = this.waiting;
        this.waiting = null;
        w.resolve({ code: Number(line.slice(0, 3)), lines: reply.map((l) => l.slice(4)) });
        return;
      }
      if (!/^\d{3}-/.test(line)) {
        this.fail(new SmtpError(0, `Malformed SMTP reply: ${line.slice(0, 80)}`));
        return;
      }
    }
  }

  read(): Promise<{ code: number; lines: string[] }> {
    if (this.closed) return Promise.reject(this.closed);
    return new Promise((resolve, reject) => {
      this.waiting = { resolve, reject };
      this.pump();
    });
  }

  async command(line: string, redact = false): Promise<{ code: number; lines: string[] }> {
    if (this.closed) throw this.closed;
    this.transcript.push(`C: ${redact ? '[credentials]' : line}`);
    this.socket.write(line + '\r\n');
    return this.read();
  }

  /** Send and insist on one of the given reply codes. */
  async expect(line: string, codes: number[], redact = false): Promise<{ code: number; lines: string[] }> {
    const r = await this.command(line, redact);
    if (!codes.includes(r.code)) throw new SmtpError(r.code, `SMTP ${line.split(' ')[0]} failed: ${r.code} ${r.lines.join(' ')}`.trim());
    return r;
  }

  write(data: string) {
    this.socket.write(data);
  }

  get current(): Socket {
    return this.socket;
  }

  end() {
    this.closed ??= new SmtpError(0, 'SMTP connection closed');
    this.socket.end();
  }
}

/** RFC 2047 encoded-word for a header that carries non-ASCII text. */
export function encodeHeader(value: string): string {
  // eslint-disable-next-line no-control-regex
  if (/^[\x20-\x7e]*$/.test(value)) return value;
  return `=?UTF-8?B?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

/** RFC 5322 date, numeric zone. */
export function rfc5322Date(d = new Date()): string {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const p = (n: number) => String(n).padStart(2, '0');
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const zone = `${sign}${p(Math.floor(Math.abs(off) / 60))}${p(Math.abs(off) % 60)}`;
  return `${days[d.getDay()]}, ${p(d.getDate())} ${months[d.getMonth()]} ${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} ${zone}`;
}

/** The RFC 5322 message: headers, blank line, 8-bit UTF-8 text with CRLF line ends and dot-stuffing. */
export function buildMessage(msg: MailMessage, now = new Date()): string {
  const headers = [
    `From: ${msg.from}`,
    `To: ${msg.to.join(', ')}`,
    `Subject: ${encodeHeader(msg.subject)}`,
    `Date: ${rfc5322Date(now)}`,
    `Message-ID: <${randomBytes(12).toString('hex')}@${msg.from.split('@')[1] ?? hostname()}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    `X-Mailer: NextFix/${toolVersion()}`,
  ];
  const body = msg.text
    .replace(/\r?\n/g, '\r\n')
    .split('\r\n')
    .map((l) => (l.startsWith('.') ? `.${l}` : l))
    .join('\r\n');
  return `${headers.join('\r\n')}\r\n\r\n${body}`;
}

/**
 * One message over SMTP: EHLO, STARTTLS when `secure`, AUTH PLAIN then LOGIN when credentials are
 * given, MAIL FROM / RCPT TO / DATA, QUIT. Returns the wire conversation (credentials redacted).
 */
export async function sendMail(opts: SmtpOptions, msg: MailMessage): Promise<{ transcript: string[] }> {
  if (!msg.to.length) throw new SmtpError(0, 'No recipients');
  const client = new SmtpClient(opts.timeoutMs ?? SMTP_TIMEOUT_MS);
  const ehloName = opts.ehloName ?? hostname() ?? 'localhost';
  const socket = await new Promise<Socket>((resolve, reject) => {
    const s = netConnect({ host: opts.host, port: opts.port });
    s.once('connect', () => resolve(s));
    s.once('error', reject);
  });
  client.attach(socket);
  try {
    const greeting = await client.read();
    if (greeting.code !== 220) throw new SmtpError(greeting.code, `SMTP server refused the connection: ${greeting.code} ${greeting.lines.join(' ')}`);
    let ehlo = await client.expect(`EHLO ${ehloName}`, [250]);
    let extensions = ehlo.lines.slice(1).map((l) => l.toUpperCase());
    if (opts.secure) {
      if (!extensions.some((x) => x.startsWith('STARTTLS'))) throw new SmtpError(0, 'The server does not offer STARTTLS; turn "secure" off only if the connection is trusted');
      await client.expect('STARTTLS', [220]);
      client.detach();
      const tls = await new Promise<Socket>((resolve, reject) => {
        const t = tlsConnect({ socket: client.current, servername: opts.host, ...opts.tls }, () => resolve(t));
        t.once('error', reject);
      });
      client.attach(tls);
      ehlo = await client.expect(`EHLO ${ehloName}`, [250]);
      extensions = ehlo.lines.slice(1).map((l) => l.toUpperCase());
    }
    if (opts.user) {
      const auth = extensions.find((x) => x.startsWith('AUTH ')) ?? '';
      const mechanisms = auth.slice(5).split(/\s+/);
      const password = opts.password ?? '';
      let done = false;
      if (!mechanisms.length || mechanisms.includes('PLAIN')) {
        const r = await client.command(`AUTH PLAIN ${Buffer.from(`\0${opts.user}\0${password}`, 'utf8').toString('base64')}`, true);
        if (r.code === 235) done = true;
        else if (![504, 535, 500, 502, 538].includes(r.code)) throw new SmtpError(r.code, `SMTP AUTH failed: ${r.code} ${r.lines.join(' ')}`);
      }
      if (!done) {
        const r1 = await client.expect('AUTH LOGIN', [334]);
        void r1;
        const r2 = await client.command(Buffer.from(opts.user, 'utf8').toString('base64'), true);
        if (r2.code !== 334) throw new SmtpError(r2.code, `SMTP AUTH LOGIN failed: ${r2.code} ${r2.lines.join(' ')}`);
        const r3 = await client.command(Buffer.from(password, 'utf8').toString('base64'), true);
        if (r3.code !== 235) throw new SmtpError(r3.code, `SMTP authentication failed: ${r3.code} ${r3.lines.join(' ')}`);
      }
    }
    const eightBit = extensions.includes('8BITMIME');
    await client.expect(`MAIL FROM:<${msg.from}>${eightBit ? ' BODY=8BITMIME' : ''}`, [250]);
    for (const rcpt of msg.to) await client.expect(`RCPT TO:<${rcpt}>`, [250, 251]);
    await client.expect('DATA', [354]);
    client.transcript.push('C: [message]');
    client.write(buildMessage(msg) + '\r\n.\r\n');
    const sent = await client.read();
    if (sent.code !== 250) throw new SmtpError(sent.code, `SMTP server did not accept the message: ${sent.code} ${sent.lines.join(' ')}`);
    try {
      await client.command('QUIT');
    } catch {
      /* some servers close before answering QUIT */
    }
    return { transcript: client.transcript };
  } finally {
    client.end();
  }
}

// ---------------------------------------------------------------------------------------------
// Webhooks

async function postJson(url: string, payload: unknown, label: string): Promise<void> {
  let res: Response;
  try {
    res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': `NextFix/${toolVersion()}` }, body: JSON.stringify(payload), signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS), redirect: 'manual' });
  } catch (err) {
    throw new FeatureError(502, `${label} webhook unreachable: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (res.status < 200 || res.status > 299) {
    const text = (await res.text().catch(() => '')).slice(0, 200);
    throw new FeatureError(502, `${label} webhook answered ${res.status}${text ? `: ${text}` : ''}`);
  }
}

/** Slack incoming webhook: `text` is the notification fallback, `blocks` the rendering. */
export async function sendSlack(webhook: string, digest: Pick<Digest, 'subject' | 'blocks'>): Promise<void> {
  await postJson(webhook, { text: digest.subject, blocks: digest.blocks }, 'Slack');
}

/** The Adaptive Card 1.4 body for Teams: a title, then a container per application. */
export function teamsCard(digest: Pick<Digest, 'subject' | 'apps' | 'generatedAt'>, base = DEFAULT_PUBLIC_URL): Record<string, unknown> {
  const body: unknown[] = [{ type: 'TextBlock', size: 'Large', weight: 'Bolder', wrap: true, text: digest.subject }];
  for (const a of digest.apps) {
    body.push({
      type: 'Container',
      separator: true,
      items: [
        { type: 'TextBlock', weight: 'Bolder', wrap: true, text: `${a.name} — ${a.posture}${a.owner ? ` · owner ${a.owner}` : ''}` },
        { type: 'TextBlock', wrap: true, text: a.verdict },
        ...(a.detail ? [{ type: 'TextBlock', wrap: true, isSubtle: true, text: a.detail }] : []),
        ...a.lines.map((l) => ({ type: 'TextBlock', wrap: true, text: `- ${l}` })),
        { type: 'TextBlock', wrap: true, text: `[Open the dashboard](${a.url})` },
      ],
    });
  }
  if (!digest.apps.length) body.push({ type: 'TextBlock', wrap: true, text: `No applications have been added yet. [Open NextFix](${base})` });
  body.push({ type: 'TextBlock', size: 'Small', isSubtle: true, wrap: true, text: `Sent by NextFix ${toolVersion()} · ${base}` });
  return { $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4', msteams: { width: 'Full' }, body };
}

/** Teams incoming webhook (Workflows or the older connector): an Adaptive Card inside a message attachment. */
export async function sendTeams(webhook: string, digest: Pick<Digest, 'subject' | 'apps' | 'generatedAt'>, base = DEFAULT_PUBLIC_URL): Promise<void> {
  const payload = { type: 'message', summary: digest.subject, attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', contentUrl: null, content: teamsCard(digest, base) }] };
  await postJson(webhook, payload, 'Teams');
}

// ---------------------------------------------------------------------------------------------
// Sending and the weekly job

export interface SendOptions {
  kind: 'weekly' | 'test';
  nowMs?: number;
  /** Overrides for the SMTP path (tests pass a port and ehloName). */
  smtp?: Partial<SmtpOptions>;
}

function recipientsOf(s: DigestSettings): string {
  switch (s.channel) {
    case 'email':
      return (s.email?.to ?? []).join(', ');
    case 'slack':
      return 'slack webhook';
    case 'teams':
      return 'teams webhook';
    default:
      return '';
  }
}

function logSend(db: DatabaseSync, kind: string, channel: string, subject: string, recipients: string, ok: boolean, error: string | null, at: string): void {
  db.prepare('INSERT INTO digest_log (kind, channel, subject, recipients, ok, error, sent_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(kind, channel, subject, recipients, ok ? 1 : 0, error, at);
}

/** Send a built digest over the configured channel and record the outcome; throws after recording a failure. */
export async function sendDigest(db: DatabaseSync, settings: SettingsAccess, digest: Digest, opts: SendOptions): Promise<void> {
  const s = getDigestSettings(settings);
  if (!s.channel) throw new FeatureError(400, 'No digest channel is configured (Settings → Digest)');
  const at = new Date(opts.nowMs ?? Date.now()).toISOString();
  const base = publicUrl(settings);
  try {
    switch (s.channel) {
      case 'email': {
        const e = s.email;
        if (!e || !e.to.length || !e.from || !e.smtpHost) throw new FeatureError(400, 'The email channel is not fully configured');
        try {
          await sendMail({ host: e.smtpHost, port: e.smtpPort, user: e.smtpUser, password: e.smtpPassword, secure: e.secure, ...opts.smtp }, { from: e.from, to: e.to, subject: digest.subject, text: digest.text });
        } catch (err) {
          if (err instanceof FeatureError) throw err;
          throw new FeatureError(502, err instanceof Error ? err.message : String(err));
        }
        break;
      }
      case 'slack':
        if (!s.slack?.webhook) throw new FeatureError(400, 'The Slack webhook is not configured');
        await sendSlack(s.slack.webhook, digest);
        break;
      case 'teams':
        if (!s.teams?.webhook) throw new FeatureError(400, 'The Teams webhook is not configured');
        await sendTeams(s.teams.webhook, digest, base);
        break;
    }
    logSend(db, opts.kind, s.channel, digest.subject, recipientsOf(s), true, null, at);
  } catch (err) {
    logSend(db, opts.kind, s.channel, digest.subject, recipientsOf(s), false, err instanceof Error ? err.message : String(err), at);
    throw err;
  }
}

/** The most recent local instant at the configured weekday and hour that is not after `nowMs`. */
export function lastScheduledInstant(s: Pick<DigestSettings, 'weekday' | 'hour'>, nowMs: number): number {
  const d = new Date(nowMs);
  d.setHours(s.hour, 0, 0, 0);
  const back = (d.getDay() - s.weekday + 7) % 7;
  d.setDate(d.getDate() - back);
  if (d.getTime() > nowMs) d.setDate(d.getDate() - 7);
  return d.getTime();
}

/** Due when a channel is set, the slot has passed and nothing has been sent (or tried) since it. */
export function isDigestDue(s: DigestSettings, lastAttemptAt: string | undefined, nowMs: number): boolean {
  if (!s.channel) return false;
  const scheduled = lastScheduledInstant(s, nowMs);
  const last = lastAttemptAt ? Date.parse(lastAttemptAt) : Number.NEGATIVE_INFINITY;
  return last < scheduled;
}

function lastWeeklyAttemptAt(db: DatabaseSync): string | undefined {
  const r = db.prepare("SELECT sent_at FROM digest_log WHERE kind = 'weekly' ORDER BY sent_at DESC LIMIT 1").get() as { sent_at: string } | undefined;
  return r?.sent_at;
}

/** The scheduler's weekly job. A failed attempt is logged and not retried until the next slot. */
export async function sendDigestIfDue(db: DatabaseSync, nowMs: number, log: (msg: string) => void = () => {}, settings?: SettingsAccess): Promise<boolean> {
  const access = settings ?? settingsFor(db);
  const s = getDigestSettings(access);
  if (!isDigestDue(s, lastWeeklyAttemptAt(db), nowMs)) return false;
  const digest = buildDigest(db, access, nowMs);
  try {
    await sendDigest(db, access, digest, { kind: 'weekly', nowMs });
    log(`digest: sent over ${s.channel}: ${digest.subject}`);
    return true;
  } catch (err) {
    log(`digest: send over ${s.channel} failed: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }
}

/** A short message that proves the channel works. */
export function testDigest(settings: SettingsAccess, nowMs = Date.now()): Digest {
  const base = publicUrl(settings);
  const subject = 'NextFix · test message';
  const generatedAt = new Date(nowMs).toISOString();
  const text = `This is a test message from NextFix ${toolVersion()}. The weekly digest will arrive this way.\n\nDashboard: ${base}`;
  return {
    subject,
    apps: [],
    generatedAt,
    text,
    markdown: `# ${subject}\n\n${text}`,
    blocks: [{ type: 'header', text: { type: 'plain_text', text: subject, emoji: false } }, { type: 'section', text: { type: 'mrkdwn', text: `This is a test message from NextFix ${toolVersion()}. The weekly digest will arrive this way. <${base}|Open the dashboard>` } }],
  };
}

export const routes: Route[] = [
  {
    method: 'GET',
    pattern: '/api/settings/digest',
    role: 'admin',
    handler({ settings }) {
      return { body: publicDigestSettings(getDigestSettings(settings)) };
    },
  },
  {
    method: 'PUT',
    pattern: '/api/settings/digest',
    role: 'admin',
    handler({ settings, body, audit }) {
      const merged = mergeDigestSettings(getDigestSettings(settings), body);
      settings.set(DIGEST_SETTING_KEY, merged);
      audit('digest.settings', 'settings:digest', publicDigestSettings(merged));
      return { body: publicDigestSettings(merged) };
    },
  },
  {
    method: 'POST',
    pattern: '/api/digest/preview',
    role: 'admin',
    handler({ db, settings }) {
      return { body: buildDigest(db, settings) };
    },
  },
  {
    method: 'POST',
    pattern: '/api/digest/test',
    role: 'admin',
    async handler({ db, settings, audit }) {
      const s = getDigestSettings(settings);
      if (!s.channel) throw new FeatureError(400, 'Choose a channel and save the settings first');
      const digest = testDigest(settings);
      await sendDigest(db, settings, digest, { kind: 'test' });
      audit('digest.test', `digest:${s.channel}`, { recipients: recipientsOf(s) });
      return { body: { ok: true, message: `Test message sent over ${s.channel}` } };
    },
  },
];
