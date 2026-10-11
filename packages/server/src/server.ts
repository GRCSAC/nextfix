import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import { scan, type ScanOptions } from '../../engine/src/scan.ts';
import { toOpenVex } from '../../engine/src/report/vex.ts';
import { toolVersion } from '../../engine/src/version.ts';
import { assetPath, hasAsset, isSea, readAsset } from '../../engine/src/assets.ts';
import { defaultCachePath } from '../../engine/src/vulns/cache.ts';
import { hasPythonProject } from '../../engine/src/inventory/python.ts';
import { hasNodeProject } from '../../engine/src/inventory/node.ts';
import { hasGoProject } from '../../engine/src/inventory/go.ts';
import { detectSbomFiles } from '../../engine/src/inventory/container.ts';
import { asList, loadConfig } from '../../engine/src/config.ts';
import { ticketMarkdown, ticketTitle } from '../../engine/src/report/ticket.ts';
import type { Advisory, Finding, ScanReport } from '../../engine/src/types.ts';
import { githubCreateIssue, githubTest, jiraCreateIssue, jiraTest, mergeIntegrationConfig, IntegrationError, type GitHubConfig, type JiraConfig } from './integrations.ts';
import { SETTING_KEYS, Store, type SettingKey } from './store.ts';
import { diffReports, type ChangedFinding } from './diff.ts';
import { HttpError, type AuthMode, type AuthUser, type HttpMethod, type Route, type RouteContext } from './auth/context.ts';
import { BUILTIN_POLICY, authorize, findPolicy, isRole, matchPattern, requireRole, type RoutePolicy } from './auth/roles.ts';
import { checkPassword, displayNameOf, hashPassword, lockedUntil, lockoutError, normalizeUsername, verifyPassword } from './auth/local.ts';
import { SESSION_COOKIE, SESSION_IDLE_MS, clearCookie, clientIp, createSession, destroySession, isHttps, isLoopbackAddress, resolveSession } from './auth/sessions.ts';
import { generateToken, parseScopes, resolveToken } from './auth/tokens.ts';
import { audit } from './auth/audit.ts';
import { OIDC_COOKIE, finishAuth, normalizeOidcSettings, publicOidcSettings, redirectUriFor, startAuth, type OidcSettings } from './auth/oidc.ts';
import { featureDb } from './features/all.ts';
import { applyExceptions, exceptionsInForce, toVexException } from './features/exceptions.ts';
import { redecideReport } from './features/schedule.ts';

export { HttpError } from './auth/context.ts';
export type { AuthUser, Route, RouteContext, Role, TokenScope } from './auth/context.ts';
export { requireRole } from './auth/roles.ts';
export { audit } from './auth/audit.ts';

/** The engine's scan entry point. `signal` cancels a scan; the engine stops at its next await when it honours it. */
export type Scanner = (dir: string, opts: ScanOptions & { signal?: AbortSignal }) => Promise<ScanReport>;

export interface ServerOptions {
  store: Store;
  staticDir?: string;
  log?: (msg: string) => void;
  /** Interface the server listens on; added to the Host allowlist unless it is 0.0.0.0 / ::. */
  host?: string;
  /** Extra names browsers may use to reach this server (the --allow-host option). */
  allowHosts?: string[];
  /** A scan that runs longer than this is abandoned (default 20 minutes). */
  scanTimeoutMs?: number;
  /** Pause between two ticket creations in one request, so trackers are not flooded. */
  ticketSpacingMs?: number;
  /** Replaces the engine's scan function (tests). */
  scanner?: Scanner;
  /** Advisory cache the re-decide step reads EPSS and KEV from (default: the engine's cache). */
  cachePath?: string;
  /** Skip authentication entirely and answer loopback connections only (single-user use). */
  allowOpen?: boolean;
  /** Mark cookies Secure even when the request itself arrived over plain http (TLS terminated in front). */
  secureCookies?: boolean;
  /** Routes for this server instance, in addition to those passed to registerRoutes(). */
  routes?: Route[];
}

/** What the server knows about the scan it is running. */
export interface ScanProgress {
  targetId: number;
  /** Inventory, Code, Advisories, Symbols or Image, taken from the engine's log lines. */
  stage: string;
  lines: string[];
  startedAt: string;
}

/** Request bodies larger than this are refused. */
export const MAX_BODY_BYTES = 1024 * 1024;
export const DEFAULT_SCAN_TIMEOUT_MS = 20 * 60_000;
/** Responses shorter than this are sent as is; gzip only pays off above it. */
const GZIP_MIN_BYTES = 1024;
/** Progress keeps this many of the newest engine log lines. */
const PROGRESS_LINES = 200;
/** References per advisory in the list payload; the full finding endpoint has them all. */
const REFERENCES_IN_LIST = 6;
const HEARTBEAT_MS = 20_000;
const MUTATING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);
const METHODS = new Set<string>(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const STAGES = new Set(['Inventory', 'Code', 'Advisories', 'Symbols', 'Image']);
const AUDIT_PAGE_DEFAULT = 100;
const AUDIT_PAGE_MAX = 1000;

/** The caller while the server runs without accounts: first-run setup, or --allow-open. */
const OPEN_USER: AuthUser = { id: 0, username: 'local', displayName: 'Local user', role: 'admin', source: 'open' };

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.map': 'application/json',
};
const COMPRESSIBLE = new Set(['.html', '.js', '.css', '.svg', '.json', '.map']);

/** Routes added by feature modules; every server created afterwards (or already running) serves them. */
const featureRoutes: Route[] = [];

/**
 * Add API routes without touching the server's own dispatch. Paths are relative to /api
 * (`/exceptions/:id`); built-in routes win on a clash. Each route states the role it needs
 * and, if API tokens may call it, the scope. See `Route` for the handler contract.
 */
export function registerRoutes(routes: Route | Route[]): void {
  for (const r of Array.isArray(routes) ? routes : [routes]) {
    if (!METHODS.has(r.method)) throw new Error(`registerRoutes: unsupported method ${String(r.method)}`);
    if (!r.path.startsWith('/')) throw new Error(`registerRoutes: path must start with /: ${r.path}`);
    featureRoutes.push(r);
  }
}

/** User-supplied text echoed in an error message, kept short. */
function clip(text: unknown, max = 200): string {
  const s = typeof text === 'string' ? text : String(text ?? '');
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/** The hostname part of a Host header or URL host, lowercase, port removed; IPv6 keeps its brackets. */
export function hostnameOf(hostHeader: string): string {
  const h = hostHeader.trim().toLowerCase();
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    return end === -1 ? h : h.slice(0, end + 1);
  }
  const colon = h.lastIndexOf(':');
  return colon === -1 ? h : h.slice(0, colon);
}

/** `2026-10-10-1432` in the server's local time, for export file names. */
export function localStamp(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

function exportName(report: ScanReport, suffix: string): string {
  return `${(report.target.name ?? 'app').replace(/[^\w.-]+/g, '_')}-${localStamp(report.generatedAt)}${suffix}`;
}

function acceptsGzip(req: IncomingMessage): boolean {
  const h = String(req.headers['accept-encoding'] ?? '');
  return /(^|,)\s*gzip\s*(;q=(?!0(\.0+)?\s*(,|$))[^,]*)?\s*(,|$)/i.test(h);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** A folder with an image or SBOM to inventory is a valid target even without a lockfile. */
function hasImageSources(dir: string): boolean {
  if (detectSbomFiles(dir).length) return true;
  try {
    const cfg = loadConfig(dir);
    return asList(cfg.image).length > 0 || asList(cfg.sbom).length > 0;
  } catch {
    return false;
  }
}

/** The list payload drops the advisory's long text and caps its references. */
function trimAdvisory(a: Advisory): Omit<Advisory, 'details'> & { referenceCount: number } {
  const { details: _details, ...rest } = a;
  return { ...rest, references: (a.references ?? []).slice(0, REFERENCES_IN_LIST), referenceCount: (a.references ?? []).length };
}

function trimReport(report: ScanReport, firstSeen: Record<string, string>) {
  return {
    ...report,
    findings: report.findings.map((f) => ({ ...f, advisory: trimAdvisory(f.advisory), firstSeenAt: firstSeen[f.id] })),
  };
}


/** The user object the session and login routes return. */
function publicUser(u: AuthUser): { id: number; username: string; displayName: string; role: AuthUser['role'] } {
  return { id: u.id, username: u.username, displayName: u.displayName, role: u.role };
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** The built dashboard on disk; undefined inside the single executable, where it is read from the embedded assets. */
export function defaultStaticDir(): string | undefined {
  return isSea() ? undefined : assetPath('web');
}

export function createNextFixServer(opts: ServerOptions) {
  const staticDir = opts.staticDir ?? defaultStaticDir();
  const log = opts.log ?? (() => {});
  const scanTimeoutMs = opts.scanTimeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS;
  const ticketSpacingMs = opts.ticketSpacingMs ?? 1000;
  const scanner: Scanner = opts.scanner ?? scan;
  const cachePath = opts.cachePath ?? defaultCachePath();
  const allowOpen = opts.allowOpen === true;
  const secureCookies = opts.secureCookies === true;
  const instanceRoutes = opts.routes ?? [];

  const allowedHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
  const listenHost = (opts.host ?? '').trim().toLowerCase();
  if (listenHost && listenHost !== '0.0.0.0' && listenHost !== '::') allowedHosts.add(listenHost.includes(':') && !listenHost.startsWith('[') ? `[${listenHost}]` : listenHost);
  for (const h of opts.allowHosts ?? []) if (h.trim()) allowedHosts.add(hostnameOf(h));

  /** The scan this process is running right now, if any. */
  let progress: (ScanProgress & { controller: AbortController }) | null = null;

  async function readJson<T>(req: IncomingMessage): Promise<T> {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new HttpError(413, `Request body is larger than ${MAX_BODY_BYTES} bytes`);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > MAX_BODY_BYTES) throw new HttpError(413, `Request body is larger than ${MAX_BODY_BYTES} bytes`);
      chunks.push(c as Buffer);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    if (!text) return {} as T;
    try {
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
      return parsed as T;
    } catch {
      throw new HttpError(400, 'Body must be a JSON object');
    }
  }

  /** Write a response: gzip when the client accepts it and the body is worth it; HEAD gets headers only. */
  function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}) {
    const req = res.req;
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    let payload: Buffer | string = text;
    const out: Record<string, string | string[]> = { 'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers };
    if (status !== 204 && status !== 302 && Buffer.byteLength(text) >= GZIP_MIN_BYTES && acceptsGzip(req)) {
      payload = gzipSync(text);
      out['content-encoding'] = 'gzip';
      out.vary = 'accept-encoding';
    }
    if (status !== 204) out['content-length'] = String(Buffer.byteLength(payload));
    res.writeHead(status, out);
    if (req.method === 'HEAD' || status === 204) res.end();
    else res.end(payload);
  }

  function serverPort(): number {
    const addr = server.address();
    return addr && typeof addr === 'object' ? (addr as AddressInfo).port : 0;
  }

  // ---- who is calling ----

  /** True while the server runs without accounts: nobody has set up yet, or --allow-open. */
  function openMode(): boolean {
    return allowOpen || opts.store.countUsers() === 0;
  }

  function oidcSettings(): OidcSettings {
    const s = opts.store.getJsonSetting<OidcSettings>('oidc');
    return s && Array.isArray(s.providers) ? s : { providers: [] };
  }

  function authModeOf(): AuthMode {
    if (openMode()) return 'none';
    return oidcSettings().providers.length ? 'oidc' : 'local';
  }

  function cookieSecure(req: IncomingMessage): boolean {
    return secureCookies || isHttps(req);
  }

  /** The origin browsers use for this server, for the OIDC redirect URI. The Host header passed checkHost. */
  function requestOrigin(req: IncomingMessage): string {
    const host = req.headers.host?.trim() || `127.0.0.1:${serverPort()}`;
    return `${isHttps(req) ? 'https' : 'http'}://${host}`;
  }

  /** The session or token behind a request. A bad bearer token is a 401 on its own; no credentials is simply null. */
  function authenticate(req: IncomingMessage): { user: AuthUser | null; sessionHash?: string } {
    if (openMode()) return { user: OPEN_USER };
    const token = resolveToken(opts.store, req);
    if (token) return { user: token };
    const session = resolveSession(opts.store, req);
    return session ? { user: session.user, sessionHash: session.hash } : { user: null };
  }

  function matchFeature(method: HttpMethod, segments: string[]): { route: Route; params: Record<string, string> } | undefined {
    for (const route of [...instanceRoutes, ...featureRoutes]) {
      if (route.method !== method) continue;
      const params = matchPattern(route.path, segments);
      if (params) return { route, params };
    }
    return undefined;
  }

  function makeContext(req: IncomingMessage, res: ServerResponse, method: HttpMethod, segments: string[], params: Record<string, string>, query: URLSearchParams, user: AuthUser | null): RouteContext {
    const ctx: RouteContext = {
      req,
      res,
      method,
      path: `/${segments.join('/')}`,
      params,
      query,
      user,
      ip: clientIp(req),
      store: opts.store,
      log,
      readJson: <T>() => readJson<T>(req),
      send: (status, body, headers) => send(res, status, body, headers),
      audit: (action, target, detail) => {
        audit(ctx, action, target, detail);
      },
      requireRole: (role) => requireRole(ctx, role),
    };
    return ctx;
  }

  /** Run `fn` while holding the database-wide scan lock, so only one scan runs at a time across every server on this database. */
  async function withScanLock<T>(fn: () => Promise<T>): Promise<T> {
    if (!opts.store.beginScan(listenHost || 'localhost', serverPort())) throw new HttpError(409, 'A scan is already running; try again when it finishes');
    try {
      return await fn();
    } finally {
      opts.store.endScan();
    }
  }

  /** The scan itself; the caller holds the scan lock. */
  async function scanTarget(ctx: RouteContext, targetId: number) {
    const target = opts.store.getTarget(targetId);
    if (!target) throw new HttpError(404, 'Target not found');
    log(`scan: ${target.dir}`);
    ctx.audit('scan.start', `target:${targetId}`, { dir: target.dir });
    const controller = new AbortController();
    const record: ScanProgress & { controller: AbortController } = { targetId, stage: 'Starting', lines: [], startedAt: new Date().toISOString(), controller };
    progress = record;
    const scanLog = (m: string) => {
      log(m);
      record.lines.push(m);
      if (record.lines.length > PROGRESS_LINES) record.lines.splice(0, record.lines.length - PROGRESS_LINES);
      const head = m.slice(0, m.indexOf(':'));
      if (STAGES.has(head)) record.stage = head;
    };
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new HttpError(504, `Scan of ${clip(target.dir)} stopped after ${Math.round(scanTimeoutMs / 60_000)} minutes (--scan-timeout)`));
      }, scanTimeoutMs);
    });
    const cancelled = new Promise<never>((_, reject) => {
      controller.signal.addEventListener('abort', () => reject(new HttpError(409, 'Scan cancelled')), { once: true });
    });
    // The signal is passed whether or not the engine's ScanOptions declares it yet; an engine that
    // ignores it keeps running in the background after a cancel and its result is dropped.
    const options: ScanOptions & { signal?: AbortSignal } = { log: scanLog, signal: controller.signal };
    const work = scanner(target.dir, options);
    work.catch(() => {});
    try {
      const report = await Promise.race([work, timeout, cancelled]);
      const row = opts.store.addScan(targetId, report);
      log(`scan: done, ${report.summary.findings} findings (Act ${report.summary.byDecision.Act}, Attend ${report.summary.byDecision.Attend})`);
      ctx.audit('scan.finish', `target:${targetId}`, { scanId: row.id, findings: report.summary.findings, act: report.summary.byDecision.Act, attend: report.summary.byDecision.Attend });
      return { scan: row, report };
    } catch (err) {
      const failure = controller.signal.aborted && !(err instanceof HttpError) ? new HttpError(409, 'Scan cancelled') : err;
      ctx.audit(failure instanceof HttpError && failure.status === 409 ? 'scan.cancelled' : 'scan.failed', `target:${targetId}`, { reason: failure instanceof Error ? failure.message : String(failure) });
      throw failure;
    } finally {
      clearTimeout(timer);
      if (progress === record) progress = null;
    }
  }

  const runScan = (ctx: RouteContext, targetId: number) => withScanLock(() => scanTarget(ctx, targetId));

  function publicProgress(): ScanProgress | null {
    return progress ? { targetId: progress.targetId, stage: progress.stage, lines: progress.lines, startedAt: progress.startedAt } : null;
  }

  /** What /api/health reports under `scanning`: this server's scan, or the lock another server holds. */
  function scanningState(): { targetId: number | null; stage: string; startedAt: string } | null {
    if (progress) return { targetId: progress.targetId, stage: progress.stage, startedAt: progress.startedAt };
    const lock = opts.store.currentScan();
    if (!lock) return null;
    return { targetId: null, stage: lock.pid === opts.store.pid ? 'Starting' : 'Running on another server', startedAt: lock.since };
  }

  /** Re-run the decision step over a stored report with the cache's current EPSS and KEV data. */
  const redecide = (report: ScanReport): Promise<ChangedFinding[]> => redecideReport(report, cachePath, log);

  /** Exceptions in force for a target, read through the features' handle on the same database. */
  const exceptionsFor = (targetId: number) => exceptionsInForce(featureDb(opts.store.path), targetId);

  async function api(req: IncomingMessage, res: ServerResponse, url: URL) {
    const path = url.pathname;
    const m = req.method === 'HEAD' ? 'GET' : req.method ?? 'GET';
    const parts = path.split('/').filter(Boolean); // ['api', ...]
    const segments = parts.slice(1);

    if (m === 'OPTIONS') return send(res, 204, '', { allow: 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS' });
    if (MUTATING.has(m)) {
      const ct = String(req.headers['content-type'] ?? '').toLowerCase();
      if (!ct.startsWith('application/json')) throw new HttpError(415, 'Send a Content-Type of application/json with POST, PUT, PATCH and DELETE requests');
    }
    if (!METHODS.has(m)) throw new HttpError(404, `No route: ${m} ${clip(path)}`);
    const method = m as HttpMethod;

    // Every route has an access rule; a path without one is a 404 before any credential is looked at.
    const builtin = findPolicy(BUILTIN_POLICY, method, segments);
    const feature = builtin ? undefined : matchFeature(method, segments);
    if (!builtin && !feature) throw new HttpError(404, `No route: ${m} ${clip(path)}`);
    const policy: RoutePolicy = builtin ? builtin.policy : { method, pattern: feature!.route.path, role: feature!.route.role, scope: feature!.route.scope, public: feature!.route.public };
    const auth = authenticate(req);
    authorize(auth.user, policy);
    const ctx = makeContext(req, res, method, segments, builtin ? builtin.params : feature!.params, url.searchParams, auth.user);

    if (feature) {
      const out = await feature.route.handler(ctx);
      if (res.headersSent) return;
      return out === undefined ? send(res, 204, '') : send(res, 200, out);
    }
    return builtinRoute(ctx, auth.sessionHash);
  }

  async function builtinRoute(ctx: RouteContext, sessionHash: string | undefined) {
    const { req, res, method: m, params, query } = ctx;
    const segments = ctx.path.split('/').filter(Boolean);
    const [a, b, c] = segments;

    if (m === 'GET' && a === 'health') {
      return send(res, 200, { ok: true, version: toolVersion(), authMode: authModeOf(), scanning: scanningState(), dbPath: opts.store.path, cachePath, otherServer: opts.store.otherServer() });
    }

    // ---- stop the server from the dashboard (admin, from the machine it runs on) ----
    if (m === 'POST' && a === 'shutdown' && !b) {
      ctx.requireRole('admin');
      if (!isLoopbackAddress(ctx.ip)) throw new HttpError(403, 'The dashboards can only be stopped from the machine NextFix runs on');
      if (scanningState()) throw new HttpError(409, 'A scan is running; cancel it first or wait for it to finish');
      ctx.audit('server.shutdown', null, {});
      send(res, 202, { ok: true, message: 'The dashboards are stopping. You can close this tab.' });
      // Let the response leave before the process goes; the CLI listens for this event.
      setTimeout(() => server.emit('nextfix:shutdown'), 250);
      return;
    }

    // ---- who am I, setup, sign in and out ----
    if (a === 'session' && m === 'GET') {
      const mode = authModeOf();
      if (mode === 'none') {
        if (allowOpen) return send(res, 200, { setupRequired: false, authMode: 'none', user: publicUser(OPEN_USER) });
        return send(res, 200, { setupRequired: true, authMode: 'none' });
      }
      const body: { setupRequired: boolean; authMode: AuthMode; user?: ReturnType<typeof publicUser>; oidc?: { providers: { id: string; name: string }[] } } = { setupRequired: false, authMode: mode };
      if (ctx.user) body.user = publicUser(ctx.user);
      if (mode === 'oidc') body.oidc = { providers: oidcSettings().providers.map((p) => ({ id: p.id, name: p.name })) };
      return send(res, 200, body);
    }
    if (a === 'setup' && m === 'POST') {
      if (opts.store.countUsers() > 0) throw new HttpError(409, 'Setup is already done; sign in instead');
      if (!isLoopbackAddress(ctx.ip)) throw new HttpError(403, 'The first admin can only be created from the machine NextFix runs on');
      const body = await ctx.readJson<{ username?: unknown; password?: unknown; displayName?: unknown }>();
      const username = normalizeUsername(body.username);
      const password = checkPassword(body.password);
      const displayName = displayNameOf(body.displayName, username);
      const passwordHash = await hashPassword(password);
      if (opts.store.countUsers() > 0) throw new HttpError(409, 'Setup is already done; sign in instead');
      const user = opts.store.createUser({ username, displayName, role: 'admin', passwordHash, source: 'local' });
      opts.store.touchLogin(user.id);
      const session = createSession(opts.store, user.id, req, cookieSecure(req));
      ctx.user = { id: user.id, username: user.username, displayName: user.displayName, role: user.role, source: 'local' };
      ctx.audit('setup', `user:${user.id}`, { username });
      log(`setup: first admin ${username} created`);
      return send(res, 201, { user: publicUser(ctx.user) }, { 'set-cookie': session.cookie });
    }
    if (a === 'login' && m === 'POST') {
      if (allowOpen) throw new HttpError(409, 'Sign-in is off: this server runs with --allow-open');
      const body = await ctx.readJson<{ username?: unknown; password?: unknown }>();
      const username = typeof body.username === 'string' ? body.username.trim().toLowerCase().slice(0, 64) : '';
      const password = typeof body.password === 'string' ? body.password : '';
      if (!username || !password) throw new HttpError(400, 'username and password are required');
      const until = lockedUntil(opts.store, username);
      if (until !== undefined) throw lockoutError(until);
      const user = opts.store.getUserByUsername(username);
      const ok = await verifyPassword(password, user?.passwordHash);
      if (!user || !ok) {
        opts.store.addLoginFailure(username);
        ctx.audit('login.failed', `user:${username}`, { reason: user ? 'wrong password' : 'unknown user' });
        throw new HttpError(401, 'Wrong username or password');
      }
      if (user.disabled) {
        ctx.audit('login.failed', `user:${user.id}`, { reason: 'disabled' });
        throw new HttpError(403, 'This account is disabled');
      }
      opts.store.clearLoginFailures(username);
      opts.store.touchLogin(user.id);
      opts.store.pruneSessions(SESSION_IDLE_MS);
      const session = createSession(opts.store, user.id, req, cookieSecure(req));
      ctx.user = { id: user.id, username: user.username, displayName: user.displayName, role: user.role, source: user.source };
      ctx.audit('login', `user:${user.id}`, { method: 'password' });
      return send(res, 200, { user: publicUser(ctx.user) }, { 'set-cookie': session.cookie });
    }
    if (a === 'logout' && m === 'POST') {
      const had = destroySession(opts.store, req);
      if (had && ctx.user) ctx.audit('logout', `user:${ctx.user.id}`);
      return send(res, 204, '', { 'set-cookie': clearCookie(SESSION_COOKIE, cookieSecure(req)) });
    }
    if (a === 'auth' && b === 'oidc' && c && m === 'GET') return oidcRoute(ctx);

    // ---- the running scan ----
    if (a === 'scan' && b === 'progress' && m === 'GET') return send(res, 200, publicProgress());
    if (a === 'scan' && !b && m === 'DELETE') {
      if (progress) {
        log(`scan: cancel requested for target ${progress.targetId}`);
        ctx.audit('scan.cancel', `target:${progress.targetId}`);
        progress.controller.abort();
        return send(res, 202, { cancelled: true });
      }
      const lock = opts.store.currentScan();
      if (lock && lock.pid !== opts.store.pid) throw new HttpError(409, `The scan is running on another server (pid ${lock.pid}); cancel it there`);
      throw new HttpError(404, 'No scan is running');
    }

    // ---- settings (SLA days, scan retention) ----
    if (a === 'settings' && !b) {
      if (m === 'GET') return send(res, 200, opts.store.getSettings());
      if (m === 'PUT') {
        const body = await ctx.readJson<Record<string, unknown>>();
        const updates: [SettingKey, number][] = [];
        for (const key of SETTING_KEYS) {
          if (!(key in body)) continue;
          const n = Number(body[key]);
          if (!Number.isInteger(n) || n < 1 || n > 3650) throw new HttpError(400, `${key} must be a whole number between 1 and 3650`);
          updates.push([key, n]);
        }
        for (const [k, v] of updates) opts.store.setSetting(k, v);
        if (updates.length) ctx.audit('settings.update', 'settings', Object.fromEntries(updates));
        return send(res, 200, opts.store.getSettings());
      }
    }
    if (a === 'settings' && b === 'oidc') {
      if (m === 'GET') return send(res, 200, publicOidcSettings(oidcSettings(), requestOrigin(req)));
      if (m === 'PUT') {
        const body = await ctx.readJson<unknown>();
        const next = normalizeOidcSettings(body, oidcSettings());
        opts.store.setJsonSetting('oidc', next);
        ctx.audit('settings.oidc', 'settings', { providers: next.providers.map((p) => ({ id: p.id, preset: p.preset, issuer: p.issuer, defaultRole: p.defaultRole, allowedDomains: p.allowedDomains ?? [] })) });
        return send(res, 200, publicOidcSettings(next, requestOrigin(req)));
      }
    }

    // ---- accounts ----
    if (a === 'users' && !b) {
      if (m === 'GET') return send(res, 200, opts.store.listUsers());
      if (m === 'POST') {
        const body = await ctx.readJson<{ username?: unknown; password?: unknown; displayName?: unknown; role?: unknown }>();
        const username = normalizeUsername(body.username);
        const password = checkPassword(body.password);
        const displayName = displayNameOf(body.displayName, username);
        const role = body.role ?? 'viewer';
        if (!isRole(role)) throw new HttpError(400, 'role must be admin, analyst or viewer');
        if (opts.store.getUserByUsername(username)) throw new HttpError(409, `A user named ${username} already exists`);
        const user = opts.store.createUser({ username, displayName, role, passwordHash: await hashPassword(password), source: 'local' });
        ctx.audit('user.create', `user:${user.id}`, { username, role });
        return send(res, 201, Store.publicUser(user));
      }
    }
    if (a === 'users' && b) {
      const id = Number(b);
      if (!Number.isInteger(id)) throw new HttpError(400, 'Bad user id');
      if (m === 'POST' && c === 'password') {
        const caller = ctx.user!;
        const target = opts.store.getUser(id);
        if (!target) throw new HttpError(404, 'User not found');
        const body = await ctx.readJson<{ password?: unknown; currentPassword?: unknown }>();
        const self = caller.id === id && (caller.source === 'local' || caller.source === 'oidc');
        if (self) {
          if (typeof body.currentPassword !== 'string' || !(await verifyPassword(body.currentPassword, target.passwordHash))) throw new HttpError(403, 'The current password is wrong');
        } else {
          ctx.requireRole('admin');
        }
        const password = checkPassword(body.password);
        opts.store.setPasswordHash(id, await hashPassword(password));
        opts.store.deleteUserSessions(id, self ? sessionHash : undefined);
        ctx.audit('user.password', `user:${id}`, { by: self ? 'self' : 'admin' });
        return send(res, 204, '');
      }
      if (m === 'PATCH' && !c) {
        const target = opts.store.getUser(id);
        if (!target) throw new HttpError(404, 'User not found');
        const body = await ctx.readJson<{ role?: unknown; disabled?: unknown; displayName?: unknown }>();
        const patch: { role?: AuthUser['role']; disabled?: boolean; displayName?: string } = {};
        if (body.role !== undefined) {
          if (!isRole(body.role)) throw new HttpError(400, 'role must be admin, analyst or viewer');
          patch.role = body.role;
        }
        if (body.disabled !== undefined) {
          if (typeof body.disabled !== 'boolean') throw new HttpError(400, 'disabled must be true or false');
          patch.disabled = body.disabled;
        }
        if (body.displayName !== undefined) patch.displayName = displayNameOf(body.displayName, target.username);
        const losesAdmin = target.role === 'admin' && !target.disabled && ((patch.role !== undefined && patch.role !== 'admin') || patch.disabled === true);
        if (losesAdmin && opts.store.countEnabledAdmins() <= 1) throw new HttpError(409, 'This is the last enabled admin; make someone else an admin first');
        opts.store.updateUser(id, patch);
        if (patch.disabled === true) opts.store.deleteUserSessions(id);
        ctx.audit('user.update', `user:${id}`, patch);
        return send(res, 200, Store.publicUser(opts.store.getUser(id)!));
      }
      if (m === 'DELETE' && !c) {
        if (ctx.user!.id === id) throw new HttpError(400, 'You cannot delete your own account');
        const target = opts.store.getUser(id);
        if (!target) throw new HttpError(404, 'User not found');
        if (target.role === 'admin' && !target.disabled && opts.store.countEnabledAdmins() <= 1) throw new HttpError(409, 'This is the last enabled admin; make someone else an admin first');
        opts.store.deleteUser(id);
        ctx.audit('user.delete', `user:${id}`, { username: target.username });
        return send(res, 204, '');
      }
    }

    // ---- API tokens ----
    if (a === 'tokens' && !b) {
      if (m === 'GET') {
        const names = new Map<number, string>();
        for (const u of opts.store.listUsers()) names.set(u.id, u.username);
        return send(res, 200, opts.store.listTokens().map((t) => ({ id: t.id, name: t.name, scopes: t.scopes, createdAt: t.createdAt, lastUsedAt: t.lastUsedAt, createdBy: t.createdBy === null ? null : names.get(t.createdBy) ?? null })));
      }
      if (m === 'POST') {
        const body = await ctx.readJson<{ name?: unknown; scopes?: unknown }>();
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        if (!name || name.length > 60) throw new HttpError(400, 'name must be 1 to 60 characters');
        const scopes = parseScopes(body.scopes);
        const { token, hash } = generateToken();
        const row = opts.store.createToken({ name, hash, scopes, createdBy: ctx.user!.source === 'local' || ctx.user!.source === 'oidc' ? ctx.user!.id : null });
        ctx.audit('token.create', `token:${row.id}`, { name, scopes });
        return send(res, 201, { id: row.id, token });
      }
    }
    if (a === 'tokens' && b && !c && m === 'DELETE') {
      const id = Number(b);
      if (!Number.isInteger(id)) throw new HttpError(400, 'Bad token id');
      const row = opts.store.getToken(id);
      if (!row) throw new HttpError(404, 'Token not found');
      opts.store.deleteToken(id);
      ctx.audit('token.delete', `token:${id}`, { name: row.name });
      return send(res, 204, '');
    }

    // ---- audit log ----
    if (a === 'audit' && !b && m === 'GET') {
      const limitRaw = query.get('limit');
      const limit = limitRaw === null ? AUDIT_PAGE_DEFAULT : Number(limitRaw);
      if (!Number.isInteger(limit) || limit < 1 || limit > AUDIT_PAGE_MAX) throw new HttpError(400, `limit must be a whole number between 1 and ${AUDIT_PAGE_MAX}`);
      const beforeRaw = query.get('before');
      const before = beforeRaw === null ? undefined : Number(beforeRaw);
      if (before !== undefined && !Number.isInteger(before)) throw new HttpError(400, 'before must be an audit row id');
      const rows = opts.store.listAudit(limit, before);
      return send(res, 200, { rows, next: rows.length === limit ? rows[rows.length - 1]!.id : null });
    }

    if (a === 'targets' && !b) {
      if (m === 'GET') return send(res, 200, opts.store.listTargets());
      if (m === 'POST') {
        const body = await ctx.readJson<{ dir?: unknown }>();
        const given = typeof body.dir === 'string' ? body.dir : '';
        const dir = given ? resolve(given) : '';
        if (!dir || !existsSync(dir) || !statSync(dir).isDirectory()) throw new HttpError(400, `Folder not found: ${clip(given)}`);
        if (!hasNodeProject(dir) && !hasPythonProject(dir) && !hasGoProject(dir) && !hasImageSources(dir)) throw new HttpError(400, 'That folder has no package-lock.json, yarn.lock or pnpm-lock.yaml, no Python requirements or lockfile, no go.mod, no SBOM and no image in nextfix.config.json. NextFix scans npm, PyPI and Go projects with pinned dependencies, and container images.');
        // The target is only recorded once the scan lock is ours, so a busy server never leaves an unscanned target behind.
        const result = await withScanLock(async () => {
          const target = opts.store.upsertTarget(dir);
          ctx.audit('target.add', `target:${target.id}`, { dir });
          return { target: target.id, ...(await scanTarget(ctx, target.id)) };
        });
        return send(res, 201, { target: opts.store.getTarget(result.target), scan: result.scan, report: result.report });
      }
    }
    if (a === 'targets' && b) {
      const id = Number(b);
      if (!Number.isInteger(id)) throw new HttpError(400, 'Bad target id');
      if (m === 'DELETE' && !c) {
        const target = opts.store.getTarget(id);
        opts.store.deleteTarget(id);
        if (target) ctx.audit('target.delete', `target:${id}`, { dir: target.dir });
        return send(res, 204, '');
      }
      if (m === 'POST' && c === 'scan') {
        if (!opts.store.getTarget(id)) throw new HttpError(404, 'Target not found');
        return send(res, 201, await runScan(ctx, id));
      }
      if (m === 'GET' && c === 'scans') return send(res, 200, opts.store.listScans(id));
      if (m === 'GET' && c === 'history') {
        if (!opts.store.getTarget(id)) throw new HttpError(404, 'Target not found');
        return send(res, 200, opts.store.historySummary(id));
      }
      if (m === 'POST' && c === 'redecide') {
        const last = opts.store.latestScan(id);
        if (!last) throw new HttpError(404, opts.store.getTarget(id) ? 'This application has not been scanned yet' : 'Target not found');
        const report = opts.store.getReport(last.id)!;
        const changed = await redecide(report);
        const order = ['Act', 'Attend', 'Track*', 'Track'];
        const escalated = changed.filter((x) => order.indexOf(x.to) < order.indexOf(x.from)).length;
        return send(res, 200, { scanId: last.id, checkedAt: new Date().toISOString(), changed, summary: { changed: changed.length, escalated, deescalated: changed.length - escalated } });
      }
    }
    // ---- tracker integrations ----
    if (a === 'integrations' && !b && m === 'GET') {
      const gh = opts.store.getIntegration<GitHubConfig>('github');
      const jira = opts.store.getIntegration<JiraConfig>('jira');
      return send(res, 200, {
        github: gh ? { repo: gh.repo, labels: gh.labels ?? [], hasToken: !!gh.token } : undefined,
        jira: jira ? { baseUrl: jira.baseUrl, email: jira.email, projectKey: jira.projectKey, issueType: jira.issueType ?? 'Task', hasToken: !!jira.apiToken } : undefined,
      });
    }
    if (a === 'integrations' && (b === 'github' || b === 'jira')) {
      if (m === 'DELETE') {
        opts.store.deleteIntegration(b);
        ctx.audit('integration.delete', `integration:${b}`);
        return send(res, 204, '');
      }
      if (m === 'PUT') {
        const body = await ctx.readJson<Record<string, unknown>>();
        const existing = opts.store.getIntegration<Record<string, unknown>>(b);
        let merged: Record<string, unknown>;
        try {
          merged = mergeIntegrationConfig(b, existing, body);
        } catch (err) {
          if (err instanceof IntegrationError) throw new HttpError(err.status, err.message);
          throw err;
        }
        opts.store.setIntegration(b, merged);
        ctx.audit('integration.update', `integration:${b}`, { fields: Object.keys(body).filter((k) => !/token/i.test(k)) });
        return send(res, 200, { ok: true });
      }
      if (m === 'POST' && c === 'test') {
        const cfg = opts.store.getIntegration<GitHubConfig & JiraConfig>(b);
        if (!cfg) throw new HttpError(400, 'Not configured yet');
        try {
          const msg = b === 'github' ? await githubTest(cfg) : await jiraTest(cfg);
          return send(res, 200, { ok: true, message: msg });
        } catch (err) {
          throw new HttpError(err instanceof IntegrationError ? 400 : 500, err instanceof Error ? err.message : String(err));
        }
      }
    }
    if (a === 'targets' && b && c === 'tickets') {
      const id = Number(b);
      if (m === 'GET') return send(res, 200, opts.store.listTickets(id));
      if (m === 'POST') {
        const body = await ctx.readJson<{ scanId?: number; findingIds?: unknown; kind?: unknown }>();
        const kind = body.kind === 'github' || body.kind === 'jira' ? body.kind : undefined;
        if (!kind) throw new HttpError(400, 'kind must be "github" or "jira"');
        const report = body.scanId ? opts.store.getReport(body.scanId) : undefined;
        if (!report) throw new HttpError(404, 'Scan not found');
        const cfg = opts.store.getIntegration<GitHubConfig & JiraConfig>(kind);
        if (!cfg) throw new HttpError(400, `${kind === 'github' ? 'GitHub' : 'Jira'} is not configured (Settings → Integrations)`);
        const existing = opts.store.listTickets(id);
        const targetName = report.target.name ?? report.target.dir;
        const results: { findingId: string; key?: string; url?: string; error?: string; skipped?: boolean }[] = [];
        const findingIds = Array.isArray(body.findingIds) ? body.findingIds.filter((x): x is string => typeof x === 'string') : [];
        let created = 0;
        for (const fid of findingIds) {
          const f = report.findings.find((x) => x.id === fid);
          if (!f) {
            results.push({ findingId: fid, error: 'finding not in this scan' });
            continue;
          }
          const already = existing[fid]?.find((t) => t.kind === kind);
          if (already) {
            results.push({ findingId: fid, key: already.key, url: already.url, skipped: true });
            continue;
          }
          if (created > 0 && ticketSpacingMs > 0) await sleep(ticketSpacingMs);
          let ticket: { key: string; url: string } | undefined;
          try {
            const title = ticketTitle(f);
            const md = ticketMarkdown(f, targetName);
            ticket = kind === 'github' ? await githubCreateIssue(cfg, title, md) : await jiraCreateIssue(cfg, title, md);
          } catch (err) {
            results.push({ findingId: fid, error: err instanceof Error ? err.message : String(err) });
            continue;
          }
          // Persist the link before anything else can fail, so a retry finds it instead of creating a duplicate.
          opts.store.addTicket(id, fid, kind, ticket.key, ticket.url);
          created++;
          results.push({ findingId: fid, key: ticket.key, url: ticket.url });
          ctx.audit('ticket.create', `ticket:${kind}:${ticket.key}`, { targetId: id, findingId: fid, url: ticket.url });
          log(`ticket: ${kind} ${ticket.key} for ${fid}`);
        }
        return send(res, 200, { results });
      }
    }

    if (a === 'scans' && b) {
      const id = Number(b);
      const row = opts.store.getScan(id);
      if (!row) throw new HttpError(404, 'Scan not found');
      // Approved exceptions turn their findings into set-asides with the approver's reason on top.
      const report = applyExceptions(opts.store.getReport(id)!, exceptionsFor(row.targetId));
      // The list payload: findings without advisory text, references capped, first-seen dates joined in.
      if (m === 'GET' && !c) return send(res, 200, trimReport(report, opts.store.firstSeenMap(row.targetId)));
      // The complete report, as a download.
      if (m === 'GET' && c === 'json') return send(res, 200, JSON.stringify(report, null, 2), { 'content-disposition': `attachment; filename="${exportName(report, '.nextfix.json')}"`, 'content-type': 'application/json; charset=utf-8' });
      if (m === 'GET' && c === 'findings') {
        const findingId = decodeURIComponent(params['*'] ?? segments.slice(3).join('/'));
        const f = report.findings.find((x) => x.id === findingId);
        if (!f) throw new HttpError(404, 'Finding not in this scan');
        return send(res, 200, { ...f, firstSeenAt: opts.store.firstSeenMap(row.targetId)[f.id] });
      }
      if (m === 'GET' && c === 'diff') {
        const prev = opts.store.previousScan(row);
        const prevReport = prev ? opts.store.getReport(prev.id) : undefined;
        return send(res, 200, { previous: prev, ...diffReports(report, prevReport) });
      }
      if (m === 'GET' && c === 'vex') {
        return send(res, 200, JSON.stringify(toOpenVex(report, exceptionsFor(row.targetId).map(toVexException)), null, 2), { 'content-disposition': `attachment; filename="${exportName(report, '.openvex.json')}"`, 'content-type': 'application/json; charset=utf-8' });
      }
    }
    throw new HttpError(404, `No route: ${m} ${clip(ctx.path)}`);
  }

  /** GET /api/auth/oidc/:provider/start and /callback: the browser round trip through the identity provider. */
  async function oidcRoute(ctx: RouteContext) {
    const { req, res, params, query } = ctx;
    const step = ctx.path.split('/').filter(Boolean)[3];
    const provider = oidcSettings().providers.find((p) => p.id === params.provider);
    if (!provider) throw new HttpError(404, 'No such sign-in provider');
    const secure = cookieSecure(req);
    const redirectUri = redirectUriFor(requestOrigin(req), provider.id);
    if (step === 'start') {
      if (allowOpen) throw new HttpError(409, 'Sign-in is off: this server runs with --allow-open');
      if (opts.store.countUsers() === 0) throw new HttpError(409, 'Create the first admin before signing in with SSO');
      const { location, cookie } = await startAuth(provider, redirectUri, opts.store.authSecret(), secure);
      return send(res, 302, '', { location, 'set-cookie': cookie });
    }
    if (step !== 'callback') throw new HttpError(404, `No route: GET ${clip(ctx.path)}`);
    const flowCookie = (req.headers.cookie ?? '').split(';').map((s) => s.trim()).find((s) => s.startsWith(`${OIDC_COOKIE}=`))?.slice(OIDC_COOKIE.length + 1);
    const clearFlow = clearCookie(OIDC_COOKIE, secure);
    try {
      if (allowOpen || opts.store.countUsers() === 0) throw new HttpError(409, 'SSO sign-in is not available on this server yet');
      const identity = await finishAuth(provider, redirectUri, query, flowCookie, opts.store.authSecret());
      let user = opts.store.getUserByOidc(provider.id, identity.sub);
      if (!user) {
        const byName = opts.store.getUserByUsername(identity.email);
        if (byName) {
          // The provider vouches for this address; the existing account becomes its sign-in.
          opts.store.updateUser(byName.id, { oidcProvider: provider.id, oidcSub: identity.sub });
          user = opts.store.getUser(byName.id)!;
          ctx.audit('oidc.link', `user:${user.id}`, { provider: provider.id, username: user.username });
        } else {
          user = opts.store.createUser({ username: identity.email, displayName: identity.name, role: identity.role, source: 'oidc', oidcProvider: provider.id, oidcSub: identity.sub });
          ctx.audit('user.create', `user:${user.id}`, { username: user.username, role: user.role, provider: provider.id });
        }
      }
      if (user.disabled) {
        ctx.audit('login.failed', `user:${user.id}`, { reason: 'disabled', provider: provider.id });
        throw new HttpError(403, 'This account is disabled');
      }
      // A role mapping keeps the role in step with the provider; without one, the admin's choice here stands.
      const patch: { displayName?: string; role?: AuthUser['role'] } = {};
      if (identity.name && identity.name !== user.displayName) patch.displayName = identity.name;
      if (provider.roleMap && identity.role !== user.role) {
        if (user.role === 'admin' && !user.disabled && opts.store.countEnabledAdmins() <= 1) log(`oidc: ${user.username} stays admin; the provider maps them lower but they are the last admin`);
        else patch.role = identity.role;
      }
      if (Object.keys(patch).length) {
        opts.store.updateUser(user.id, patch);
        user = opts.store.getUser(user.id)!;
      }
      opts.store.touchLogin(user.id);
      opts.store.pruneSessions(SESSION_IDLE_MS);
      const session = createSession(opts.store, user.id, req, secure);
      ctx.user = { id: user.id, username: user.username, displayName: user.displayName, role: user.role, source: 'oidc' };
      ctx.audit('login', `user:${user.id}`, { method: 'oidc', provider: provider.id });
      return send(res, 302, '', { location: '/', 'set-cookie': [session.cookie, clearFlow] });
    } catch (err) {
      if (!(err instanceof HttpError)) throw err;
      log(`oidc: sign-in through ${provider.id} failed: ${err.message}`);
      const html = `<!doctype html><meta charset="utf-8"><title>NextFix — sign-in failed</title><body style="font-family:system-ui;padding:2rem;max-width:40rem"><h1>Sign-in failed</h1><p>${escapeHtml(err.message)}</p><p><a href="/">Back to NextFix</a></p>`;
      return send(res, err.status, html, { 'content-type': 'text/html; charset=utf-8', 'set-cookie': clearFlow, ...err.headers });
    }
  }

  function serveStatic(req: IncomingMessage, res: ServerResponse, path: string) {
    let name = path === '/' ? 'index.html' : path.replace(/^\/+/, '');
    let body: Buffer | undefined;
    if (staticDir) {
      let file = normalize(join(staticDir, name));
      if (!file.startsWith(normalize(staticDir))) return send(res, 403, 'Forbidden');
      if (!existsSync(file) || statSync(file).isDirectory()) {
        file = join(staticDir, 'index.html');
        name = 'index.html';
      }
      if (existsSync(file)) body = readFileSync(file);
    } else {
      // Embedded in the executable: exact keys only, so a path with ".." simply falls back to the app shell.
      if (!hasAsset(`web/${name}`)) name = 'index.html';
      if (hasAsset(`web/${name}`)) body = readAsset(`web/${name}`);
    }
    if (body === undefined) {
      return send(res, 200, '<!doctype html><meta charset="utf-8"><title>NextFix</title><body style="font-family:system-ui;padding:2rem"><h1>NextFix</h1><p>The dashboard has not been built yet. Run <code>npm run build</code> in the repo, then reload.</p><p>The API is live at <code>/api/health</code>.</p>', { 'content-type': 'text/html; charset=utf-8' });
    }
    const ext = extname(name).toLowerCase();
    const isAsset = name.startsWith('assets/') || name.includes('/assets/');
    const headers: Record<string, string> = { 'content-type': MIME[ext] ?? 'application/octet-stream', 'cache-control': isAsset ? 'public, max-age=3600' : 'no-cache' };
    if (COMPRESSIBLE.has(ext) && body.length >= GZIP_MIN_BYTES && acceptsGzip(req)) {
      body = gzipSync(body);
      headers['content-encoding'] = 'gzip';
      headers.vary = 'accept-encoding';
    }
    headers['content-length'] = String(body.length);
    res.writeHead(200, headers);
    if (req.method === 'HEAD') res.end();
    else res.end(body);
  }

  /** Browsers reach a local server through DNS names an attacker may control; only names we know are served. */
  function checkHost(req: IncomingMessage) {
    const host = req.headers.host;
    if (host === undefined) return;
    if (!allowedHosts.has(hostnameOf(host))) throw new HttpError(421, `NextFix does not answer to the name "${clip(host, 100)}"; start it with --allow-host ${clip(hostnameOf(host), 100)} if that name is yours`);
  }

  /** A cross-site page cannot call the API: an Origin header must name this server exactly (behind TLS, the https name). */
  function checkOrigin(req: IncomingMessage) {
    const origin = req.headers.origin;
    if (origin === undefined) return;
    let ok = false;
    try {
      const u = new URL(origin);
      const port = u.port || (u.protocol === 'http:' ? '80' : '443');
      const host = u.hostname.toLowerCase();
      if (u.protocol === 'http:') ok = allowedHosts.has(host) && port === String(serverPort());
      else if (u.protocol === 'https:') ok = (secureCookies || isHttps(req)) && allowedHosts.has(host);
    } catch {
      ok = false;
    }
    if (!ok) throw new HttpError(403, `Requests from ${clip(origin, 100)} are not accepted`);
  }

  /** Without accounts the server answers this machine only; anyone else gets a sentence saying why. */
  function checkLoopback(req: IncomingMessage) {
    if (!openMode() || isLoopbackAddress(clientIp(req))) return;
    if (allowOpen) throw new HttpError(403, 'This NextFix server runs with --allow-open and answers only on the machine it runs on');
    throw new HttpError(403, `NextFix has no accounts yet; open http://127.0.0.1:${serverPort()} on the machine it runs on to create the first admin`);
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      checkHost(req);
      checkLoopback(req);
      if (url.pathname.startsWith('/api/')) {
        checkOrigin(req);
        await api(req, res, url);
      } else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res, url.pathname);
      else send(res, 405, 'Method not allowed');
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof Error ? err.message : String(err);
      if (status >= 500) log(`error: ${message}`);
      if (!res.headersSent) send(res, status, { error: message }, err instanceof HttpError ? err.headers : {});
      else res.end();
    }
  });

  // Register this server in the shared database and keep its lock rows fresh while it runs.
  let heartbeat: NodeJS.Timeout | undefined;
  server.on('listening', () => {
    try {
      const other = opts.store.acquireServerLock(listenHost || 'localhost', serverPort());
      if (other) log(`warning: another NextFix server (pid ${other.pid}, port ${other.port}) is using this database`);
    } catch (err) {
      log(`warning: could not record the server lock: ${err instanceof Error ? err.message : String(err)}`);
    }
    heartbeat = setInterval(() => {
      try {
        opts.store.heartbeat();
      } catch {
        /* the store may already be closed during shutdown */
      }
    }, HEARTBEAT_MS);
    heartbeat.unref();
  });
  server.on('close', () => {
    if (heartbeat) clearInterval(heartbeat);
    try {
      opts.store.releaseLocks();
    } catch {
      /* the store may already be closed */
    }
  });

  // Scans the scheduler starts are attributed to a system user in the audit log.
  const schedulerUser: AuthUser = { id: 0, username: 'scheduler', displayName: 'Scheduler', role: 'admin', source: 'open' };
  const schedulerCtx = {
    user: schedulerUser,
    ip: '127.0.0.1',
    store: opts.store,
    log,
    audit: (action: string, target?: string | null, detail?: unknown) => audit({ user: schedulerUser, ip: '127.0.0.1', store: opts.store }, action, target, detail),
  } as unknown as RouteContext;

  return Object.assign(server, {
    nextfix: {
      /** Scan a target outside a request (the scheduler); same lock and timeout as a dashboard scan. */
      runScan: (targetId: number) => runScan(schedulerCtx, targetId).then(() => undefined),
      redecide,
    },
  });
}
