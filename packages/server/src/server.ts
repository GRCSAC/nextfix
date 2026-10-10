import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../../engine/src/scan.ts';
import { toOpenVex } from '../../engine/src/report/vex.ts';
import { toolVersion } from '../../engine/src/version.ts';
import { defaultCachePath } from '../../engine/src/vulns/cache.ts';
import { hasPythonProject } from '../../engine/src/inventory/python.ts';
import { detectSbomFiles } from '../../engine/src/inventory/container.ts';
import { asList, loadConfig } from '../../engine/src/config.ts';
import { ticketMarkdown, ticketTitle } from '../../engine/src/report/ticket.ts';
import { githubCreateIssue, githubTest, jiraCreateIssue, jiraTest, mergeIntegrationConfig, IntegrationError, type GitHubConfig, type JiraConfig } from './integrations.ts';
import { Store } from './store.ts';
import { diffReports } from './diff.ts';

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
}

/** Request bodies larger than this are refused. */
export const MAX_BODY_BYTES = 1024 * 1024;
export const DEFAULT_SCAN_TIMEOUT_MS = 20 * 60_000;
const HEARTBEAT_MS = 20_000;
const MUTATING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

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

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
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

export function defaultStaticDir(): string {
  return fileURLToPath(new URL('../../web/dist/', import.meta.url));
}

export function createNextFixServer(opts: ServerOptions) {
  const staticDir = opts.staticDir ?? defaultStaticDir();
  const log = opts.log ?? (() => {});
  const scanTimeoutMs = opts.scanTimeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS;
  const ticketSpacingMs = opts.ticketSpacingMs ?? 1000;

  const allowedHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
  const listenHost = (opts.host ?? '').trim().toLowerCase();
  if (listenHost && listenHost !== '0.0.0.0' && listenHost !== '::') allowedHosts.add(listenHost.includes(':') && !listenHost.startsWith('[') ? `[${listenHost}]` : listenHost);
  for (const h of opts.allowHosts ?? []) if (h.trim()) allowedHosts.add(hostnameOf(h));

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

  function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
    res.end(text);
  }

  function serverPort(): number {
    const addr = server.address();
    return addr && typeof addr === 'object' ? (addr as AddressInfo).port : 0;
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
  async function scanTarget(targetId: number) {
    const target = opts.store.getTarget(targetId);
    if (!target) throw new HttpError(404, 'Target not found');
    log(`scan: ${target.dir}`);
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new HttpError(504, `Scan of ${clip(target.dir)} stopped after ${Math.round(scanTimeoutMs / 60_000)} minutes (--scan-timeout)`)), scanTimeoutMs);
    });
    const work = scan(target.dir, { log });
    // If the timeout wins, the engine keeps running in the background; its result is dropped.
    work.catch(() => {});
    try {
      const report = await Promise.race([work, timeout]);
      const row = opts.store.addScan(targetId, report);
      log(`scan: done, ${report.summary.findings} findings (Act ${report.summary.byDecision.Act}, Attend ${report.summary.byDecision.Attend})`);
      return { scan: row, report };
    } finally {
      clearTimeout(timer);
    }
  }

  const runScan = (targetId: number) => withScanLock(() => scanTarget(targetId));

  async function api(req: IncomingMessage, res: ServerResponse, path: string) {
    const m = req.method ?? 'GET';
    const parts = path.split('/').filter(Boolean); // ['api', ...]
    const [, a, b, c] = parts;

    if (m === 'OPTIONS') return send(res, 204, '', { allow: 'GET, HEAD, POST, PUT, DELETE, OPTIONS' });
    if (MUTATING.has(m)) {
      const ct = String(req.headers['content-type'] ?? '').toLowerCase();
      if (!ct.startsWith('application/json')) throw new HttpError(415, 'Send a Content-Type of application/json with POST, PUT, PATCH and DELETE requests');
    }

    if (m === 'GET' && a === 'health') {
      return send(res, 200, { ok: true, version: toolVersion(), scanning: opts.store.scanInProgress(), dbPath: opts.store.path, cachePath: defaultCachePath(), otherServer: opts.store.otherServer() });
    }

    if (a === 'targets' && !b) {
      if (m === 'GET') return send(res, 200, opts.store.listTargets());
      if (m === 'POST') {
        const body = await readJson<{ dir?: unknown }>(req);
        const given = typeof body.dir === 'string' ? body.dir : '';
        const dir = given ? resolve(given) : '';
        if (!dir || !existsSync(dir) || !statSync(dir).isDirectory()) throw new HttpError(400, `Folder not found: ${clip(given)}`);
        if (!existsSync(join(dir, 'package-lock.json')) && !hasPythonProject(dir) && !hasImageSources(dir)) throw new HttpError(400, 'That folder has no package-lock.json, no Python requirements or lockfile, no SBOM and no image in nextfix.config.json. NextFix scans npm and PyPI projects with pinned dependencies, and container images.');
        // The target is only recorded once the scan lock is ours, so a busy server never leaves an unscanned target behind.
        const result = await withScanLock(async () => {
          const target = opts.store.upsertTarget(dir);
          return { target: target.id, ...(await scanTarget(target.id)) };
        });
        return send(res, 201, { target: opts.store.getTarget(result.target), scan: result.scan, report: result.report });
      }
    }
    if (a === 'targets' && b) {
      const id = Number(b);
      if (!Number.isInteger(id)) throw new HttpError(400, 'Bad target id');
      if (m === 'DELETE' && !c) {
        opts.store.deleteTarget(id);
        return send(res, 204, '');
      }
      if (m === 'POST' && c === 'scan') {
        if (!opts.store.getTarget(id)) throw new HttpError(404, 'Target not found');
        return send(res, 201, await runScan(id));
      }
      if (m === 'GET' && c === 'scans') return send(res, 200, opts.store.listScans(id));
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
        return send(res, 204, '');
      }
      if (m === 'PUT') {
        const body = await readJson<Record<string, unknown>>(req);
        const existing = opts.store.getIntegration<Record<string, unknown>>(b);
        let merged: Record<string, unknown>;
        try {
          merged = mergeIntegrationConfig(b, existing, body);
        } catch (err) {
          if (err instanceof IntegrationError) throw new HttpError(err.status, err.message);
          throw err;
        }
        opts.store.setIntegration(b, merged);
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
        const body = await readJson<{ scanId?: number; findingIds?: unknown; kind?: unknown }>(req);
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
          log(`ticket: ${kind} ${ticket.key} for ${fid}`);
        }
        return send(res, 200, { results });
      }
    }

    if (a === 'scans' && b) {
      const id = Number(b);
      const row = opts.store.getScan(id);
      if (!row) throw new HttpError(404, 'Scan not found');
      const report = opts.store.getReport(id)!;
      if (m === 'GET' && !c) return send(res, 200, report);
      if (m === 'GET' && c === 'diff') {
        const prev = opts.store.previousScan(row);
        const prevReport = prev ? opts.store.getReport(prev.id) : undefined;
        return send(res, 200, { previous: prev, ...diffReports(report, prevReport) });
      }
      if (m === 'GET' && c === 'vex') {
        const name = `${(report.target.name ?? 'app').replace(/[^\w.-]+/g, '_')}-${report.generatedAt.slice(0, 10)}.openvex.json`;
        return send(res, 200, JSON.stringify(toOpenVex(report), null, 2), { 'content-disposition': `attachment; filename="${name}"`, 'content-type': 'application/json; charset=utf-8' });
      }
    }
    throw new HttpError(404, `No route: ${m} ${clip(path)}`);
  }

  function serveStatic(res: ServerResponse, path: string) {
    let file = normalize(join(staticDir, path === '/' ? 'index.html' : path));
    if (!file.startsWith(normalize(staticDir))) return send(res, 403, 'Forbidden');
    if (!existsSync(file) || statSync(file).isDirectory()) file = join(staticDir, 'index.html');
    if (!existsSync(file)) {
      return send(res, 200, '<!doctype html><meta charset="utf-8"><title>NextFix</title><body style="font-family:system-ui;padding:2rem"><h1>NextFix</h1><p>The dashboard has not been built yet. Run <code>npm run build</code> in the repo, then reload.</p><p>The API is live at <code>/api/health</code>.</p>', { 'content-type': 'text/html; charset=utf-8' });
    }
    const ext = extname(file).toLowerCase();
    const isAsset = file.includes(`${normalize('/assets/')}`) || file.includes('\\assets\\');
    res.writeHead(200, { 'content-type': MIME[ext] ?? 'application/octet-stream', 'cache-control': isAsset ? 'public, max-age=3600' : 'no-cache' });
    res.end(readFileSync(file));
  }

  /** Browsers reach a local server through DNS names an attacker may control; only names we know are served. */
  function checkHost(req: IncomingMessage) {
    const host = req.headers.host;
    if (host === undefined) return;
    if (!allowedHosts.has(hostnameOf(host))) throw new HttpError(421, `NextFix does not answer to the name "${clip(host, 100)}"; start it with --allow-host ${clip(hostnameOf(host), 100)} if that name is yours`);
  }

  /** A cross-site page cannot call the API: an Origin header must name this server exactly. */
  function checkOrigin(req: IncomingMessage) {
    const origin = req.headers.origin;
    if (origin === undefined) return;
    let ok = false;
    try {
      const u = new URL(origin);
      const port = u.port || (u.protocol === 'http:' ? '80' : '443');
      ok = u.protocol === 'http:' && allowedHosts.has(u.hostname.toLowerCase()) && port === String(serverPort());
    } catch {
      ok = false;
    }
    if (!ok) throw new HttpError(403, `Requests from ${clip(origin, 100)} are not accepted`);
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      checkHost(req);
      if (url.pathname.startsWith('/api/')) {
        checkOrigin(req);
        await api(req, res, url.pathname);
      } else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(res, url.pathname);
      else send(res, 405, 'Method not allowed');
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof Error ? err.message : String(err);
      if (status >= 500) log(`error: ${message}`);
      if (!res.headersSent) send(res, status, { error: message });
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

  return server;
}
