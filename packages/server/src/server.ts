import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../../engine/src/scan.ts';
import { toOpenVex } from '../../engine/src/report/vex.ts';
import { toolVersion } from '../../engine/src/version.ts';
import { defaultCachePath } from '../../engine/src/vulns/cache.ts';
import { Store } from './store.ts';
import { diffReports } from './diff.ts';

export interface ServerOptions {
  store: Store;
  staticDir?: string;
  log?: (msg: string) => void;
}

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

export function defaultStaticDir(): string {
  return fileURLToPath(new URL('../../web/dist/', import.meta.url));
}

export function createNextFixServer(opts: ServerOptions) {
  const staticDir = opts.staticDir ?? defaultStaticDir();
  const log = opts.log ?? (() => {});
  let scanning = false;

  async function readJson<T>(req: IncomingMessage): Promise<T> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const text = Buffer.concat(chunks).toString('utf8');
    if (!text) return {} as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new HttpError(400, 'Body must be JSON');
    }
  }

  function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
    res.end(text);
  }

  async function runScan(targetId: number) {
    const target = opts.store.getTarget(targetId);
    if (!target) throw new HttpError(404, 'Target not found');
    if (scanning) throw new HttpError(409, 'A scan is already running');
    scanning = true;
    try {
      log(`scan: ${target.dir}`);
      const report = await scan(target.dir, { log });
      const row = opts.store.addScan(targetId, report);
      log(`scan: done, ${report.summary.findings} findings (Act ${report.summary.byDecision.Act}, Attend ${report.summary.byDecision.Attend})`);
      return { scan: row, report };
    } finally {
      scanning = false;
    }
  }

  async function api(req: IncomingMessage, res: ServerResponse, path: string) {
    const m = req.method ?? 'GET';
    const parts = path.split('/').filter(Boolean); // ['api', ...]
    const [, a, b, c] = parts;

    if (m === 'GET' && a === 'health') return send(res, 200, { ok: true, version: toolVersion(), scanning, dbPath: opts.store.path, cachePath: defaultCachePath() });

    if (a === 'targets' && !b) {
      if (m === 'GET') return send(res, 200, opts.store.listTargets());
      if (m === 'POST') {
        const body = await readJson<{ dir?: string }>(req);
        const dir = body.dir ? resolve(body.dir) : '';
        if (!dir || !existsSync(dir) || !statSync(dir).isDirectory()) throw new HttpError(400, `Folder not found: ${body.dir ?? ''}`);
        if (!existsSync(join(dir, 'package-lock.json'))) throw new HttpError(400, 'That folder has no package-lock.json. NextFix currently scans npm projects with a lockfile.');
        const target = opts.store.upsertTarget(dir);
        const result = await runScan(target.id);
        return send(res, 201, { target: opts.store.getTarget(target.id), ...result });
      }
    }
    if (a === 'targets' && b) {
      const id = Number(b);
      if (!Number.isInteger(id)) throw new HttpError(400, 'Bad target id');
      if (m === 'DELETE' && !c) {
        opts.store.deleteTarget(id);
        return send(res, 204, '');
      }
      if (m === 'POST' && c === 'scan') return send(res, 201, await runScan(id));
      if (m === 'GET' && c === 'scans') return send(res, 200, opts.store.listScans(id));
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
    throw new HttpError(404, `No route: ${m} ${path}`);
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

  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/')) await api(req, res, url.pathname);
      else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(res, url.pathname);
      else send(res, 405, 'Method not allowed');
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof Error ? err.message : String(err);
      if (status >= 500) log(`error: ${message}`);
      send(res, status, { error: message });
    }
  });
}
