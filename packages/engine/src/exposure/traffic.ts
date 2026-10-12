import { createReadStream, existsSync, readdirSync, statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { isAbsolute, join, relative, resolve } from 'node:path';
import type { EntryPoint, ObservedTraffic, RouteTraffic, TrafficFile, TrafficSummary } from '../types.ts';

/*
 * Observed traffic: the access logs a reverse proxy, load balancer or the application itself
 * already writes, read once per scan and counted against the entry points the code analysis
 * found. Nothing is installed and nothing is sent anywhere; a line is reduced to its method,
 * path, client address and time, and only the counts survive into the report.
 *
 * Formats, detected per line: nginx/Apache "combined" and "common", AWS ALB access logs, and
 * JSON lines (Caddy, Cloudflare Logpush, Traefik, pino-http, GCP HTTP load balancer, anything
 * with a method, a path, a client address and a time under the usual key names). Lines that
 * parse as none of these are counted and ignored. Compressed rotations are not read.
 */

export interface ParsedRequest {
  method: string;
  path: string;
  /** Milliseconds since the epoch, or undefined when the line carries no usable time. */
  at?: number;
  /** Client address as written; `public` says whether it is outside private ranges. */
  ip: string;
  public: boolean;
}

export interface TrafficOptions {
  /** Days of logs to count, ending at the newest line seen (default 30). */
  windowDays?: number;
  /** The scan time, to decide whether the logs are stale (default now). */
  now?: number;
  log?: (msg: string) => void;
}

export interface TrafficResult {
  summary: TrafficSummary;
  /** Per entry point, in the order the entry points were given. */
  perEntry: RouteTraffic[];
  observed: ObservedTraffic;
}

export const DEFAULT_WINDOW_DAYS = 30;
/** A window that ends more than this many days before the scan says nothing about today's traffic. */
export const STALE_AFTER_DAYS = 30;
const DAY_MS = 86_400_000;
const LOG_NAME = /\.(log|json|jsonl|txt|ndjson)(\.\d+)?$/i;
const ANY_METHOD = new Set(['ALL', 'ANY', 'USE', '*']);

// ---------------------------------------------------------------------------------------------
// Addresses

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Private, loopback, link-local, carrier-grade NAT and unique-local addresses are "internal"; everything else is public. */
export function isPublicAddress(ip: string): boolean {
  let s = ip.trim();
  if (s.startsWith('[')) s = s.slice(1, s.indexOf(']') === -1 ? undefined : s.indexOf(']'));
  if (s.startsWith('::ffff:')) s = s.slice(7);
  const v4 = V4.exec(s);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    return a <= 223;
  }
  if (s.includes(':')) {
    const low = s.toLowerCase();
    if (low === '::1' || low === '::') return false;
    if (/^f[cd]/.test(low)) return false; // fc00::/7
    if (/^fe[89ab]/.test(low)) return false; // fe80::/10
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// Line formats

const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** `10/Oct/2026:14:22:01 +0000` (Apache/nginx) to epoch milliseconds. */
export function parseClfTime(s: string): number | undefined {
  const m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-])(\d{2})(\d{2}))?/.exec(s.trim());
  if (!m) return undefined;
  const mon = MONTHS[m[2]!.toLowerCase()];
  if (mon === undefined) return undefined;
  let t = Date.UTC(Number(m[3]), mon, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
  if (m[7]) {
    const off = (Number(m[8]) * 60 + Number(m[9])) * 60_000;
    t += m[7] === '+' ? -off : off;
  }
  return t;
}

/** Numbers are epoch seconds, milliseconds or nanoseconds by magnitude; strings go through Date.parse. */
function parseAnyTime(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) {
    if (v > 1e17) return Math.round(v / 1e6);
    if (v > 1e14) return Math.round(v / 1e3);
    if (v > 1e11) return Math.round(v);
    return Math.round(v * 1000);
  }
  if (typeof v === 'string' && v) {
    const n = Number(v);
    if (Number.isFinite(n) && /^\d+(\.\d+)?$/.test(v)) return parseAnyTime(n);
    const clf = parseClfTime(v);
    if (clf !== undefined) return clf;
    const t = Date.parse(v);
    return Number.isNaN(t) ? undefined : t;
  }
  return undefined;
}

const COMBINED = /^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)(?: [^"]*)?" (\d{3})/;
const ALB = /^(?:http|https|h2|ws|wss|grpcs?) (\S+) \S+ ([^\s:]+|\[[^\]]+\]):\d+ \S+ \S+ \S+ \S+ (\d{3}|-) \S+ \S+ \S+ "([A-Z]+) (\S+) [^"]*"/;

function firstForwarded(v: unknown): string | undefined {
  if (typeof v === 'string' && v.trim()) return v.split(',')[0]!.trim();
  if (Array.isArray(v) && typeof v[0] === 'string') return firstForwarded(v[0]);
  return undefined;
}

function pick(o: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) {
    const parts = k.split('.');
    let cur: unknown = o;
    for (const p of parts) {
      if (cur && typeof cur === 'object' && p in (cur as Record<string, unknown>)) cur = (cur as Record<string, unknown>)[p];
      else {
        cur = undefined;
        break;
      }
    }
    if (cur !== undefined && cur !== null && cur !== '') return cur;
  }
  return undefined;
}

const JSON_METHOD = ['method', 'request.method', 'req.method', 'ClientRequestMethod', 'httpRequest.requestMethod', 'RequestMethod', 'http.method', 'verb'];
const JSON_PATH = ['path', 'uri', 'url', 'request.uri', 'request.url', 'request.path', 'req.url', 'req.path', 'ClientRequestPath', 'ClientRequestURI', 'httpRequest.requestUrl', 'RequestPath', 'http.url', 'http.path', 'URI'];
const JSON_IP = ['x_forwarded_for', 'xff', 'request.headers.X-Forwarded-For', 'request.headers.x-forwarded-for', 'req.headers.x-forwarded-for', 'ClientIP', 'client_ip', 'clientIp', 'clientIP', 'remote_ip', 'remote_addr', 'remoteAddr', 'remoteIp', 'ip', 'request.remote_ip', 'request.remote_addr', 'request.client_ip', 'req.remoteAddress', 'req.ip', 'httpRequest.remoteIp', 'ClientHost', 'client', 'source_ip', 'src_ip', 'addr'];
const JSON_TIME = ['@timestamp', 'timestamp', 'time', 'ts', 'EdgeStartTimestamp', 'StartUTC', 'date', 'datetime', 'time_local', 'time_iso8601', 'msec', 'receiveTimestamp', 'start_time', 'startTime'];
const JSON_STATUS = ['status', 'status_code', 'statusCode', 'res.statusCode', 'EdgeResponseStatus', 'httpRequest.status', 'DownstreamStatus', 'response.status', 'code'];

/** Parse one line; returns the request and the format it was recognised as, or undefined. */
export function parseLine(line: string): { req: ParsedRequest; format: string } | undefined {
  const s = line.trim();
  if (!s) return undefined;
  if (s.startsWith('{')) {
    let o: unknown;
    try {
      o = JSON.parse(s);
    } catch {
      return undefined;
    }
    if (!o || typeof o !== 'object') return undefined;
    const rec = o as Record<string, unknown>;
    const method = pick(rec, JSON_METHOD);
    const path = pick(rec, JSON_PATH);
    if (typeof method !== 'string' || typeof path !== 'string') return undefined;
    const ipRaw = firstForwarded(pick(rec, JSON_IP)) ?? '';
    const ip = String(ipRaw).replace(/:\d+$/, (m) => (ipRaw.includes('.') ? '' : m));
    void pick(rec, JSON_STATUS);
    return { req: { method: method.toUpperCase(), path: cleanPath(path), at: parseAnyTime(pick(rec, JSON_TIME)), ip, public: isPublicAddress(ip) }, format: 'json' };
  }
  const alb = ALB.exec(s);
  if (alb) {
    const ip = alb[2]!.replace(/^\[|\]$/g, '');
    return { req: { method: alb[4]!, path: cleanPath(alb[5]!), at: parseAnyTime(alb[1]), ip, public: isPublicAddress(ip) }, format: 'alb' };
  }
  const c = COMBINED.exec(s);
  if (c) {
    const ip = c[1]!;
    return { req: { method: c[3]!, path: cleanPath(c[4]!), at: parseClfTime(c[2]!), ip, public: isPublicAddress(ip) }, format: 'combined' };
  }
  return undefined;
}

/** A request path without scheme/host, query or fragment, decoded, with one leading slash and no trailing one. */
export function cleanPath(raw: string): string {
  let p = raw.trim();
  const abs = /^[a-z][a-z0-9+.-]*:\/\/[^/]+(\/.*)?$/i.exec(p);
  if (abs) p = abs[1] ?? '/';
  const q = p.search(/[?#]/);
  if (q !== -1) p = p.slice(0, q);
  try {
    p = decodeURIComponent(p);
  } catch {
    /* keep as written */
  }
  if (!p.startsWith('/')) p = '/' + p;
  p = p.replace(/\/{2,}/g, '/');
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p;
}

// ---------------------------------------------------------------------------------------------
// Matching routes

interface Matcher {
  index: number;
  method: string;
  re: RegExp;
  /** Literal characters in the pattern: the more, the more specific the route. */
  weight: number;
}

/** Express, Flask, FastAPI, Django and Go route patterns as one regular expression over a cleaned path. */
export function routeRegex(pattern: string): RegExp {
  let p = pattern.trim();
  if (p.startsWith('^')) {
    // Django-style regex: strip the anchors and the optional trailing slash
    try {
      p = p.replace(/\$$/, '').replace(/\/?$/, '').replace(/\(\?P</g, '(?<');
      return new RegExp(`^/?${p.slice(1)}/?$`);
    } catch {
      return /$^/;
    }
  }
  if (!p.startsWith('/')) p = '/' + p;
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  let out = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i]!;
    if (ch === ':' && /[A-Za-z_]/.test(p[i + 1] ?? '')) {
      let j = i + 1;
      while (j < p.length && /[A-Za-z0-9_]/.test(p[j]!)) j++;
      const optional = p[j] === '?';
      if (optional) j++;
      out = optional && out.endsWith('/') ? out.slice(0, -1) + '(?:/[^/]+)?' : out + '[^/]+';
      i = j - 1;
      continue;
    }
    if (ch === '{' || ch === '<') {
      const close = p.indexOf(ch === '{' ? '}' : '>', i);
      if (close !== -1) {
        const inner = p.slice(i + 1, close);
        const greedy = /path/i.test(inner) || inner.endsWith('*') || inner.includes(':.*');
        out += greedy ? '.+' : '[^/]+';
        i = close;
        continue;
      }
    }
    if (ch === '*') {
      out += '.*';
      continue;
    }
    if (ch === '(' ) {
      // Express-style inline regex group: keep up to the matching paren as-is
      const close = p.indexOf(')', i);
      if (close !== -1) {
        out += p.slice(i, close + 1);
        i = close;
        continue;
      }
    }
    out += /[.+?^$|\\[\]]/.test(ch) ? '\\' + ch : ch;
  }
  try {
    return new RegExp(`^${out}$`, 'i');
  } catch {
    return /$^/;
  }
}

function literalWeight(pattern: string): number {
  return pattern.replace(/:[A-Za-z0-9_]+\??|\{[^}]*\}|<[^>]*>|\*|\([^)]*\)/g, '').length;
}

export function buildMatchers(entries: EntryPoint[]): Matcher[] {
  return entries
    .map((e, index) => ({ index, method: e.method.toUpperCase(), re: routeRegex(e.path), weight: literalWeight(e.path) }))
    .sort((a, b) => b.weight - a.weight);
}

/** The most specific entry point whose method and pattern match; undefined when none does. */
export function matchRoute(matchers: Matcher[], method: string, path: string): number | undefined {
  let best: Matcher | undefined;
  for (const m of matchers) {
    if (best && m.weight < best.weight) break;
    const methodOk = m.method === method || ANY_METHOD.has(m.method) || (method === 'HEAD' && m.method === 'GET');
    if (!methodOk || !m.re.test(path)) continue;
    if (!best || (ANY_METHOD.has(best.method) && !ANY_METHOD.has(m.method))) best = m;
  }
  return best?.index;
}

// ---------------------------------------------------------------------------------------------
// Files

/** Expand the configured sources: a file as given, a directory to its log-looking files (one level). */
export function expandSources(rootDir: string, sources: string[]): { path: string; problem?: string }[] {
  const out: { path: string; problem?: string }[] = [];
  const seen = new Set<string>();
  for (const src of sources) {
    const abs = isAbsolute(src) ? src : resolve(rootDir, src);
    if (!existsSync(abs)) {
      out.push({ path: abs, problem: 'not found' });
      continue;
    }
    let st;
    try {
      st = statSync(abs);
    } catch (err) {
      out.push({ path: abs, problem: err instanceof Error ? err.message : String(err) });
      continue;
    }
    if (st.isDirectory()) {
      const names = readdirSync(abs).filter((n) => LOG_NAME.test(n) && !n.endsWith('.gz')).sort();
      if (!names.length) out.push({ path: abs, problem: 'no .log, .json or .txt files in the folder' });
      for (const n of names) {
        const p = join(abs, n);
        if (!seen.has(p)) {
          seen.add(p);
          out.push({ path: p });
        }
      }
    } else if (!seen.has(abs)) {
      seen.add(abs);
      if (/\.gz$/i.test(abs)) out.push({ path: abs, problem: 'compressed logs are not read; point at the uncompressed file' });
      else out.push({ path: abs });
    }
  }
  return out;
}

interface Counted {
  requests: number;
  public: number;
  internal: number;
  first?: number;
  last?: number;
}

/**
 * Read every source and count requests per entry point inside the window. Two passes are avoided
 * by keeping only (entry, time, public) triples: counts are settled once the newest time is known.
 */
export async function observeTraffic(rootDir: string, sources: string[], entries: EntryPoint[], opts: TrafficOptions = {}): Promise<TrafficResult> {
  const log = opts.log ?? (() => {});
  const windowDays = opts.windowDays ?? DEFAULT_WINDOW_DAYS;
  const now = opts.now ?? Date.now();
  const matchers = buildMatchers(entries);
  const files: TrafficFile[] = [];
  // Entry index (-1 = unmatched), time, public flag; compact enough for millions of lines.
  const hits: { entry: number; at: number; pub: boolean }[] = [];
  let newest = 0;
  let untimed = 0;

  for (const src of expandSources(rootDir, sources)) {
    const shown = relative(rootDir, src.path).startsWith('..') ? src.path : relative(rootDir, src.path) || src.path;
    if (src.problem) {
      log(`Traffic: ${shown}: ${src.problem}`);
      files.push({ path: shown, format: 'unreadable', lines: 0, parsed: 0, matched: 0 });
      continue;
    }
    const file: TrafficFile = { path: shown, format: 'unknown', lines: 0, parsed: 0, matched: 0 };
    const formats = new Map<string, number>();
    try {
      const rl = createInterface({ input: createReadStream(src.path, { encoding: 'utf8' }), crlfDelay: Infinity });
      for await (const line of rl) {
        file.lines++;
        const parsed = parseLine(line);
        if (!parsed) continue;
        file.parsed++;
        formats.set(parsed.format, (formats.get(parsed.format) ?? 0) + 1);
        const at = parsed.req.at ?? -1;
        if (at < 0) untimed++;
        if (at > newest) newest = at;
        const entry = matchRoute(matchers, parsed.req.method, parsed.req.path);
        if (entry !== undefined) file.matched++;
        hits.push({ entry: entry ?? -1, at, pub: parsed.req.public });
      }
    } catch (err) {
      log(`Traffic: ${shown}: ${err instanceof Error ? err.message : String(err)}`);
      file.format = 'unreadable';
    }
    if (formats.size) file.format = [...formats.entries()].sort((a, b) => b[1] - a[1])[0]![0];
    files.push(file);
    log(`Traffic: ${shown}: ${file.lines} lines, ${file.parsed} requests (${file.format}), ${file.matched} on known routes`);
  }

  // Window: the last `windowDays` ending at the newest line. Lines without a time count as inside it.
  const to = newest || now;
  const from = to - windowDays * DAY_MS;
  const counts: Counted[] = entries.map(() => ({ requests: 0, public: 0, internal: 0 }));
  let requests = 0;
  let pub = 0;
  let internal = 0;
  let unmatched = 0;
  for (const h of hits) {
    if (h.at >= 0 && h.at < from) continue;
    requests++;
    if (h.pub) pub++;
    else internal++;
    if (h.entry < 0) {
      unmatched++;
      continue;
    }
    const c = counts[h.entry]!;
    c.requests++;
    if (h.pub) c.public++;
    else c.internal++;
    if (h.at >= 0) {
      if (c.first === undefined || h.at < c.first) c.first = h.at;
      if (c.last === undefined || h.at > c.last) c.last = h.at;
    }
  }
  const perEntry: RouteTraffic[] = counts.map((c) => ({ requests: c.requests, public: c.public, internal: c.internal, firstSeenAt: c.first !== undefined ? new Date(c.first).toISOString() : undefined, lastSeenAt: c.last !== undefined ? new Date(c.last).toISOString() : undefined }));
  const routesSeen = perEntry.filter((t) => t.requests > 0).length;
  const stale = newest > 0 && now - newest > STALE_AFTER_DAYS * DAY_MS;
  const haveLines = hits.length > 0;
  const summary: TrafficSummary = {
    files,
    windowDays,
    from: haveLines ? new Date(from).toISOString() : undefined,
    to: haveLines ? new Date(to).toISOString() : undefined,
    requests,
    public: pub,
    internal,
    unmatched,
    routesSeen,
    routesCold: entries.length - routesSeen,
    stale,
  };
  if (haveLines) log(`Traffic: ${requests} requests in the ${windowDays} days to ${new Date(to).toISOString().slice(0, 10)} (${pub} from public addresses); ${routesSeen} of ${entries.length} routes seen${stale ? '; the logs end more than a month before this scan' : ''}${untimed ? `; ${untimed} lines without a time counted as current` : ''}`);
  else log('Traffic: no requests could be read from the configured logs');
  const observed: ObservedTraffic = { public: pub, internal, days: windowDays, to: new Date(to).toISOString(), stale, routesSeen };
  return { summary, perEntry, observed };
}
