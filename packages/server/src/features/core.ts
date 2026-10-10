import type { DatabaseSync } from 'node:sqlite';

/* Types and helpers every feature module shares; index.ts re-exports them and adds the aggregates. */

export type Role = 'viewer' | 'analyst' | 'admin';
export type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface RouteUser {
  id: number;
  username: string;
  role: Role;
}

/** Settings as the features read them: the store's `settings` table, values JSON-encoded. */
export interface SettingsAccess {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
}

/** What the server hands a feature route. */
export interface RouteContext {
  db: DatabaseSync;
  /** Path parameters from the route pattern, e.g. { id: '3' } for /api/targets/:id. */
  params: Record<string, string>;
  /** Query string, first value per key. */
  query: Record<string, string>;
  /** Parsed JSON body ({} for GET). */
  body: Record<string, unknown>;
  /** The signed-in user; null while auth is not wired or for anonymous viewers. */
  user: RouteUser | null;
  /** Append to the audit log: action ('exception.propose'), target ('target:3/finding:…'), free-form detail. */
  audit(action: string, target: string, detail?: unknown): void;
  settings: SettingsAccess;
  log(msg: string): void;
}

export interface RouteResult {
  /** Defaults to 200; 204 sends no body. */
  status?: number;
  body?: unknown;
}

export interface Route {
  method: Method;
  /** `/api/targets/:id/exceptions`: a `:name` segment matches one path segment. */
  pattern: string;
  /** Lowest role allowed; the server enforces it before calling the handler. */
  role: Role;
  handler(ctx: RouteContext): Promise<RouteResult> | RouteResult;
}

/** An error with the HTTP status the server should answer with. */
export class FeatureError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** The rank of each role; a user may call a route whose role ranks at or below theirs. */
export const ROLE_RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

export function roleAllows(user: RouteUser | null, required: Role): boolean {
  const have = user?.role ?? 'viewer';
  return ROLE_RANK[have] >= ROLE_RANK[required];
}

/** Match a request against a route pattern; the params are decoded path segments. */
export function matchPattern(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split('/').filter(Boolean);
  const s = path.split('/').filter(Boolean);
  if (p.length !== s.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < p.length; i++) {
    const seg = p[i]!;
    if (seg.startsWith(':')) params[seg.slice(1)] = decodeURIComponent(s[i]!);
    else if (seg !== s[i]) return null;
  }
  return params;
}

/** The first route whose method and pattern match; `methodMismatch` tells 404 from 405 apart. */
export function findRoute(routes: Route[], method: string, path: string): { route: Route; params: Record<string, string> } | { route?: undefined; methodMismatch: boolean } {
  let methodMismatch = false;
  for (const route of routes) {
    const params = matchPattern(route.pattern, path);
    if (!params) continue;
    if (route.method === method) return { route, params };
    methodMismatch = true;
  }
  return { methodMismatch };
}

/** Settings access over the store's `settings` table (numbers were stored as plain text, which JSON also reads). */
export function settingsFor(db: DatabaseSync): SettingsAccess {
  return {
    get(key) {
      const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
      if (!r) return undefined;
      try {
        return JSON.parse(r.value) as unknown;
      } catch {
        return r.value;
      }
    },
    set(key, value) {
      db.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').run(key, JSON.stringify(value), new Date().toISOString());
    },
  };
}

/** A context for tests and for callers that run a handler outside the HTTP server. */
export function makeContext(db: DatabaseSync, partial: Partial<RouteContext> = {}): RouteContext {
  return {
    db,
    params: {},
    query: {},
    body: {},
    user: null,
    audit: () => {},
    settings: settingsFor(db),
    log: () => {},
    ...partial,
  };
}

/** Dispatch one request through the feature routes (role check included), the way the server will. */
export async function dispatch(routes: Route[], method: Method, path: string, ctx: Omit<RouteContext, 'params'> & { params?: Record<string, string> }): Promise<RouteResult> {
  const found = findRoute(routes, method, path);
  if (!found.route) throw new FeatureError(found.methodMismatch ? 405 : 404, `No route: ${method} ${path}`);
  if (!roleAllows(ctx.user, found.route.role)) throw new FeatureError(ctx.user ? 403 : 401, `${found.route.role} role required`);
  const result = await found.route.handler({ ...ctx, params: found.params });
  return { status: result.status ?? 200, body: result.body };
}
