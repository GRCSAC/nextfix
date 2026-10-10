import { DatabaseSync } from 'node:sqlite';
import { FeatureError, settingsFor } from './core.ts';
import type { Method, Role, Route, RouteUser, SettingsAccess } from './core.ts';
import * as exceptions from './exceptions.ts';
import * as portfolio from './portfolio.ts';
import * as schedule from './schedule.ts';
import * as digest from './digest.ts';

/*
 * The feature modules side by side: their migrations in order, their routes, and the adapter
 * that turns a feature route into the server's route shape. index.ts imports this and registers
 * the routes; tests import it without touching the server.
 */

/** Migrations in the order they must be appended to the store's list (versions 4 to 7 after the auth schema). */
export function featureMigrations(): string[] {
  return [...exceptions.migrations, ...portfolio.migrations, ...schedule.migrations, ...digest.migrations];
}

/** Every feature route, in match order. */
export function featureRoutes(): Route[] {
  return [...exceptions.routes, ...portfolio.routes, ...schedule.routes, ...digest.routes];
}

/**
 * Apply the feature migrations to a database that already has the store's schema. CREATE
 * statements are idempotent; an ALTER TABLE that already ran is skipped by its duplicate-column
 * error. Once the store carries these versions itself this is a no-op.
 */
export function applyFeatureMigrations(db: DatabaseSync): void {
  for (const sql of featureMigrations()) {
    for (const stmt of sql.split(';').map((s) => s.trim()).filter(Boolean)) {
      try {
        db.exec(stmt);
      } catch (err) {
        if (!/duplicate column name/i.test(err instanceof Error ? err.message : String(err))) throw err;
      }
    }
  }
}

/**
 * The part of the server's route context the adapter uses (structural, so this file does not
 * import the auth module). `store.path` locates the database the features open their own handle on.
 */
export interface ServerRouteContext {
  user: RouteUser | null;
  params: Record<string, string>;
  query: URLSearchParams;
  store: { path: string };
  log: (msg: string) => void;
  readJson<T = Record<string, unknown>>(): Promise<T>;
  send(status: number, body: unknown, headers?: Record<string, string | string[]>): void;
  audit(action: string, target?: string | null, detail?: unknown): void;
}

export interface ServerRoute {
  method: Method;
  /** The path under /api. */
  path: string;
  role: Role;
  /** API tokens may call read-only routes with the `read` scope; mutating routes are session-only. */
  scope?: 'read';
  handler: (ctx: ServerRouteContext) => unknown;
}

const handles = new Map<string, DatabaseSync>();

/** One handle per database file, feature tables ensured on first use. The store's own handle stays private to it. */
export function featureDb(path: string): DatabaseSync {
  let db = handles.get(path);
  if (!db) {
    db = new DatabaseSync(path);
    db.exec('PRAGMA foreign_keys = ON');
    db.exec('PRAGMA busy_timeout = 5000');
    applyFeatureMigrations(db);
    handles.set(path, db);
  }
  return db;
}

/** Close the handles featureDb() opened (tests, shutdown). */
export function closeFeatureDbs(): void {
  for (const db of handles.values()) db.close();
  handles.clear();
}

/**
 * Feature routes in the server's route shape: the pattern loses its /api prefix, the body is read
 * for mutating methods, the query becomes a plain object, and a status other than 200 is sent
 * through ctx.send. Errors stay FeatureError (status + message) for the server's error handler.
 */
export interface AdapterDeps {
  db?: DatabaseSync;
  settings?: SettingsAccess;
  /** Converts a FeatureError into the error class the server's handler maps to a status (its HttpError). */
  mapError?: (err: FeatureError) => Error;
}

export function toServerRoutes(routes: Route[], deps: AdapterDeps = {}): ServerRoute[] {
  return routes.map((r) => ({
    method: r.method,
    path: r.pattern.replace(/^\/api/, ''),
    role: r.role,
    scope: r.method === 'GET' ? 'read' : undefined,
    async handler(ctx: ServerRouteContext) {
      const db = deps.db ?? featureDb(ctx.store.path);
      const settings = deps.settings ?? settingsFor(db);
      const body = r.method === 'GET' ? {} : await ctx.readJson();
      const query: Record<string, string> = {};
      ctx.query.forEach((v, k) => {
        if (!(k in query)) query[k] = v;
      });
      let result;
      try {
        result = await r.handler({ db, params: ctx.params, query, body, user: ctx.user, audit: (a, t, d) => ctx.audit(a, t, d), settings, log: ctx.log });
      } catch (err) {
        if (err instanceof FeatureError && deps.mapError) throw deps.mapError(err);
        throw err;
      }
      const status = result.status ?? 200;
      if (status === 200) return result.body ?? {};
      ctx.send(status, status === 204 ? '' : result.body);
      return undefined;
    },
  }));
}

export { exceptions, portfolio, schedule, digest };
