import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Role, Store, UserSource } from '../store.ts';

export type { Role, UserSource };

/** What an API token may do. `read` covers every GET; `scan` and `tickets` the matching POSTs. */
export type TokenScope = 'read' | 'scan' | 'tickets';
export const TOKEN_SCOPES: TokenScope[] = ['read', 'scan', 'tickets'];

export type AuthMode = 'none' | 'local' | 'oidc';

/** An error that becomes an HTTP response: the status, a one-sentence message and optional headers. */
export class HttpError extends Error {
  status: number;
  headers: Record<string, string>;
  constructor(status: number, message: string, headers: Record<string, string> = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

/**
 * Who is making the request. `source` is `token` for an API token (role derived from its
 * scopes) and `open` when the server runs without accounts (first-run setup or --allow-open).
 */
export interface AuthUser {
  id: number;
  username: string;
  displayName: string;
  role: Role;
  source: UserSource | 'token' | 'open';
  scopes?: TokenScope[];
  tokenId?: number;
}

/** The part of a request context the auth helpers need. */
export interface AuthContext {
  user: AuthUser | null;
  ip: string;
  store: Store;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** What a route handler gets: the request, who is calling, the store, and helpers to answer, audit and gate by role. */
export interface RouteContext extends AuthContext {
  req: IncomingMessage;
  res: ServerResponse;
  method: HttpMethod;
  /** The path under /api, e.g. `/exceptions/12`. */
  path: string;
  /** Captured `:name` and `*` segments of the matched pattern. */
  params: Record<string, string>;
  query: URLSearchParams;
  log: (msg: string) => void;
  /** The JSON object body (400 when it is not one, 413 when too large). */
  readJson<T = Record<string, unknown>>(): Promise<T>;
  /** Write the response: JSON for objects, text for strings; gzip when it pays off. */
  send(status: number, body: unknown, headers?: Record<string, string | string[]>): void;
  /** Append an audit row attributed to the caller. Keys that look like secrets are dropped from `detail`. */
  audit(action: string, target?: string | null, detail?: unknown): void;
  /** Throw 401/403 unless the caller holds at least `role`; returns the caller. */
  requireRole(role: Role): AuthUser;
}

/** A route a feature module adds. Patterns are matched against the path under /api; built-in routes take precedence. */
export interface Route {
  method: HttpMethod;
  /** `/exceptions`, `/exceptions/:id`, `/files/*` (a trailing `*` captures the rest as `params['*']`). */
  path: string;
  /** Lowest role that may call it; omitted means any signed-in user (viewer). */
  role?: Role;
  /** The API-token scope that may call it; omitted means API tokens are refused. */
  scope?: TokenScope;
  /** Reachable without signing in (the server still applies its Host and Origin checks). */
  public?: boolean;
  /** Return a value to send it as JSON with 200, call `ctx.send` yourself, or return nothing for 204. */
  handler: (ctx: RouteContext) => unknown;
}
