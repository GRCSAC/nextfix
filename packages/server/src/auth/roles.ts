import { HttpError, type AuthUser, type HttpMethod, type Role, type TokenScope } from './context.ts';

export const ROLES: Role[] = ['viewer', 'analyst', 'admin'];
const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

export function isRole(x: unknown): x is Role {
  return x === 'admin' || x === 'analyst' || x === 'viewer';
}

export function roleAtLeast(have: Role, need: Role): boolean {
  return RANK[have] >= RANK[need];
}

/** The role an API token acts with: scan or tickets make it an analyst for those routes, read alone a viewer. */
export function roleForScopes(scopes: TokenScope[]): Role {
  return scopes.includes('scan') || scopes.includes('tickets') ? 'analyst' : 'viewer';
}

/** Access rule for one route: who may call it and whether API tokens can. */
export interface RoutePolicy {
  method: HttpMethod;
  pattern: string;
  role?: Role;
  scope?: TokenScope;
  public?: boolean;
}

/**
 * Who may call each built-in route. Every route the server serves is listed here; a path that
 * matches nothing is a 404 before authentication. Viewers read, analysts run scans and create
 * tickets, admins manage users, tokens, settings, integrations and targets.
 */
export const BUILTIN_POLICY: RoutePolicy[] = [
  { method: 'GET', pattern: '/health', public: true },
  { method: 'GET', pattern: '/session', public: true },
  { method: 'POST', pattern: '/setup', public: true },
  { method: 'POST', pattern: '/login', public: true },
  { method: 'POST', pattern: '/logout', public: true },
  { method: 'POST', pattern: '/shutdown', role: 'admin' },
  { method: 'GET', pattern: '/auth/oidc/:provider/start', public: true },
  { method: 'GET', pattern: '/auth/oidc/:provider/callback', public: true },

  { method: 'GET', pattern: '/scan/progress', role: 'viewer', scope: 'read' },
  { method: 'DELETE', pattern: '/scan', role: 'analyst', scope: 'scan' },

  { method: 'GET', pattern: '/settings', role: 'viewer', scope: 'read' },
  { method: 'PUT', pattern: '/settings', role: 'admin' },
  { method: 'GET', pattern: '/settings/oidc', role: 'admin' },
  { method: 'PUT', pattern: '/settings/oidc', role: 'admin' },

  { method: 'GET', pattern: '/targets', role: 'viewer', scope: 'read' },
  { method: 'POST', pattern: '/targets', role: 'analyst', scope: 'scan' },
  { method: 'DELETE', pattern: '/targets/:id', role: 'admin' },
  { method: 'POST', pattern: '/targets/:id/scan', role: 'analyst', scope: 'scan' },
  { method: 'GET', pattern: '/targets/:id/scans', role: 'viewer', scope: 'read' },
  { method: 'GET', pattern: '/targets/:id/history', role: 'viewer', scope: 'read' },
  { method: 'POST', pattern: '/targets/:id/redecide', role: 'analyst', scope: 'scan' },
  { method: 'GET', pattern: '/targets/:id/tickets', role: 'viewer', scope: 'read' },
  { method: 'POST', pattern: '/targets/:id/tickets', role: 'analyst', scope: 'tickets' },

  { method: 'GET', pattern: '/integrations', role: 'viewer', scope: 'read' },
  { method: 'PUT', pattern: '/integrations/:kind', role: 'admin' },
  { method: 'DELETE', pattern: '/integrations/:kind', role: 'admin' },
  { method: 'POST', pattern: '/integrations/:kind/test', role: 'admin' },

  { method: 'GET', pattern: '/scans/:id', role: 'viewer', scope: 'read' },
  { method: 'GET', pattern: '/scans/:id/json', role: 'viewer', scope: 'read' },
  { method: 'GET', pattern: '/scans/:id/findings/*', role: 'viewer', scope: 'read' },
  { method: 'GET', pattern: '/scans/:id/diff', role: 'viewer', scope: 'read' },
  { method: 'GET', pattern: '/scans/:id/vex', role: 'viewer', scope: 'read' },

  { method: 'GET', pattern: '/users', role: 'admin' },
  { method: 'POST', pattern: '/users', role: 'admin' },
  { method: 'PATCH', pattern: '/users/:id', role: 'admin' },
  // Admins reset anyone's password; a user changes their own with the current one. The handler decides.
  { method: 'POST', pattern: '/users/:id/password', role: 'viewer' },
  { method: 'DELETE', pattern: '/users/:id', role: 'admin' },
  { method: 'GET', pattern: '/tokens', role: 'admin' },
  { method: 'POST', pattern: '/tokens', role: 'admin' },
  { method: 'DELETE', pattern: '/tokens/:id', role: 'admin' },
  { method: 'GET', pattern: '/audit', role: 'admin' },
];

/** Match `/a/:b/*` style patterns against path segments; returns the captures or undefined. */
export function matchPattern(pattern: string, segments: string[]): Record<string, string> | undefined {
  const want = pattern.split('/').filter(Boolean);
  const params: Record<string, string> = {};
  for (let i = 0; i < want.length; i++) {
    const w = want[i]!;
    if (w === '*') {
      if (i !== want.length - 1) return undefined;
      params['*'] = segments.slice(i).join('/');
      return params;
    }
    const got = segments[i];
    if (got === undefined) return undefined;
    if (w.startsWith(':')) params[w.slice(1)] = got;
    else if (w !== got) return undefined;
  }
  return segments.length === want.length ? params : undefined;
}

export function findPolicy<T extends RoutePolicy>(policies: T[], method: HttpMethod, segments: string[]): { policy: T; params: Record<string, string> } | undefined {
  for (const policy of policies) {
    if (policy.method !== method) continue;
    const params = matchPattern(policy.pattern, segments);
    if (params) return { policy, params };
  }
  return undefined;
}

/** Throw 401 or 403 unless `user` holds at least `role`; the message says what was missing. */
export function requireRole(ctx: { user: AuthUser | null }, role: Role): AuthUser {
  const user = ctx.user;
  if (!user) throw new HttpError(401, 'Sign in to use this');
  if (!roleAtLeast(user.role, role)) {
    if (user.source === 'token') throw new HttpError(403, `This API token cannot do that; it needs a scope that grants the ${role} role`);
    throw new HttpError(403, `This needs the ${role} role; you are signed in as a ${user.role}`);
  }
  return user;
}

/** Apply a route's policy to the caller: public passes, tokens need the route's scope, people need the role. */
export function authorize(user: AuthUser | null, policy: RoutePolicy): void {
  if (policy.public) return;
  if (!user) throw new HttpError(401, 'Sign in to use this');
  if (user.source === 'token') {
    if (!policy.scope) throw new HttpError(403, 'API tokens cannot use this route; sign in as an admin');
    if (!user.scopes?.includes(policy.scope)) throw new HttpError(403, `This API token does not have the ${policy.scope} scope`);
    return;
  }
  requireRole({ user }, policy.role ?? 'viewer');
}
