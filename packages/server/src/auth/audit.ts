import type { AuthContext } from './context.ts';

/** Keys whose values never belong in an audit row. */
const SECRET_KEY = /password|secret|token|authorization|cookie|apikey|api_key|credential/i;
/** Audit detail is kept small; long strings are clipped, deep objects cut off. */
const MAX_STRING = 500;
const MAX_DEPTH = 4;

/** A copy of `value` with secret-looking keys removed and strings clipped, safe to store. */
export function scrubDetail(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= MAX_DEPTH) return '[…]';
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => scrubDetail(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY.test(k)) continue;
      out[k] = scrubDetail(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

/**
 * Record who did what. `ctx.user` may be null (a failed login, for example); `detail` is
 * scrubbed of anything that looks like a secret before it is stored.
 */
export function audit(ctx: AuthContext, action: string, target?: string | null, detail?: unknown): number {
  const user = ctx.user;
  return ctx.store.addAudit({
    userId: user && user.source !== 'open' ? user.id : null,
    username: user ? user.username : null,
    action,
    target: target ?? null,
    detail: detail === undefined ? undefined : scrubDetail(detail),
    ip: ctx.ip || null,
  });
}
