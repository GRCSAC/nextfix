import { createHash, randomBytes } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { TLSSocket } from 'node:tls';
import type { Store } from '../store.ts';
import type { AuthUser } from './context.ts';

export const SESSION_COOKIE = 'nextfix_session';
/** A session ends after this long without a request. */
export const SESSION_IDLE_MS = 12 * 60 * 60_000;
/** And after this long regardless. */
export const SESSION_ABSOLUTE_MS = 7 * 24 * 60 * 60_000;
/** last_seen_at is written at most this often, so a busy dashboard does not write on every request. */
const TOUCH_MS = 60_000;

export function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (!name) continue;
    out[name] = part.slice(eq + 1).trim();
  }
  return out;
}

/** True when the request itself arrived over TLS or a proxy in front says it did. */
export function isHttps(req: IncomingMessage): boolean {
  if ((req.socket as TLSSocket).encrypted) return true;
  const proto = String(req.headers['x-forwarded-proto'] ?? '').split(',')[0]!.trim().toLowerCase();
  return proto === 'https';
}

/** The peer's address, with the IPv4-mapped IPv6 prefix removed. */
export function clientIp(req: IncomingMessage): string {
  const addr = req.socket.remoteAddress ?? '';
  return addr.startsWith('::ffff:') ? addr.slice(7) : addr;
}

export function isLoopbackAddress(addr: string): boolean {
  const a = addr.startsWith('::ffff:') ? addr.slice(7) : addr;
  return a === '::1' || a === '127.0.0.1' || /^127\.\d+\.\d+\.\d+$/.test(a);
}

export function serializeCookie(name: string, value: string, opts: { maxAge: number; secure: boolean; sameSite?: 'Lax' | 'Strict' }): string {
  const parts = [`${name}=${value}`, 'Path=/', 'HttpOnly', `SameSite=${opts.sameSite ?? 'Lax'}`, `Max-Age=${opts.maxAge}`];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

export function clearCookie(name: string, secure: boolean): string {
  return serializeCookie(name, '', { maxAge: 0, secure });
}

/** Start a session for a user. Returns the cookie value (the raw id) and the Set-Cookie header. */
export function createSession(store: Store, userId: number, req: IncomingMessage, secure: boolean, now = Date.now()): { id: string; hash: string; cookie: string } {
  const id = randomBytes(32).toString('base64url');
  const hash = sha256(id);
  store.createSession({ id: hash, userId, expiresAt: new Date(now + SESSION_ABSOLUTE_MS).toISOString(), ip: clientIp(req) || null, userAgent: String(req.headers['user-agent'] ?? '').slice(0, 300) || null });
  return { id, hash, cookie: serializeCookie(SESSION_COOKIE, id, { maxAge: Math.floor(SESSION_ABSOLUTE_MS / 1000), secure }) };
}

/** The session cookie's raw value, if any. */
export function sessionIdFrom(req: IncomingMessage): string | undefined {
  const raw = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  return raw && /^[A-Za-z0-9_-]{40,50}$/.test(raw) ? raw : undefined;
}

/** The user behind the request's session cookie, or null. Expired, idle and disabled sessions are dropped on sight. */
export function resolveSession(store: Store, req: IncomingMessage, now = Date.now()): { user: AuthUser; hash: string } | null {
  const id = sessionIdFrom(req);
  if (!id) return null;
  const hash = sha256(id);
  const session = store.getSession(hash);
  if (!session) return null;
  if (Date.parse(session.expiresAt) <= now || Date.parse(session.lastSeenAt) + SESSION_IDLE_MS <= now) {
    store.deleteSession(hash);
    return null;
  }
  const user = store.getUser(session.userId);
  if (!user || user.disabled) {
    store.deleteSession(hash);
    return null;
  }
  if (now - Date.parse(session.lastSeenAt) >= TOUCH_MS) store.touchSession(hash, new Date(now).toISOString());
  return { user: { id: user.id, username: user.username, displayName: user.displayName, role: user.role, source: user.source }, hash };
}

/** End the request's session, if it has one. */
export function destroySession(store: Store, req: IncomingMessage): boolean {
  const id = sessionIdFrom(req);
  if (!id) return false;
  const hash = sha256(id);
  const existed = !!store.getSession(hash);
  store.deleteSession(hash);
  return existed;
}
