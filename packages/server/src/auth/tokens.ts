import { randomInt } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { Store } from '../store.ts';
import { HttpError, TOKEN_SCOPES, type AuthUser, type TokenScope } from './context.ts';
import { roleForScopes } from './roles.ts';
import { sha256 } from './sessions.ts';

export const TOKEN_PREFIX = 'nfx_';
const TOKEN_BODY_LENGTH = 40;
const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const TOKEN_SHAPE = /^nfx_[A-Za-z0-9]{40}$/;
/** last_used_at is written at most this often per token. */
const TOUCH_MS = 60_000;

/** A fresh token (`nfx_` + 40 base62 characters) and the hash the database keeps. */
export function generateToken(): { token: string; hash: string } {
  let body = '';
  for (let i = 0; i < TOKEN_BODY_LENGTH; i++) body += BASE62[randomInt(BASE62.length)];
  const token = TOKEN_PREFIX + body;
  return { token, hash: sha256(token) };
}

export function parseScopes(raw: unknown): TokenScope[] {
  if (!Array.isArray(raw) || !raw.length) throw new HttpError(400, `scopes must be a non-empty list of ${TOKEN_SCOPES.join(', ')}`);
  const out: TokenScope[] = [];
  for (const s of raw) {
    if (!TOKEN_SCOPES.includes(s as TokenScope)) throw new HttpError(400, `Unknown scope ${typeof s === 'string' ? s.slice(0, 40) : typeof s}; use ${TOKEN_SCOPES.join(', ')}`);
    if (!out.includes(s as TokenScope)) out.push(s as TokenScope);
  }
  return out;
}

/** The bearer token on the request, if the Authorization header carries one. */
export function bearerFrom(req: IncomingMessage): string | undefined {
  const h = req.headers.authorization;
  if (!h) return undefined;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(h);
  return m ? m[1] : undefined;
}

/**
 * The synthetic user for an API token on the request, null when there is none, and 401 when
 * one is presented but unknown. Tokens act with the role their scopes imply.
 */
export function resolveToken(store: Store, req: IncomingMessage, now = Date.now()): AuthUser | null {
  const token = bearerFrom(req);
  if (token === undefined) return null;
  if (!TOKEN_SHAPE.test(token)) throw new HttpError(401, 'That is not a NextFix API token');
  const row = store.getTokenByHash(sha256(token));
  if (!row) throw new HttpError(401, 'Unknown or revoked API token');
  const scopes = row.scopes.filter((s): s is TokenScope => TOKEN_SCOPES.includes(s as TokenScope));
  if (!row.lastUsedAt || now - Date.parse(row.lastUsedAt) >= TOUCH_MS) store.touchToken(row.id, new Date(now).toISOString());
  return { id: -row.id, username: `token:${row.name}`, displayName: row.name, role: roleForScopes(scopes), source: 'token', scopes, tokenId: row.id };
}
