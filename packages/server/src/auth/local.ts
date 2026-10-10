import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { HttpError } from './context.ts';
import type { Store } from '../store.ts';

/** scrypt parameters; recorded in each hash so they can change later without invalidating old ones. */
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_BYTES = 64;
const SALT_BYTES = 32;

export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 1024;
export const USERNAME_MAX = 64;
export const LOCKOUT_ATTEMPTS = 5;
export const LOCKOUT_MS = 15 * 60_000;

function scryptAsync(password: string, salt: Buffer, N: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KEY_BYTES, { N, r, p, maxmem: 128 * N * r * 2 }, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/** `scrypt$N$r$p$salt$hash`, salt and hash base64. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const key = await scryptAsync(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P);
  return ['scrypt', SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.toString('base64'), key.toString('base64')].join('$');
}

let dummyHash: Promise<string> | undefined;
/** A hash to verify against when the user does not exist, so a missing user costs the same time as a wrong password. */
function dummy(): Promise<string> {
  dummyHash ??= hashPassword(randomBytes(16).toString('hex'));
  return dummyHash;
}

/** Constant-time check of a password against a stored hash; a missing or malformed hash always fails after the usual work. */
export async function verifyPassword(password: string, stored: string | null | undefined): Promise<boolean> {
  const parts = (stored ?? (await dummy())).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (![N, r, p].every((n) => Number.isInteger(n) && n > 0)) return false;
  const salt = Buffer.from(parts[4]!, 'base64');
  const expected = Buffer.from(parts[5]!, 'base64');
  const key = await scryptAsync(password, salt, N, r, p);
  const same = key.length === expected.length && timingSafeEqual(key, expected);
  return same && stored !== undefined && stored !== null;
}

/** Usernames are short, lowercase and e-mail-safe, so an OIDC e-mail address is a valid username. */
export function normalizeUsername(raw: unknown): string {
  if (typeof raw !== 'string') throw new HttpError(400, 'username must be a string');
  const name = raw.trim().toLowerCase();
  if (!name || name.length > USERNAME_MAX) throw new HttpError(400, `username must be 1 to ${USERNAME_MAX} characters`);
  if (!/^[a-z0-9][a-z0-9._@+-]*$/.test(name)) throw new HttpError(400, 'username may contain letters, digits, dots, underscores, @, + and hyphens');
  return name;
}

export function checkPassword(raw: unknown): string {
  if (typeof raw !== 'string') throw new HttpError(400, 'password must be a string');
  if (raw.length < PASSWORD_MIN) throw new HttpError(400, `password must be at least ${PASSWORD_MIN} characters`);
  if (raw.length > PASSWORD_MAX) throw new HttpError(400, `password must be at most ${PASSWORD_MAX} characters`);
  return raw;
}

export function displayNameOf(raw: unknown, fallback: string): string {
  if (raw === undefined || raw === null || raw === '') return fallback;
  if (typeof raw !== 'string') throw new HttpError(400, 'displayName must be a string');
  const name = raw.trim();
  if (!name || name.length > 120) throw new HttpError(400, 'displayName must be 1 to 120 characters');
  return name;
}

/**
 * When a username is locked out, the time (ms since epoch) the lock lifts; otherwise undefined.
 * Five failures inside fifteen minutes lock the name until the oldest of those five ages out.
 */
export function lockedUntil(store: Store, username: string, now = Date.now()): number | undefined {
  const failures = store.loginFailures(username, new Date(now - LOCKOUT_MS).toISOString());
  if (failures.length < LOCKOUT_ATTEMPTS) return undefined;
  const fifth = Date.parse(failures[LOCKOUT_ATTEMPTS - 1]!);
  const until = fifth + LOCKOUT_MS;
  return until > now ? until : undefined;
}

/** The 429 a locked-out login gets, with Retry-After in whole seconds. */
export function lockoutError(until: number, now = Date.now()): HttpError {
  const seconds = Math.max(1, Math.ceil((until - now) / 1000));
  return new HttpError(429, `Too many failed sign-ins; try again in ${Math.ceil(seconds / 60)} minute${seconds > 60 ? 's' : ''}`, { 'retry-after': String(seconds) });
}
