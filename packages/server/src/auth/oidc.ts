import { createHash, createHmac, randomBytes, timingSafeEqual, webcrypto } from 'node:crypto';
import { USER_AGENT } from '../../../engine/src/version.ts';
import { HttpError, type Role } from './context.ts';
import { serializeCookie } from './sessions.ts';

export type OidcPreset = 'entra' | 'google' | 'okta' | 'generic';
export const OIDC_PRESETS: OidcPreset[] = ['entra', 'google', 'okta', 'generic'];

export interface OidcProvider {
  id: string;
  name: string;
  preset: OidcPreset;
  issuer: string;
  clientId: string;
  clientSecret?: string;
  scopes: string[];
  roleClaim?: string;
  roleMap?: { admin?: string[]; analyst?: string[] };
  defaultRole: 'viewer' | 'analyst';
  allowedDomains?: string[];
  /** Entra: the tenant id or domain the issuer template is filled with. */
  tenant?: string;
  /** Okta: the org domain the issuer template is filled with. */
  domain?: string;
}

export interface OidcSettings {
  providers: OidcProvider[];
}

/** The settings as the API returns them: no secret, plus whether one is stored and the redirect URI to register. */
export type PublicOidcProvider = Omit<OidcProvider, 'clientSecret'> & { hasSecret: boolean; redirectUri: string };

export const OIDC_COOKIE = 'nextfix_oidc';
/** The sign-in must come back from the provider within this long. */
const FLOW_TTL_MS = 10 * 60_000;
const DISCOVERY_TTL_MS = 60 * 60_000;
const JWKS_REFETCH_MIN_MS = 60_000;
const FETCH_TIMEOUT_MS = 10_000;
/** Accepted drift between the provider's clock and ours. */
const CLOCK_SKEW_S = 60;
const DEFAULT_SCOPES = ['openid', 'profile', 'email'];
const PROVIDER_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;

const ISSUER_TEMPLATES: Record<OidcPreset, ((p: { tenant?: string; domain?: string }) => string | undefined) | undefined> = {
  entra: (p) => (p.tenant ? `https://login.microsoftonline.com/${p.tenant}/v2.0` : undefined),
  google: () => 'https://accounts.google.com',
  okta: (p) => (p.domain ? `https://${p.domain}/oauth2/default` : undefined),
  generic: undefined,
};

function str(x: unknown, field: string, max: number, required: boolean): string | undefined {
  if (x === undefined || x === null || x === '') {
    if (required) throw new HttpError(400, `${field} is required`);
    return undefined;
  }
  if (typeof x !== 'string') throw new HttpError(400, `${field} must be a string`);
  const v = x.trim();
  if (!v) {
    if (required) throw new HttpError(400, `${field} is required`);
    return undefined;
  }
  if (v.length > max) throw new HttpError(400, `${field} must be at most ${max} characters`);
  return v;
}

function strList(x: unknown, field: string): string[] | undefined {
  if (x === undefined || x === null) return undefined;
  const list = typeof x === 'string' ? x.split(/[,\s]+/) : x;
  if (!Array.isArray(list)) throw new HttpError(400, `${field} must be a list of strings`);
  const out: string[] = [];
  for (const v of list) {
    if (typeof v !== 'string') throw new HttpError(400, `${field} must be a list of strings`);
    const t = v.trim();
    if (t && !out.includes(t)) out.push(t.slice(0, 200));
  }
  return out;
}

function isLoopbackHost(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
}

/** An issuer is an https URL without query or fragment; http is allowed only on loopback for local test providers. */
export function checkIssuer(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new HttpError(400, `issuer must be a URL, not ${raw.slice(0, 100)}`);
  }
  if (u.search || u.hash || u.username || u.password) throw new HttpError(400, 'issuer must not carry a query, fragment or credentials');
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLoopbackHost(u.hostname))) throw new HttpError(400, 'issuer must use https');
  return u.href.replace(/\/+$/, '');
}

/** The issuer a provider resolves to: the explicit one, or the preset's template filled in. */
export function resolveIssuer(p: { preset: OidcPreset; issuer?: string; tenant?: string; domain?: string }): string | undefined {
  if (p.issuer) return p.issuer;
  return ISSUER_TEMPLATES[p.preset]?.(p);
}

/**
 * Validate the body of PUT /api/settings/oidc. A provider whose secret is omitted keeps the
 * stored one (matched by id), so the UI can edit everything else without re-entering it.
 */
export function normalizeOidcSettings(body: unknown, existing: OidcSettings | undefined): OidcSettings {
  if (!body || typeof body !== 'object') throw new HttpError(400, 'Body must be a JSON object');
  const raw = (body as { providers?: unknown }).providers;
  if (!Array.isArray(raw)) throw new HttpError(400, 'providers must be a list');
  if (raw.length > 10) throw new HttpError(400, 'At most 10 providers');
  const providers: OidcProvider[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') throw new HttpError(400, 'Each provider must be an object');
    const r = item as Record<string, unknown>;
    const id = str(r.id, 'id', 32, true)!.toLowerCase();
    if (!PROVIDER_ID.test(id)) throw new HttpError(400, 'A provider id is 1 to 32 lowercase letters, digits or hyphens');
    if (providers.some((p) => p.id === id)) throw new HttpError(400, `Provider id ${id} is used twice`);
    const preset = str(r.preset, 'preset', 16, false) ?? 'generic';
    if (!OIDC_PRESETS.includes(preset as OidcPreset)) throw new HttpError(400, `preset must be one of ${OIDC_PRESETS.join(', ')}`);
    const tenant = str(r.tenant, 'tenant', 200, false);
    const domain = str(r.domain, 'domain', 200, false);
    if (tenant && !/^[A-Za-z0-9.-]+$/.test(tenant)) throw new HttpError(400, 'tenant must be a tenant id or domain name');
    if (domain && !/^[A-Za-z0-9.-]+$/.test(domain)) throw new HttpError(400, 'domain must be a host name');
    const explicit = str(r.issuer, 'issuer', 500, false);
    const issuerRaw = resolveIssuer({ preset: preset as OidcPreset, issuer: explicit, tenant, domain });
    if (!issuerRaw) {
      if (preset === 'entra') throw new HttpError(400, 'Entra needs the tenant (its id or primary domain)');
      if (preset === 'okta') throw new HttpError(400, 'Okta needs the org domain (for example acme.okta.com)');
      throw new HttpError(400, 'issuer is required');
    }
    const issuer = checkIssuer(issuerRaw);
    const clientId = str(r.clientId, 'clientId', 300, true)!;
    const previous = existing?.providers.find((p) => p.id === id);
    const givenSecret = str(r.clientSecret, 'clientSecret', 2000, false);
    const clientSecret = givenSecret ?? previous?.clientSecret;
    const scopes = strList(r.scopes, 'scopes') ?? DEFAULT_SCOPES.slice();
    if (!scopes.includes('openid')) scopes.unshift('openid');
    const roleClaim = str(r.roleClaim, 'roleClaim', 100, false);
    let roleMap: OidcProvider['roleMap'];
    if (r.roleMap !== undefined && r.roleMap !== null) {
      if (typeof r.roleMap !== 'object') throw new HttpError(400, 'roleMap must be an object with admin and analyst lists');
      const m = r.roleMap as Record<string, unknown>;
      roleMap = {};
      const admin = strList(m.admin, 'roleMap.admin');
      const analyst = strList(m.analyst, 'roleMap.analyst');
      if (admin?.length) roleMap.admin = admin;
      if (analyst?.length) roleMap.analyst = analyst;
    }
    const defaultRole = str(r.defaultRole, 'defaultRole', 16, false) ?? 'viewer';
    if (defaultRole !== 'viewer' && defaultRole !== 'analyst') throw new HttpError(400, 'defaultRole must be viewer or analyst');
    const allowedDomains = strList(r.allowedDomains, 'allowedDomains')?.map((d) => d.toLowerCase().replace(/^@/, ''));
    const provider: OidcProvider = { id, name: str(r.name, 'name', 60, false) ?? id, preset: preset as OidcPreset, issuer, clientId, scopes, defaultRole };
    if (clientSecret) provider.clientSecret = clientSecret;
    if (roleClaim) provider.roleClaim = roleClaim;
    if (roleMap && (roleMap.admin || roleMap.analyst)) provider.roleMap = roleMap;
    if (allowedDomains?.length) provider.allowedDomains = allowedDomains;
    if (tenant) provider.tenant = tenant;
    if (domain) provider.domain = domain;
    providers.push(provider);
  }
  return { providers };
}

export function redirectUriFor(origin: string, providerId: string): string {
  return `${origin}/api/auth/oidc/${providerId}/callback`;
}

export function publicOidcSettings(settings: OidcSettings | undefined, origin: string): { providers: PublicOidcProvider[] } {
  return {
    providers: (settings?.providers ?? []).map((p) => {
      const { clientSecret, ...rest } = p;
      return { ...rest, hasSecret: !!clientSecret, redirectUri: redirectUriFor(origin, p.id) };
    }),
  };
}

// ---- discovery and keys ----

interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
}

interface Jwk {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
}

interface IssuerState {
  discovery?: { doc: Discovery; at: number };
  jwks?: { keys: Jwk[]; at: number };
}

const issuers = new Map<string, IssuerState>();

/** Forget cached discovery documents and keys (tests). */
export function resetOidcCache(): void {
  issuers.clear();
}

async function getJson(url: string, init: RequestInit = {}): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, headers: { accept: 'application/json', 'user-agent': USER_AGENT, ...(init.headers as Record<string, string> | undefined) }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new HttpError(502, `Could not reach the identity provider at ${new URL(url).host}: ${err instanceof Error ? err.message : String(err)}`);
  }
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  if (!res.ok) {
    const desc = body && typeof body === 'object' ? String((body as { error_description?: unknown; error?: unknown }).error_description ?? (body as { error?: unknown }).error ?? '') : '';
    throw new HttpError(502, `The identity provider answered ${res.status}${desc ? `: ${desc.slice(0, 200)}` : ''}`);
  }
  if (body === undefined) throw new HttpError(502, 'The identity provider did not answer with JSON');
  return body;
}

export async function discover(issuer: string, now = Date.now()): Promise<Discovery> {
  const state = issuers.get(issuer) ?? {};
  if (state.discovery && now - state.discovery.at < DISCOVERY_TTL_MS) return state.discovery.doc;
  const doc = (await getJson(`${issuer}/.well-known/openid-configuration`)) as Partial<Discovery>;
  for (const f of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
    if (typeof doc[f] !== 'string' || !doc[f]) throw new HttpError(502, `The provider's discovery document has no ${f}`);
  }
  state.discovery = { doc: doc as Discovery, at: now };
  issuers.set(issuer, state);
  return doc as Discovery;
}

async function keysFor(issuer: string, jwksUri: string, kid: string | undefined, now = Date.now()): Promise<Jwk | undefined> {
  const state = issuers.get(issuer) ?? {};
  const pick = (keys: Jwk[]) => keys.find((k) => (kid ? k.kid === kid : true) && (!k.use || k.use === 'sig'));
  if (state.jwks) {
    const hit = pick(state.jwks.keys);
    if (hit) return hit;
    if (now - state.jwks.at < JWKS_REFETCH_MIN_MS) return undefined;
  }
  const doc = (await getJson(jwksUri)) as { keys?: unknown };
  if (!Array.isArray(doc.keys)) throw new HttpError(502, 'The provider JWKS has no keys');
  state.jwks = { keys: doc.keys.filter((k): k is Jwk => !!k && typeof k === 'object' && typeof (k as Jwk).kty === 'string'), at: now };
  issuers.set(issuer, state);
  return pick(state.jwks.keys);
}

// ---- JWT verification (RS256 and ES256) ----

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function decodeSegment(seg: string): unknown {
  try {
    return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  name?: string;
  [claim: string]: unknown;
}

/** Verify a JWS compact token against a JWK with the algorithm the header names; RS256 and ES256 only. */
export async function verifyJwtSignature(token: string, resolveKey: (kid: string | undefined, kty: string) => Promise<Jwk | undefined>): Promise<{ header: { alg: string; kid?: string }; claims: IdTokenClaims }> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new HttpError(400, 'The id_token is not a compact JWS');
  const header = decodeSegment(parts[0]!) as { alg?: unknown; kid?: unknown } | undefined;
  const claims = decodeSegment(parts[1]!) as IdTokenClaims | undefined;
  if (!header || typeof header !== 'object' || !claims || typeof claims !== 'object') throw new HttpError(400, 'The id_token could not be decoded');
  const alg = header.alg;
  if (alg !== 'RS256' && alg !== 'ES256') throw new HttpError(400, `The id_token uses ${typeof alg === 'string' ? alg.slice(0, 20) : 'no'} signatures; NextFix accepts RS256 and ES256`);
  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  const jwk = await resolveKey(kid, alg === 'RS256' ? 'RSA' : 'EC');
  if (!jwk) throw new HttpError(400, 'The id_token was signed with a key the provider does not publish');
  let key: webcrypto.CryptoKey;
  try {
    if (alg === 'RS256') {
      if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) throw new Error('not an RSA key');
      key = await webcrypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    } else {
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) throw new Error('not a P-256 key');
      key = await webcrypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    }
  } catch (err) {
    throw new HttpError(502, `The provider's signing key could not be used: ${err instanceof Error ? err.message : String(err)}`);
  }
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2]!, 'base64url');
  const ok = await webcrypto.subtle.verify(alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' }, key, signature, data);
  if (!ok) throw new HttpError(400, 'The id_token signature does not verify');
  return { header: { alg, kid }, claims };
}

/** The checks every id_token must pass once its signature is good. */
export function checkClaims(claims: IdTokenClaims, expect: { issuer: string; clientId: string; nonce: string }, now = Date.now()): void {
  const nowS = Math.floor(now / 1000);
  if (claims.iss !== expect.issuer) throw new HttpError(400, 'The id_token was issued by someone else');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expect.clientId)) throw new HttpError(400, 'The id_token is not for this application');
  if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_S <= nowS) throw new HttpError(400, 'The id_token has expired; try signing in again');
  if (typeof claims.iat === 'number' && claims.iat - CLOCK_SKEW_S > nowS) throw new HttpError(400, 'The id_token is dated in the future; check the clocks');
  if (typeof claims.nonce !== 'string' || claims.nonce.length !== expect.nonce.length || !timingSafeEqual(Buffer.from(claims.nonce), Buffer.from(expect.nonce))) throw new HttpError(400, 'The sign-in response does not match the request that started it (nonce)');
  if (typeof claims.sub !== 'string' || !claims.sub) throw new HttpError(400, 'The id_token has no subject');
}

// ---- the signed flow cookie ----

interface FlowState {
  p: string;
  s: string;
  n: string;
  v: string;
  exp: number;
}

function sign(payload: string, secret: Buffer): string {
  return b64url(createHmac('sha256', secret).update(payload).digest());
}

export function sealFlow(state: FlowState, secret: Buffer): string {
  const payload = b64url(Buffer.from(JSON.stringify(state)));
  return `${payload}.${sign(payload, secret)}`;
}

export function openFlow(cookie: string | undefined, secret: Buffer, now = Date.now()): FlowState | undefined {
  if (!cookie) return undefined;
  const dot = cookie.indexOf('.');
  if (dot === -1) return undefined;
  const payload = cookie.slice(0, dot);
  const mac = cookie.slice(dot + 1);
  const expected = sign(payload, secret);
  if (mac.length !== expected.length || !timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return undefined;
  const state = decodeSegment(payload) as FlowState | undefined;
  if (!state || typeof state !== 'object' || typeof state.exp !== 'number' || state.exp <= now) return undefined;
  if ([state.p, state.s, state.n, state.v].some((x) => typeof x !== 'string' || !x)) return undefined;
  return state;
}

// ---- the flow ----

/** Build the provider redirect and the cookie that ties the callback to this request. */
export async function startAuth(provider: OidcProvider, redirectUri: string, secret: Buffer, cookieSecure: boolean, now = Date.now()): Promise<{ location: string; cookie: string }> {
  const doc = await discover(provider.issuer, now);
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const url = new URL(doc.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', provider.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', provider.scopes.join(' '));
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  const cookie = serializeCookie(OIDC_COOKIE, sealFlow({ p: provider.id, s: state, n: nonce, v: verifier, exp: now + FLOW_TTL_MS }, secret), { maxAge: Math.floor(FLOW_TTL_MS / 1000), secure: cookieSecure });
  return { location: url.href, cookie };
}

export interface OidcIdentity {
  sub: string;
  email: string;
  name: string;
  role: Role;
}

/** The role a provider's claims map to: roleMap lists checked against the role claim, else the provider's default. */
export function mapRole(claims: Record<string, unknown>, provider: OidcProvider): Role {
  const names = provider.roleClaim ? [provider.roleClaim] : ['groups', 'roles'];
  const values = new Set<string>();
  for (const name of names) {
    const v = claims[name];
    if (typeof v === 'string') values.add(v);
    else if (Array.isArray(v)) for (const x of v) if (typeof x === 'string') values.add(x);
  }
  if (provider.roleMap?.admin?.some((g) => values.has(g))) return 'admin';
  if (provider.roleMap?.analyst?.some((g) => values.has(g))) return 'analyst';
  return provider.defaultRole;
}

/** Exchange the callback for a verified identity: state, PKCE, signature, claims, nonce, e-mail and domain are all checked. */
export async function finishAuth(provider: OidcProvider, redirectUri: string, query: URLSearchParams, flowCookie: string | undefined, secret: Buffer, now = Date.now()): Promise<OidcIdentity> {
  const providerError = query.get('error');
  if (providerError) throw new HttpError(400, `The identity provider refused the sign-in: ${(query.get('error_description') ?? providerError).slice(0, 200)}`);
  const flow = openFlow(flowCookie, secret, now);
  if (!flow || flow.p !== provider.id) throw new HttpError(400, 'This sign-in did not start here or took too long; try again');
  const state = query.get('state') ?? '';
  if (state.length !== flow.s.length || !timingSafeEqual(Buffer.from(state), Buffer.from(flow.s))) throw new HttpError(400, 'The sign-in response does not match the request that started it (state)');
  const code = query.get('code');
  if (!code) throw new HttpError(400, 'The identity provider sent no authorization code');

  const doc = await discover(provider.issuer, now);
  const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: flow.v });
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
  if (provider.clientSecret) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(provider.clientId)}:${encodeURIComponent(provider.clientSecret)}`).toString('base64')}`;
  else form.set('client_id', provider.clientId);
  const tokens = (await getJson(doc.token_endpoint, { method: 'POST', headers, body: form.toString() })) as { id_token?: unknown; access_token?: unknown };
  if (typeof tokens.id_token !== 'string') throw new HttpError(502, 'The identity provider returned no id_token; make sure the openid scope is granted');

  const { claims } = await verifyJwtSignature(tokens.id_token, (kid) => keysFor(provider.issuer, doc.jwks_uri, kid, now));
  checkClaims(claims, { issuer: doc.issuer, clientId: provider.clientId, nonce: flow.n }, now);

  let email = typeof claims.email === 'string' ? claims.email : undefined;
  if (!email && typeof claims.preferred_username === 'string' && claims.preferred_username.includes('@')) email = claims.preferred_username;
  let name = typeof claims.name === 'string' ? claims.name : undefined;
  let extra: Record<string, unknown> = {};
  if ((!email || !name) && doc.userinfo_endpoint && typeof tokens.access_token === 'string') {
    try {
      extra = (await getJson(doc.userinfo_endpoint, { headers: { authorization: `Bearer ${tokens.access_token}` } })) as Record<string, unknown>;
      if (typeof extra.sub === 'string' && extra.sub !== claims.sub) extra = {};
    } catch {
      extra = {};
    }
    if (!email && typeof extra.email === 'string') email = extra.email;
    if (!name && typeof extra.name === 'string') name = extra.name;
  }
  if (!email) throw new HttpError(400, 'The identity provider did not return an e-mail address; grant the email scope');
  email = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 64) throw new HttpError(400, 'The e-mail address the provider returned is not usable as a username');
  if (provider.allowedDomains?.length) {
    const domain = email.slice(email.lastIndexOf('@') + 1);
    if (!provider.allowedDomains.includes(domain)) throw new HttpError(403, `Accounts from ${domain} are not allowed to sign in here`);
  }
  return { sub: claims.sub, email, name: (name ?? email).slice(0, 120), role: mapRole({ ...extra, ...claims }, provider) };
}
