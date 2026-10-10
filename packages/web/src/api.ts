import type { Advisory, Component, Decision, Finding, ScanReport, ScanSummary } from '../../engine/src/types.ts';

export type { Component, Decision, Finding, ScanReport, ScanSummary };
export type { EntryPoint, ReachTier, ReachPath } from '../../engine/src/types.ts';

export interface ScanMeta {
  id: number;
  targetId: number;
  createdAt: string;
  toolVersion: string;
  summary: ScanSummary;
}

export interface Schedule { everyHours: number }

export interface Target {
  id: number;
  dir: string;
  name: string | null;
  createdAt: string;
  lastScan?: ScanMeta;
  owner?: string | null;
  schedule?: Schedule | null;
}

// ---------------------------------------------------------------------------------------------
// Session, users, tokens, single sign-on, audit

export type Role = 'admin' | 'analyst' | 'viewer';
export type AuthMode = 'none' | 'local' | 'oidc';

export interface User {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  disabled?: boolean;
  createdAt?: string;
  lastLoginAt?: string;
}

export interface Session {
  setupRequired: boolean;
  authMode: AuthMode;
  user?: User;
  oidc?: { providers: { id: string; name: string }[] };
}

export type TokenScope = 'read' | 'scan' | 'tickets';
export interface ApiToken {
  id: string;
  name: string;
  scopes: TokenScope[];
  createdAt: string;
  lastUsedAt?: string | null;
  createdBy: string;
}

export type OidcPreset = 'entra' | 'google' | 'okta' | 'generic';
export interface OidcProvider {
  id: string;
  name: string;
  preset: OidcPreset;
  issuer: string;
  clientId: string;
  hasSecret: boolean;
  /** Only sent when changing it; never returned. */
  clientSecret?: string;
  scopes?: string;
  roleClaim?: string;
  roleMap?: Record<string, Role>;
  defaultRole: Role;
  allowedDomains?: string[];
  redirectUri: string;
}
export interface OidcSettings { providers: OidcProvider[] }

export interface AuditRow {
  id: number;
  at: string;
  username: string;
  action: string;
  target?: string;
  detail?: string;
  ip?: string;
}
export interface AuditPage { rows: AuditRow[]; next?: number | null }

// ---------------------------------------------------------------------------------------------
// Exceptions (a person sets a finding aside; analysts propose, admins approve)

export type ExceptionKind = 'accepted-risk' | 'false-positive' | 'mitigated';
export type ExceptionStatus = 'pending' | 'approved' | 'rejected' | 'revoked' | 'expired';
export interface Exception {
  id: string;
  findingId: string;
  kind: ExceptionKind;
  reason: string;
  status: ExceptionStatus;
  proposedBy: string;
  approvedBy?: string;
  expiresAt?: string | null;
  createdAt: string;
  updatedAt: string;
}
/** What a finding in GET /api/scans/:id carries once an exception exists for it. */
export interface FindingException { id: string; kind: ExceptionKind; status: ExceptionStatus; expiresAt?: string | null }

// ---------------------------------------------------------------------------------------------
// Portfolio

export type Posture = 'Exposed' | 'Attention' | 'Contained' | 'Clean' | 'Never scanned';
export interface PortfolioTarget {
  id: number;
  name: string;
  dir: string;
  owner?: string | null;
  lastScanAt?: string;
  posture: Posture;
  byDecision: Record<Decision, number>;
  exposedSurface: { open: number; total: number };
  oldestPastSlaDays?: number;
  /** Actionable findings per scan, oldest first, up to 8. */
  trend: number[];
  pendingExceptions: number;
}
export interface Portfolio { targets: PortfolioTarget[] }

// ---------------------------------------------------------------------------------------------
// Weekly digest

export type DigestChannel = 'email' | 'slack' | 'teams';
export interface DigestSettings {
  channel: DigestChannel | null;
  email?: { to: string[]; from: string; smtpHost: string; smtpPort: number; smtpUser: string; hasPassword: boolean; secure: boolean };
  slack?: { hasWebhook: boolean };
  teams?: { hasWebhook: boolean };
  weekday: number;
  hour: number;
}
/** PUT body: the settings plus the secrets only when they change. */
export type DigestPatch = DigestSettings & { smtpPassword?: string; slackWebhook?: string; teamsWebhook?: string };

/**
 * GET /api/scans/:id returns the report with each finding's advisory trimmed: no `details`,
 * `references` capped at 6 (`referenceCount` has the real number). `firstSeenAt` is joined in
 * from the finding history (absent for findings the history has not recorded). The full finding
 * is one request away at GET /api/scans/:id/findings/:findingId (`api.finding`).
 */
export type ListAdvisory = Omit<Advisory, 'details'> & { referenceCount: number };
export type ListFinding = Omit<Finding, 'advisory'> & { advisory: ListAdvisory; firstSeenAt?: string; exception?: FindingException };
export type ListReport = Omit<ScanReport, 'findings'> & { findings: ListFinding[] };
/** The complete finding, with the full advisory text and every reference. */
export type FullFinding = Finding & { firstSeenAt?: string };

export interface ChangedFinding {
  finding: Finding;
  from: Decision;
  to: Decision;
  /** Short reasons: "decision Attend → Act", "entered KEV", "fix published 4.18.0", "new entry point reaches it". */
  reasons: string[];
}

export interface ScanDiff {
  previous?: ScanMeta;
  added: Finding[];
  resolved: Finding[];
  changed: ChangedFinding[];
  summary: { added: number; resolved: number; escalated: number; deescalated: number };
}

/** POST /api/targets/:id/redecide: the latest report re-decided with current EPSS/KEV; nothing is stored. */
export interface Redecide {
  scanId: number;
  checkedAt: string;
  changed: ChangedFinding[];
  summary: { changed: number; escalated: number; deescalated: number };
}

export type AgeBucket = '0-7' | '8-30' | '31-90' | '90+';

export interface HistoryRow {
  targetId: number;
  findingId: string;
  firstSeenAt: string;
  lastSeenAt: string;
  firstScanId: number;
  lastScanId: number;
  resolvedAt: string | null;
  resolvedScanId: number | null;
  decisionLatest: Decision;
}

/** GET /api/targets/:id/history. Ages are days since first seen; SLA days come from settings. */
export interface History {
  rows: HistoryRow[];
  open: Record<Decision, Record<AgeBucket, number>>;
  pastSla: Record<Decision, number>;
  sla: { slaActDays: number; slaAttendDays: number };
  medianDaysToResolve: number | null;
  resolvedLast30: number;
  introducedLast30: number;
  /** Finding id → first seen, for every open finding of the target. */
  firstSeen: Record<string, string>;
  computedAt: string;
}

/** GET/PUT /api/settings. PUT accepts any subset; whole numbers from 1 to 3650. */
export interface Settings {
  slaActDays: number;
  slaAttendDays: number;
  /** Scans kept per application; older ones are pruned when a new scan is stored. */
  retentionScans: number;
}

export interface Integrations {
  github?: { repo: string; labels: string[]; hasToken: boolean };
  jira?: { baseUrl: string; email: string; projectKey: string; issueType: string; hasToken: boolean };
}

export type TicketKind = 'github' | 'jira';
export interface Ticket { kind: TicketKind; key: string; url: string; createdAt: string }
export type TicketMap = Record<string, Ticket[]>;
export interface TicketResult { findingId: string; key?: string; url?: string; error?: string; skipped?: boolean }

/** `scanning` is null when idle; `targetId` is null when the scan runs on another server sharing the database. */
export interface Scanning { targetId: number | null; stage: string; startedAt: string }

export interface Health {
  ok: boolean;
  version: string;
  scanning: Scanning | null;
  dbPath?: string;
  cachePath?: string;
}

/** GET /api/scan/progress: the scan this server is running, with the engine's latest log lines. */
export interface ScanProgress extends Scanning { targetId: number; lines: string[] }

/** An HTTP failure with its status, so callers can tell a wrong password (401) from a lock-out (429). */
export class ApiError extends Error {
  status: number;
  retryAfter?: number;
  constructor(status: number, message: string, retryAfter?: number) {
    super(message);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

let onUnauthorized: (() => void) | null = null;
/** Called once per 401 outside the sign-in calls, so the shell can show the login page and keep the hash to return to. */
export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn;
}

const AUTH_URLS = ['/api/session', '/api/login', '/api/setup', '/api/logout'];

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) } });
  if (res.status === 204) return undefined as T;
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) {
    if (res.status === 401 && !AUTH_URLS.includes(url)) onUnauthorized?.();
    const retry = res.headers.get('retry-after');
    throw new ApiError(res.status, body?.error ?? `${res.status} ${res.statusText}`, retry ? Number(retry) : undefined);
  }
  return body as T;
}

export const api = {
  // session
  session: () => call<Session>('/api/session'),
  setup: (body: { username: string; password: string; displayName: string }) => call<Session>('/api/setup', { method: 'POST', body: JSON.stringify(body) }),
  login: (body: { username: string; password: string }) => call<Session>('/api/login', { method: 'POST', body: JSON.stringify(body) }),
  logout: () => call<void>('/api/logout', { method: 'POST' }),
  oidcStartUrl: (provider: string) => `/api/auth/oidc/${encodeURIComponent(provider)}/start`,
  // users and tokens (admin)
  users: () => call<User[]>('/api/users'),
  createUser: (body: { username: string; password: string; displayName: string; role: Role }) => call<User>('/api/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUser: (id: string, patch: { role?: Role; disabled?: boolean; displayName?: string }) => call<User>(`/api/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  setPassword: (id: string, body: { password: string; currentPassword?: string }) => call<void>(`/api/users/${encodeURIComponent(id)}/password`, { method: 'POST', body: JSON.stringify(body) }),
  deleteUser: (id: string) => call<void>(`/api/users/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  tokens: () => call<ApiToken[]>('/api/tokens'),
  createToken: (body: { name: string; scopes: TokenScope[] }) => call<{ id: string; token: string }>('/api/tokens', { method: 'POST', body: JSON.stringify(body) }),
  revokeToken: (id: string) => call<void>(`/api/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  oidcSettings: () => call<OidcSettings>('/api/settings/oidc'),
  saveOidcSettings: (body: OidcSettings) => call<OidcSettings>('/api/settings/oidc', { method: 'PUT', body: JSON.stringify(body) }),
  audit: (before?: number | null, limit = 100) => call<AuditPage>(`/api/audit?limit=${limit}${before ? `&before=${before}` : ''}`),
  // exceptions
  exceptions: (targetId: number, signal?: AbortSignal) => call<Exception[]>(`/api/targets/${targetId}/exceptions`, { signal }),
  proposeException: (targetId: number, body: { findingId: string; kind: ExceptionKind; reason: string; expiresAt?: string }) => call<Exception>(`/api/targets/${targetId}/exceptions`, { method: 'POST', body: JSON.stringify(body) }),
  updateException: (id: string, body: { status: 'approved' | 'rejected' | 'revoked'; reason?: string }) => call<Exception>(`/api/exceptions/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) }),
  // portfolio and targets
  portfolio: (signal?: AbortSignal) => call<Portfolio>('/api/portfolio', { signal }),
  updateTarget: (targetId: number, patch: { owner?: string | null; schedule?: Schedule | null }) => call<Target>(`/api/targets/${targetId}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  // digest (admin)
  digest: () => call<DigestSettings>('/api/settings/digest'),
  saveDigest: (body: DigestPatch) => call<DigestSettings>('/api/settings/digest', { method: 'PUT', body: JSON.stringify(body) }),
  testDigest: () => call<{ ok: boolean; message: string }>('/api/digest/test', { method: 'POST' }),
  previewDigest: () => call<{ subject: string; text: string }>('/api/digest/preview', { method: 'POST' }),
  health: (signal?: AbortSignal) => call<Health>('/api/health', { signal }),
  progress: () => call<ScanProgress | null>('/api/scan/progress'),
  cancelScan: () => call<{ cancelled: boolean }>('/api/scan', { method: 'DELETE' }),
  targets: () => call<Target[]>('/api/targets'),
  addTarget: (dir: string) => call<{ target: Target; scan: ScanMeta; report: ScanReport }>('/api/targets', { method: 'POST', body: JSON.stringify({ dir }) }),
  rescan: (targetId: number) => call<{ scan: ScanMeta; report: ScanReport }>(`/api/targets/${targetId}/scan`, { method: 'POST' }),
  removeTarget: (targetId: number) => call<void>(`/api/targets/${targetId}`, { method: 'DELETE' }),
  scans: (targetId: number, signal?: AbortSignal) => call<ScanMeta[]>(`/api/targets/${targetId}/scans`, { signal }),
  history: (targetId: number, signal?: AbortSignal) => call<History>(`/api/targets/${targetId}/history`, { signal }),
  redecide: (targetId: number) => call<Redecide>(`/api/targets/${targetId}/redecide`, { method: 'POST' }),
  report: (scanId: number, signal?: AbortSignal) => call<ListReport>(`/api/scans/${scanId}`, { signal }),
  finding: (scanId: number, findingId: string, signal?: AbortSignal) => call<FullFinding>(`/api/scans/${scanId}/findings/${encodeURIComponent(findingId)}`, { signal }),
  diff: (scanId: number, signal?: AbortSignal) => call<ScanDiff>(`/api/scans/${scanId}/diff`, { signal }),
  vexUrl: (scanId: number) => `/api/scans/${scanId}/vex`,
  /** The complete report as a download (the list endpoint above is trimmed). */
  reportUrl: (scanId: number) => `/api/scans/${scanId}/json`,
  settings: () => call<Settings>('/api/settings'),
  saveSettings: (patch: Partial<Settings>) => call<Settings>('/api/settings', { method: 'PUT', body: JSON.stringify(patch) }),
  integrations: () => call<Integrations>('/api/integrations'),
  saveIntegration: (kind: TicketKind, config: Record<string, unknown>) => call<{ ok: boolean }>(`/api/integrations/${kind}`, { method: 'PUT', body: JSON.stringify(config) }),
  removeIntegration: (kind: TicketKind) => call<void>(`/api/integrations/${kind}`, { method: 'DELETE' }),
  testIntegration: (kind: TicketKind) => call<{ ok: boolean; message: string }>(`/api/integrations/${kind}/test`, { method: 'POST' }),
  tickets: (targetId: number, signal?: AbortSignal) => call<TicketMap>(`/api/targets/${targetId}/tickets`, { signal }),
  createTickets: (targetId: number, scanId: number, kind: TicketKind, findingIds: string[]) => call<{ results: TicketResult[] }>(`/api/targets/${targetId}/tickets`, { method: 'POST', body: JSON.stringify({ scanId, kind, findingIds }) }),
};
