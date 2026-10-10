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

export interface Target {
  id: number;
  dir: string;
  name: string | null;
  createdAt: string;
  lastScan?: ScanMeta;
}

/**
 * GET /api/scans/:id returns the report with each finding's advisory trimmed: no `details`,
 * `references` capped at 6 (`referenceCount` has the real number). `firstSeenAt` is joined in
 * from the finding history (absent for findings the history has not recorded). The full finding
 * is one request away at GET /api/scans/:id/findings/:findingId (`api.finding`).
 */
export type ListAdvisory = Omit<Advisory, 'details'> & { referenceCount: number };
export type ListFinding = Omit<Finding, 'advisory'> & { advisory: ListAdvisory; firstSeenAt?: string };
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

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) } });
  if (res.status === 204) return undefined as T;
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new Error(body?.error ?? `${res.status} ${res.statusText}`);
  return body as T;
}

export const api = {
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
