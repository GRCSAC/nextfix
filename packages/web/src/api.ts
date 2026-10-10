import type { Component, Decision, Finding, ScanReport, ScanSummary } from '../../engine/src/types.ts';

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

export interface ScanDiff {
  previous?: ScanMeta;
  added: Finding[];
  resolved: Finding[];
  changed: { finding: Finding; from: Decision; to: Decision }[];
}

export interface Integrations {
  github?: { repo: string; labels: string[]; hasToken: boolean };
  jira?: { baseUrl: string; email: string; projectKey: string; issueType: string; hasToken: boolean };
}

export type TicketKind = 'github' | 'jira';
export interface Ticket { kind: TicketKind; key: string; url: string; createdAt: string }
export type TicketMap = Record<string, Ticket[]>;
export interface TicketResult { findingId: string; key?: string; url?: string; error?: string; skipped?: boolean }

export interface Health {
  ok: boolean;
  version: string;
  scanning: boolean;
  dbPath?: string;
  cachePath?: string;
}

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) } });
  if (res.status === 204) return undefined as T;
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  return body as T;
}

export const api = {
  health: () => call<Health>('/api/health'),
  targets: () => call<Target[]>('/api/targets'),
  addTarget: (dir: string) => call<{ target: Target; scan: ScanMeta; report: ScanReport }>('/api/targets', { method: 'POST', body: JSON.stringify({ dir }) }),
  rescan: (targetId: number) => call<{ scan: ScanMeta; report: ScanReport }>(`/api/targets/${targetId}/scan`, { method: 'POST' }),
  removeTarget: (targetId: number) => call<void>(`/api/targets/${targetId}`, { method: 'DELETE' }),
  scans: (targetId: number) => call<ScanMeta[]>(`/api/targets/${targetId}/scans`),
  report: (scanId: number) => call<ScanReport>(`/api/scans/${scanId}`),
  diff: (scanId: number) => call<ScanDiff>(`/api/scans/${scanId}/diff`),
  vexUrl: (scanId: number) => `/api/scans/${scanId}/vex`,
  reportUrl: (scanId: number) => `/api/scans/${scanId}`,
  integrations: () => call<Integrations>('/api/integrations'),
  saveIntegration: (kind: TicketKind, config: Record<string, unknown>) => call<{ ok: boolean }>(`/api/integrations/${kind}`, { method: 'PUT', body: JSON.stringify(config) }),
  removeIntegration: (kind: TicketKind) => call<void>(`/api/integrations/${kind}`, { method: 'DELETE' }),
  testIntegration: (kind: TicketKind) => call<{ ok: boolean; message: string }>(`/api/integrations/${kind}/test`, { method: 'POST' }),
  tickets: (targetId: number) => call<TicketMap>(`/api/targets/${targetId}/tickets`),
  createTickets: (targetId: number, scanId: number, kind: TicketKind, findingIds: string[]) => call<{ results: TicketResult[] }>(`/api/targets/${targetId}/tickets`, { method: 'POST', body: JSON.stringify({ scanId, kind, findingIds }) }),
};
