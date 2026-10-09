import type { Decision, Finding, ScanReport, ScanSummary } from '../../engine/src/types.ts';

export type { Decision, Finding, ScanReport, ScanSummary };
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

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) } });
  if (res.status === 204) return undefined as T;
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  return body as T;
}

export const api = {
  health: () => call<{ ok: boolean; version: string; scanning: boolean }>('/api/health'),
  targets: () => call<Target[]>('/api/targets'),
  addTarget: (dir: string) => call<{ target: Target; scan: ScanMeta; report: ScanReport }>('/api/targets', { method: 'POST', body: JSON.stringify({ dir }) }),
  rescan: (targetId: number) => call<{ scan: ScanMeta; report: ScanReport }>(`/api/targets/${targetId}/scan`, { method: 'POST' }),
  removeTarget: (targetId: number) => call<void>(`/api/targets/${targetId}`, { method: 'DELETE' }),
  scans: (targetId: number) => call<ScanMeta[]>(`/api/targets/${targetId}/scans`),
  report: (scanId: number) => call<ScanReport>(`/api/scans/${scanId}`),
  diff: (scanId: number) => call<ScanDiff>(`/api/scans/${scanId}/diff`),
  vexUrl: (scanId: number) => `/api/scans/${scanId}/vex`,
};
