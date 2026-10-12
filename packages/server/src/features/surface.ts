import type { DatabaseSync } from 'node:sqlite';
import type { Route } from './core.ts';

/*
 * Surface: what the deployment and the logs say about an application, beside what the code says.
 * Holds the access-log paths per target (read at scan time), the portfolio map built from the
 * service links every report carries, and the helpers the portfolio and digest use for it.
 */

export const migrations: string[] = [
  // 8: access logs per target, a JSON list of file or folder paths the scan reads.
  `
    ALTER TABLE targets ADD COLUMN access_logs TEXT;
  `,
];

export const MAX_LOG_SOURCES = 20;
export const MAX_LOG_PATH = 500;

/** The access-log paths a target's scans read, or an empty list. */
export function accessLogsOf(db: DatabaseSync, targetId: number): string[] {
  const r = db.prepare('SELECT access_logs FROM targets WHERE id = ?').get(targetId) as { access_logs: string | null } | undefined;
  return parseAccessLogs(r?.access_logs ?? null);
}

export function parseAccessLogs(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw) as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim().length > 0) : [];
  } catch {
    return [];
  }
}

export const routes: Route[] = [];
